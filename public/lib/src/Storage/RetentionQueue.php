<?php

declare(strict_types=1);

namespace Shorty\Storage;

use Shorty\App;

/**
 * Hourly buckets of runtime files to revisit. Every runtime record carries `purge_after`;
 * the collector deletes records past it and reschedules the others. A file is scheduled
 * once, when it is created, so the queue stays small and no tree scan is ever needed.
 */
final class RetentionQueue
{
    public function __construct(private readonly App $app, private readonly string $dir)
    {
    }

    public function schedule(string $path, int $due): void
    {
        $bucket = $this->bucketPath($due);
        $relative = $this->relative($path);
        $this->app->locks()->with([$bucket], function () use ($bucket, $relative) {
            $data = GuardedFile::read($bucket) ?? ['paths' => []];
            $data['paths'][] = $relative;
            GuardedFile::write($bucket, $data);
        }, LockManager::RETENTION);
    }

    /** Processes at most $budget entries from buckets already due. Returns entries handled. */
    public function collect(int $budget): int
    {
        $handled = 0;
        $this->app->locks()->tryWith('gc', function () use ($budget, &$handled) {
            if (!is_dir($this->dir)) {
                return;
            }
            $current = $this->bucketName($this->app->now());
            $buckets = array_filter(scandir($this->dir) ?: [], fn ($f) => preg_match('/^\d{10}\.php$/', $f) && substr($f, 0, 10) < $current);
            sort($buckets);
            foreach ($buckets as $file) {
                $bucket = $this->dir . '/' . $file;
                // Pop entries under the bucket lock, visit them after releasing it:
                // bucket locks are leaves and never wait on record locks.
                $batch = $this->app->locks()->with([$bucket], function () use ($bucket, $budget, $handled) {
                    $data = GuardedFile::read($bucket) ?? ['paths' => []];
                    $batch = array_splice($data['paths'], 0, max(0, $budget - $handled));
                    $data['paths'] ? GuardedFile::write($bucket, $data) : GuardedFile::delete($bucket);
                    return $batch;
                }, LockManager::RETENTION);
                foreach ($batch as $relative) {
                    try {
                        $this->visit((string) $relative);
                    } catch (StorageError) {
                        $this->schedule($this->app->runtimeDir() . '/' . $relative, $this->app->now() + 3600);
                    }
                    $handled++;
                }
                if ($handled >= $budget) {
                    break;
                }
            }
        });
        return $handled;
    }

    private function visit(string $relative): void
    {
        if (!preg_match('#^[a-z]+(/[A-Za-z0-9._-]+)+\.php$#', $relative) || str_contains($relative, '..')) {
            return;
        }
        $path = $this->app->runtimeDir() . '/' . $relative;
        $this->app->locks()->with([$path], function () use ($path) {
            try {
                $data = GuardedFile::read($path);
            } catch (StorageError) {
                GuardedFile::delete($path);
                return;
            }
            if ($data === null) {
                return;
            }
            $after = (int) ($data['purge_after'] ?? 0);
            if ($after <= $this->app->now()) {
                GuardedFile::delete($path);
            } else {
                $this->schedule($path, $after);
            }
        });
    }

    private function relative(string $path): string
    {
        $root = $this->app->runtimeDir() . '/';
        if (!str_starts_with($path, $root)) {
            throw new StorageError('Path outside runtime.');
        }
        return substr($path, strlen($root));
    }

    private function bucketName(int $ts): string
    {
        return gmdate('YmdH', $ts);
    }

    private function bucketPath(int $due): string
    {
        return $this->dir . '/' . $this->bucketName($due) . '.php';
    }
}
