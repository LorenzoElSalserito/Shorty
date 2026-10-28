<?php

declare(strict_types=1);

namespace Shorty\Storage;

/**
 * Striped advisory locks (flock) kept in files that are never renamed, so data files can be
 * replaced atomically while the lock stays valid.
 *
 * Deadlock freedom: locks live in tiers (records < metrics < retention buckets). A process
 * only blocks on a stripe that is above everything it already holds (higher tier, or same
 * tier and higher stripe). Any other acquisition is attempted without blocking and fails
 * closed with StorageError after a short retry. Re-entrant within a process.
 */
final class LockManager
{
    public const RECORDS = 0;
    public const METRICS = 1;
    public const RETENTION = 2;

    private const STRIPES = 256;

    /** @var array<string, resource> */
    private array $held = [];

    public function __construct(private readonly string $dir)
    {
    }

    /**
     * @template T
     * @param list<string> $keys
     * @param callable(): T $fn
     * @return T
     */
    public function with(array $keys, callable $fn, int $tier = self::RECORDS): mixed
    {
        $stripes = [];
        foreach ($keys as $key) {
            $stripes[] = hexdec(substr(hash('sha256', $key), 0, 4)) % self::STRIPES;
        }
        $stripes = array_values(array_unique($stripes));
        sort($stripes);

        $acquired = [];
        try {
            foreach ($stripes as $s) {
                $id = $tier . ':' . $s;
                if (isset($this->held[$id])) {
                    continue;
                }
                $this->held[$id] = $this->acquire($tier, $s, $this->ordered($tier, $s));
                $acquired[] = $id;
            }
            return $fn();
        } finally {
            foreach (array_reverse($acquired) as $id) {
                flock($this->held[$id], LOCK_UN);
                fclose($this->held[$id]);
                unset($this->held[$id]);
            }
        }
    }

    /** Non-blocking single lock, used by optional work such as GC. */
    public function tryWith(string $key, callable $fn): bool
    {
        GuardedFile::ensureDir($this->dir);
        $fh = @fopen($this->dir . '/try-' . substr(hash('sha256', $key), 0, 16) . '.lock', 'c');
        if ($fh === false) {
            return false;
        }
        try {
            if (!flock($fh, LOCK_EX | LOCK_NB)) {
                return false;
            }
            $fn();
            flock($fh, LOCK_UN);
            return true;
        } finally {
            fclose($fh);
        }
    }

    private function ordered(int $tier, int $stripe): bool
    {
        foreach (array_keys($this->held) as $id) {
            [$t, $s] = array_map('intval', explode(':', $id));
            if ($t > $tier || ($t === $tier && $s > $stripe)) {
                return false;
            }
        }
        return true;
    }

    /** @return resource */
    private function acquire(int $tier, int $stripe, bool $mayBlock)
    {
        GuardedFile::ensureDir($this->dir);
        $fh = @fopen(sprintf('%s/%d-%03d.lock', $this->dir, $tier, $stripe), 'c');
        if ($fh === false) {
            throw new StorageError('Cannot open lock.');
        }
        if ($mayBlock) {
            if (flock($fh, LOCK_EX)) {
                return $fh;
            }
        } else {
            for ($i = 0; $i < 200; $i++) {
                if (flock($fh, LOCK_EX | LOCK_NB)) {
                    return $fh;
                }
                usleep(10000);
            }
        }
        fclose($fh);
        throw new StorageError('Cannot acquire lock.');
    }
}
