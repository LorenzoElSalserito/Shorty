<?php

declare(strict_types=1);

namespace Shorty\Storage;

use Shorty\App;

/**
 * Link records v2: runtime/links/A/b/AbCdEf1234.php (PHP guard + JSON). No raw IPs.
 */
final class LinkStore
{
    public const CODE_PATTERN = '/^[A-Za-z0-9]{10}$/';
    private const ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

    public function __construct(private readonly App $app)
    {
    }

    /** 10 base62 chars from the CSPRNG; random_int throws if unavailable (fail closed). */
    public static function generateCode(): string
    {
        $code = '';
        for ($i = 0; $i < 10; $i++) {
            $code .= self::ALPHABET[random_int(0, 61)];
        }
        return $code;
    }

    public function path(string $code): string
    {
        if (!preg_match(self::CODE_PATTERN, $code)) {
            throw new StorageError('Invalid code.');
        }
        return $this->app->runtimeDir() . '/links/' . $code[0] . '/' . $code[1] . '/' . $code . '.php';
    }

    /** Returns the record, or null when missing/corrupt (uniform "not found"). */
    public function get(string $code): ?array
    {
        if (!preg_match(self::CODE_PATTERN, $code)) {
            return null;
        }
        try {
            $r = GuardedFile::read($this->path($code));
        } catch (StorageError) {
            return null;
        }
        if (!is_array($r) || ($r['v'] ?? null) !== 2 || ($r['code'] ?? null) !== $code || !isset($r['url'], $r['expires_at'])) {
            return null;
        }
        return $r;
    }

    /** Lazy purge of an expired record. */
    public function deleteExpired(string $code): void
    {
        $path = $this->path($code);
        $this->app->locks()->with([$path], function () use ($path) {
            $r = GuardedFile::read($path);
            if ($r !== null && (int) ($r['expires_at'] ?? 0) <= $this->app->now()) {
                GuardedFile::delete($path);
            }
        });
    }

    /** Picks an unused code; caller then writes it inside the transaction. */
    public function freshCode(): string
    {
        for ($i = 0; $i < 8; $i++) {
            $code = self::generateCode();
            if (!file_exists($this->path($code))) {
                return $code;
            }
        }
        throw new StorageError('Cannot allocate a code.');
    }

    /** Exclusive insert; must hold the lock for path($record['code']). */
    public function insert(array $record): void
    {
        $path = $this->path($record['code']);
        if (file_exists($path)) {
            throw new StorageError('Code collision.');
        }
        GuardedFile::write($path, $record);
        $this->app->retention()->schedule($path, (int) $record['purge_after']);
    }

    public function remove(string $code): void
    {
        GuardedFile::delete($this->path($code));
    }

    public function setStatus(string $code, string $status, string $reason): void
    {
        $path = $this->path($code);
        $this->app->locks()->with([$path], function () use ($path, $status, $reason) {
            $r = GuardedFile::read($path);
            if ($r === null) {
                return;
            }
            $r['status'] = $status;
            $r['status_reason'] = $reason;
            $r['status_at'] = $this->app->now();
            GuardedFile::write($path, $r);
        });
    }

    public function dedupPath(string $actorId, string $urlHash): string
    {
        return GuardedFile::sharded($this->app->runtimeDir() . '/dedup', hash('sha256', $actorId . '|' . $urlHash));
    }
}
