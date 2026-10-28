<?php

declare(strict_types=1);

namespace Shorty\Security;

use Shorty\Storage\StorageError;

/**
 * Build-time compiled FOSS threat feed (tools/build-threat-feed.mjs).
 *
 * domains/XX.bin: sorted, fixed-width 16-byte records (truncated SHA-256 of the lowercase
 * hostname), sharded by the first hash byte. A lookup opens one shard and binary-searches
 * it with fseek: O(log n) I/O, O(1) memory, nothing loaded in RAM.
 */
final class ThreatFeed
{
    private const RECORD = 16;

    private ?bool $available = null;

    public function __construct(private readonly string $dir)
    {
    }

    /** False when the feed is missing: callers switch to conservative mode. */
    public function available(): bool
    {
        if ($this->available === null) {
            $meta = json_decode((string) @file_get_contents($this->dir . '/METADATA.json'), true);
            $this->available = is_array($meta) && ($meta['format'] ?? null) === 'shorty-feed-v1';
        }
        return $this->available;
    }

    public function metadata(): ?array
    {
        $meta = json_decode((string) @file_get_contents($this->dir . '/METADATA.json'), true);
        return is_array($meta) ? $meta : null;
    }

    /** Checks the host and each parent domain. */
    public function domainListed(string $host): bool
    {
        if (!$this->available()) {
            return false;
        }
        foreach (Denylist::parents($host) as $candidate) {
            if (str_contains($candidate, '.') && $this->contains(substr(hash('sha256', $candidate, true), 0, self::RECORD))) {
                return true;
            }
        }
        return false;
    }

    private function contains(string $needle): bool
    {
        $shard = $this->dir . '/domains/' . bin2hex($needle[0]) . '.bin';
        // The builder writes all 256 shards: a missing one means a broken package.
        $size = @filesize($shard);
        if ($size === false || $size % self::RECORD !== 0) {
            throw new StorageError('Threat feed shard missing or corrupted.');
        }
        if ($size === 0) {
            return false;
        }
        $fh = @fopen($shard, 'rb');
        if ($fh === false) {
            throw new StorageError('Threat feed shard unreadable.');
        }
        try {
            $lo = 0;
            $hi = intdiv($size, self::RECORD) - 1;
            while ($lo <= $hi) {
                $mid = ($lo + $hi) >> 1;
                fseek($fh, $mid * self::RECORD);
                $rec = fread($fh, self::RECORD);
                $cmp = strcmp((string) $rec, $needle);
                if ($cmp === 0) {
                    return true;
                }
                $cmp < 0 ? $lo = $mid + 1 : $hi = $mid - 1;
            }
            return false;
        } finally {
            fclose($fh);
        }
    }
}
