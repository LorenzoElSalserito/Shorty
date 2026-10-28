<?php

declare(strict_types=1);

namespace Shorty\Security;

use Shorty\Storage\StorageError;

/**
 * Local emergency denylist (lib/security/local/*.txt), editable via FTP.
 * One entry per line, "#" comments. An invalid entry makes the file corrupt: fail closed.
 *
 *   blocked-domains.txt     hostname or domain; blocks it and every subdomain
 *   blocked-url-hashes.txt  sha256 of the canonical URL
 *   blocked-codes.txt       short codes
 *   blocked-ips.txt         IP or CIDR the destination must not resolve to
 */
final class Denylist
{
    private array $cache = [];

    public function __construct(private readonly string $dir)
    {
    }

    public function domainBlocked(string $host): bool
    {
        $set = $this->set('blocked-domains.txt', '/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/');
        foreach (self::parents($host) as $candidate) {
            if (isset($set[$candidate])) {
                return true;
            }
        }
        return false;
    }

    public function urlBlocked(string $urlHash): bool
    {
        return isset($this->set('blocked-url-hashes.txt', '/^[a-f0-9]{64}$/')[$urlHash]);
    }

    public function codeBlocked(string $code): bool
    {
        return isset($this->set('blocked-codes.txt', '/^[A-Za-z0-9]{6,10}$/', false)[$code]);
    }

    /** @param list<string> $ips */
    public function ipsBlocked(array $ips): bool
    {
        $cidrs = array_keys($this->set('blocked-ips.txt', '#^[0-9a-f:.]+(/\d{1,3})?$#'));
        foreach ($ips as $ip) {
            $bin = @inet_pton($ip);
            if ($bin === false) {
                continue;
            }
            foreach ($cidrs as $cidr) {
                if (IpClassifier::inCidr($bin, (string) $cidr)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** host, then each parent domain (a.b.example.com, b.example.com, example.com, com). */
    public static function parents(string $host): array
    {
        $labels = explode('.', $host);
        $out = [];
        for ($i = 0; $i < count($labels); $i++) {
            $out[] = implode('.', array_slice($labels, $i));
        }
        return $out;
    }

    private function set(string $file, string $pattern, bool $lowercase = true): array
    {
        if (isset($this->cache[$file])) {
            return $this->cache[$file];
        }
        $path = $this->dir . '/' . $file;
        if (!file_exists($path)) {
            return $this->cache[$file] = [];
        }
        $lines = @file($path, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            throw new StorageError('Denylist unreadable: ' . $file);
        }
        $set = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            if ($lowercase) {
                $line = strtolower($line);
            }
            if (!preg_match($pattern, $line)) {
                throw new StorageError('Denylist corrupted: ' . $file);
            }
            $set[$line] = true;
        }
        return $this->cache[$file] = $set;
    }
}
