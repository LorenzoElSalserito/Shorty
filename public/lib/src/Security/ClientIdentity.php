<?php

declare(strict_types=1);

namespace Shorty\Security;

/**
 * Pseudonymous client identifiers: scope-separated HMACs of the remote address.
 * The raw address is never returned or stored.
 */
final class ClientIdentity
{
    private string $address;
    private string $prefix;

    public function __construct(private readonly string $key, string $remoteAddr)
    {
        [$this->address, $this->prefix] = self::normalize($remoteAddr);
    }

    /** @return array{0: string, 1: string} normalized address and network prefix (/24 or /64) */
    public static function normalize(string $addr): array
    {
        $bin = @inet_pton($addr);
        if ($bin === false) {
            throw new \InvalidArgumentException('Invalid IP.');
        }
        // IPv4-mapped IPv6 (::ffff:a.b.c.d) counts as the IPv4 address.
        if (strlen($bin) === 16 && str_starts_with($bin, str_repeat("\0", 10) . "\xff\xff")) {
            $bin = substr($bin, 12);
        }
        if (strlen($bin) === 4) {
            return [inet_ntop($bin), inet_ntop(substr($bin, 0, 3) . "\0") . '/24'];
        }
        return [inet_ntop($bin), inet_ntop(substr($bin, 0, 8) . str_repeat("\0", 8)) . '/64'];
    }

    public function actorId(): string
    {
        return $this->mac('actor:v1', $this->address);
    }

    public function subnetId(): string
    {
        return $this->mac('subnet:v1', $this->prefix);
    }

    public function reporterId(): string
    {
        return $this->mac('reporter:v1', $this->address);
    }

    public function reporterSubnetId(): string
    {
        return $this->mac('reporter-subnet:v1', $this->prefix);
    }

    /** Short subnet token used only to count distinct creators in the trust engine. */
    public function trustBucket(): string
    {
        return substr($this->mac('trust:v1', $this->prefix), 0, 16);
    }

    private function mac(string $scope, string $value): string
    {
        return hash_hmac('sha256', $scope . '|' . $value, $this->key);
    }
}
