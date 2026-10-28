<?php

declare(strict_types=1);

namespace Shorty\Security;

/**
 * DNS-only host class check: the destination must resolve, and only to public addresses.
 * Shorty never opens a connection to the destination (no SSRF surface).
 */
final class DnsPolicy
{
    /** @var (callable(string): list<string>)|null */
    private $resolver;

    public function __construct(?callable $resolver = null)
    {
        $this->resolver = $resolver;
    }

    /** Dev/test only: resolve from a JSON map {"host": ["ip", ...]}. */
    public static function fromStubFile(string $file): self
    {
        $map = json_decode((string) @file_get_contents($file), true);
        $map = is_array($map) ? $map : [];
        return new self(static fn (string $host): array => array_values((array) ($map[$host] ?? [])));
    }

    /** @return list<string> resolved addresses */
    public function resolve(string $host): array
    {
        if ($this->resolver !== null) {
            return ($this->resolver)($host);
        }
        $ips = [];
        $records = @dns_get_record($host . '.', DNS_A | DNS_AAAA);
        foreach (is_array($records) ? $records : [] as $r) {
            if (isset($r['ip'])) {
                $ips[] = $r['ip'];
            } elseif (isset($r['ipv6'])) {
                $ips[] = $r['ipv6'];
            }
        }
        if (!$ips) {
            $v4 = @gethostbynamel($host . '.');
            $ips = is_array($v4) ? $v4 : [];
        }
        return array_values(array_unique($ips));
    }

    /**
     * @return string|null null when acceptable, otherwise a reason code
     */
    public function check(string $host, array &$resolved = []): ?string
    {
        $resolved = $this->resolve($host);
        if (!$resolved) {
            return 'dns_unresolved';
        }
        foreach ($resolved as $ip) {
            if (!IpClassifier::isPublic($ip)) {
                return 'dns_non_public';
            }
        }
        return null;
    }
}
