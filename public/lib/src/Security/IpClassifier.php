<?php

declare(strict_types=1);

namespace Shorty\Security;

/**
 * Classifies IP addresses: only globally routable unicast space counts as public.
 */
final class IpClassifier
{
    private const V4_BLOCKED = [
        '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
        '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
        '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
    ];

    // IPv6 is allow-listed to 2000::/3 (global unicast), minus these special ranges.
    private const V6_BLOCKED = [
        '2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20', '64:ff9b::/96', '64:ff9b:1::/48',
    ];

    public static function isPublic(string $ip): bool
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return false;
        }
        if (strlen($bin) === 16 && str_starts_with($bin, str_repeat("\0", 10) . "\xff\xff")) {
            $bin = substr($bin, 12);
        }
        if (strlen($bin) === 4) {
            foreach (self::V4_BLOCKED as $cidr) {
                if (self::inCidr($bin, $cidr)) {
                    return false;
                }
            }
            return true;
        }
        if (!self::inCidr($bin, '2000::/3')) {
            return false;
        }
        foreach (self::V6_BLOCKED as $cidr) {
            if (self::inCidr($bin, $cidr)) {
                return false;
            }
        }
        return true;
    }

    public static function inCidr(string $bin, string $cidr): bool
    {
        [$net, $bits] = explode('/', $cidr) + [1 => null];
        $netBin = @inet_pton($net);
        if ($netBin === false || strlen($netBin) !== strlen($bin)) {
            return false;
        }
        $bits = $bits === null ? strlen($bin) * 8 : (int) $bits;
        $bytes = intdiv($bits, 8);
        if (substr($bin, 0, $bytes) !== substr($netBin, 0, $bytes)) {
            return false;
        }
        $rest = $bits % 8;
        if ($rest === 0) {
            return true;
        }
        $mask = (0xff << (8 - $rest)) & 0xff;
        return (ord($bin[$bytes]) & $mask) === (ord($netBin[$bytes]) & $mask);
    }
}
