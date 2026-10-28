<?php

declare(strict_types=1);

namespace Shorty\Security;

use Shorty\App;

/**
 * Short-lived signed token that lets the interstitial's "Continua" form leave Shorty.
 * Payload: code | issued_at | expires_at | nonce, HMAC scope outbound:v1.
 */
final class OutboundToken
{
    public function __construct(private readonly string $key, private readonly App $app)
    {
    }

    public function issue(string $code): string
    {
        $now = $this->app->now();
        $body = implode('|', [$code, $now, $now + (int) $this->app->config['outbound_token_ttl'], bin2hex(random_bytes(8))]);
        return self::b64($body) . '.' . self::b64(hash_hmac('sha256', 'outbound:v1|' . $body, $this->key, true));
    }

    /**
     * @return string|null null when valid, otherwise a reason (mismatch, expired, too_early, invalid)
     */
    public function check(string $token, string $code, int $minDelay): ?string
    {
        $parts = explode('.', $token);
        if (count($parts) !== 2 || strlen($token) > 256) {
            return 'invalid';
        }
        $body = self::unb64($parts[0]);
        $mac = self::unb64($parts[1]);
        if ($body === null || $mac === null || !hash_equals(hash_hmac('sha256', 'outbound:v1|' . $body, $this->key, true), $mac)) {
            return 'invalid';
        }
        $f = explode('|', $body);
        if (count($f) !== 4 || !hash_equals($f[0], $code)) {
            return 'mismatch';
        }
        $now = $this->app->now();
        if ($now > (int) $f[2]) {
            return 'expired';
        }
        if ($now - (int) $f[1] < $minDelay) {
            return 'too_early';
        }
        return null;
    }

    private static function b64(string $s): string
    {
        return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    }

    private static function unb64(string $s): ?string
    {
        if (!preg_match('/^[A-Za-z0-9_-]+$/', $s)) {
            return null;
        }
        $r = base64_decode(strtr($s, '-_', '+/'), true);
        return $r === false ? null : $r;
    }
}
