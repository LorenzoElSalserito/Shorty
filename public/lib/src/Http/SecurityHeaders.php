<?php

declare(strict_types=1);

namespace Shorty\Http;

/**
 * Single source of truth for response security headers.
 */
final class SecurityHeaders
{
    public const CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        . "img-src 'self' data:; font-src 'self'; connect-src 'self'; worker-src 'self'; "
        . "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

    /**
     * Interstitial only: the "Continua" form posts to go.php, which answers 303 to the stored
     * https destination. Browsers apply form-action to that redirect, so https: must be
     * allowed there (the target is never taken from the client).
     */
    public const CSP_INTERSTITIAL = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
        . "connect-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self' https:";

    /**
     * @param bool $noindex add X-Robots-Tag (interstitial, technical endpoints, errors)
     */
    public static function apply(bool $noindex = true, bool $https = false, string $csp = self::CSP): void
    {
        if (headers_sent()) {
            return;
        }
        header_remove('X-Powered-By');
        header('Content-Security-Policy: ' . $csp);
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: no-referrer');
        header('X-Frame-Options: DENY');
        header('Cross-Origin-Opener-Policy: same-origin');
        header('Cross-Origin-Resource-Policy: same-origin');
        header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()');
        header('Cache-Control: no-store, max-age=0');
        header('Pragma: no-cache');
        if ($noindex) {
            header('X-Robots-Tag: noindex, nofollow, noarchive');
        }
        if ($https) {
            header('Strict-Transport-Security: max-age=15552000');
        }
    }
}
