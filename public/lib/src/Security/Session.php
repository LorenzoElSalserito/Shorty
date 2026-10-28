<?php

declare(strict_types=1);

namespace Shorty\Security;

use Shorty\App;
use Shorty\Http\ApiError;

/**
 * Security-only session (no analytics, no tracking) carrying the one-time CSRF token.
 */
final class Session
{
    public static function start(App $app, bool $create): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.use_trans_sid', '0');
        ini_set('session.cookie_httponly', '1');
        ini_set('session.gc_maxlifetime', (string) $app->config['session_idle']);
        session_name($app->isHttps() ? '__Host-shorty' : 'shorty_sid');
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => $app->isHttps() ? '/' : $app->basePath(),
            'secure' => $app->isHttps(),
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        if (!$create && !isset($_COOKIE[session_name()])) {
            throw new ApiError(403, 'SESSION_REQUIRED', 'Sessione mancante: ricarica la pagina.');
        }
        if (!@session_start()) {
            throw new ApiError(503, 'SERVICE_UNAVAILABLE', 'Sessione non disponibile.');
        }
        $now = time();
        $last = (int) ($_SESSION['last'] ?? 0);
        $idle = (int) $app->config['session_idle'];
        if (!$create && ($last === 0 || $now - $last > $idle)) {
            $_SESSION = [];
            throw new ApiError(403, 'SESSION_EXPIRED', 'Sessione scaduta: ricarica la pagina.');
        }
        if ($last !== 0 && $now - $last > $idle) {
            $_SESSION = [];
            session_regenerate_id(true);
        }
        $_SESSION['last'] = $now;
    }

    /** Binding value for ALTCHA challenges: ties a proof to this session. */
    public static function binding(App $app): string
    {
        $_SESSION['bind'] ??= bin2hex(random_bytes(16));
        return substr(hash_hmac('sha256', (string) $_SESSION['bind'], $app->secrets()->key('session-binding')), 0, 32);
    }

    public static function issueCsrf(): string
    {
        $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $_SESSION['csrf'] = $token;
        return $token;
    }

    /** Constant-time check; the token is invalidated whatever the outcome. */
    public static function consumeCsrf(mixed $given): void
    {
        $expected = $_SESSION['csrf'] ?? null;
        unset($_SESSION['csrf']);
        if (!is_string($expected) || !is_string($given) || !hash_equals($expected, $given)) {
            throw new ApiError(403, 'CSRF_INVALID', 'Token di sicurezza non valido: riprova.');
        }
    }
}
