<?php

declare(strict_types=1);

namespace Shorty\Http;

use Shorty\App;
use Shorty\Security\Session;

/**
 * Wraps internal JSON endpoints: uniform errors, fail closed on unexpected failures,
 * a fresh one-time CSRF token on every response once a session exists.
 */
final class Endpoint
{
    public static function json(App $app, callable $handler, bool $rotateCsrf = true): never
    {
        $https = false;
        try {
            $https = $app->isHttps();
            $body = $handler();
            $app->maybeCollectGarbage();
            Response::json(200, $body + self::csrf($rotateCsrf), $https);
        } catch (ApiError $e) {
            if ($e->reason !== null) {
                $app->metrics()->inc('reject_' . $e->reason);
            }
            $app->metrics()->inc('reject_' . strtolower($e->errorCode));
            Response::error($e, self::csrf($rotateCsrf), $https);
        } catch (\Throwable $e) {
            error_log('Shorty internal error: ' . get_class($e) . ': ' . $e->getMessage());
            Response::json(503, ['error' => 'SERVICE_UNAVAILABLE', 'message' => 'Servizio temporaneamente non disponibile.'] + self::csrf($rotateCsrf), $https);
        }
    }

    private static function csrf(bool $rotate): array
    {
        if (!$rotate) {
            return [];
        }
        try {
            return session_status() === PHP_SESSION_ACTIVE ? ['csrf' => Session::issueCsrf()] : [];
        } catch (\Throwable) {
            return [];
        }
    }
}
