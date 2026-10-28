<?php

declare(strict_types=1);

namespace Shorty\Http;

use Shorty\App;

/**
 * Cheap request checks shared by internal endpoints: method, size, content type, origin.
 */
final class Gate
{
    public static function method(string $method): void
    {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== $method) {
            header('Allow: ' . $method);
            throw new ApiError(405, 'METHOD_NOT_ALLOWED', 'Metodo non consentito.');
        }
    }

    public static function transport(App $app): void
    {
        $app->host(); // rejects malformed / non-allowed Host headers
        if (!$app->transportAllowed()) {
            throw new ApiError(403, 'HTTPS_REQUIRED', 'Shorty accetta richieste solo via HTTPS.');
        }
    }

    /**
     * Browser same-origin check. A missing Origin is not proof of legitimacy, but it is
     * not a rejection either: the session, CSRF, ALTCHA and quotas still apply.
     */
    public static function sameOrigin(App $app, bool $allowOpaque = false): void
    {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? null;
        // Pages sent with Referrer-Policy: no-referrer make browsers post forms with
        // "Origin: null"; Sec-Fetch-Site still tells same-origin from cross-site.
        if ($allowOpaque && $origin === 'null') {
            $origin = null;
        }
        if ($origin !== null && strtolower((string) $origin) !== $app->origin()) {
            throw new ApiError(403, 'SECURITY_POLICY', 'Origine della richiesta non consentita.', 'origin');
        }
        $site = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? null;
        if ($site !== null && !in_array($site, ['same-origin', 'none'], true)) {
            throw new ApiError(403, 'SECURITY_POLICY', 'Origine della richiesta non consentita.', 'fetch_site');
        }
    }

    /** Reads a JSON object body with a hard size limit, before parsing. */
    public static function jsonBody(int $maxBytes): array
    {
        $type = strtolower((string) ($_SERVER['CONTENT_TYPE'] ?? ''));
        if (!preg_match('#^application/json\s*(;\s*charset=utf-8\s*)?$#', $type)) {
            throw new ApiError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Content-Type non supportato.');
        }
        $declared = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
        if ($declared > $maxBytes) {
            throw new ApiError(413, 'BODY_TOO_LARGE', 'Richiesta troppo grande.');
        }
        $in = fopen('php://input', 'rb');
        $raw = $in === false ? false : stream_get_contents($in, $maxBytes + 1);
        if ($raw === false || strlen($raw) > $maxBytes) {
            throw new ApiError(413, 'BODY_TOO_LARGE', 'Richiesta troppo grande.');
        }
        try {
            $data = json_decode($raw, true, 4, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new ApiError(400, 'BAD_REQUEST', 'JSON non valido.');
        }
        if (!is_array($data) || array_is_list($data)) {
            throw new ApiError(400, 'BAD_REQUEST', 'JSON non valido.');
        }
        return $data;
    }

    public static function string(array $data, string $key, int $max): string
    {
        $v = $data[$key] ?? null;
        if (!is_string($v) || $v === '' || strlen($v) > $max) {
            throw new ApiError(400, 'BAD_REQUEST', 'Campo mancante o non valido: ' . $key . '.');
        }
        return $v;
    }
}
