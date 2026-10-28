<?php

declare(strict_types=1);

namespace Shorty\Http;

final class Response
{
    public static function json(int $status, array $body, bool $https = false): never
    {
        http_response_code($status);
        SecurityHeaders::apply(true, $https);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        exit;
    }

    public static function error(ApiError $e, array $extra = [], bool $https = false): never
    {
        self::json($e->status, ['error' => $e->errorCode, 'message' => $e->getMessage()] + $extra, $https);
    }

    /** Renders a template from lib/templates with escaped variables available as $v. */
    public static function page(int $status, string $template, array $v, bool $https = false, bool $noindex = true, string $csp = SecurityHeaders::CSP): never
    {
        http_response_code($status);
        SecurityHeaders::apply($noindex, $https, $csp);
        header('Content-Type: text/html; charset=utf-8');
        $e = static fn (mixed $s): string => htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
        require dirname(__DIR__, 2) . '/templates/' . $template . '.php';
        exit;
    }

    public static function errorPage(int $status, string $title, string $message, string $base = './', bool $https = false, ?string $back = null): never
    {
        self::page($status, 'error', ['title' => $title, 'message' => $message, 'base' => $base, 'back' => $back ?? $base], $https);
    }
}
