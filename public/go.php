<?php
// POST code + token from the interstitial "Continua" form. Never accepts a URL:
// the destination is always reloaded server-side from the code.

declare(strict_types=1);

use Shorty\Http\ApiError;
use Shorty\Http\Gate;
use Shorty\Http\Response;
use Shorty\Service\Resolver;

$app = require __DIR__ . '/lib/bootstrap.php';
$base = $app->basePath();
$https = false;

try {
    $https = $app->isHttps();
    Gate::method('POST');
    Gate::transport($app);
    Gate::sameOrigin($app, true);
    if ($app->lockdown()->full()) {
        Response::errorPage(503, 'Shorty in manutenzione di sicurezza', 'I link sono temporaneamente disabilitati.', $base, $https);
    }
    $type = strtolower((string) ($_SERVER['CONTENT_TYPE'] ?? ''));
    if (!str_starts_with($type, 'application/x-www-form-urlencoded') || (int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > 1024) {
        throw new ApiError(400, 'BAD_REQUEST', 'Richiesta non valida.');
    }
    $code = $_POST['code'] ?? '';
    $token = $_POST['token'] ?? '';
    if (!is_string($code) || !is_string($token)) {
        throw new ApiError(400, 'BAD_REQUEST', 'Richiesta non valida.');
    }
    $resolver = new Resolver($app);
    [$status, $record, $state] = $resolver->resolve($code);
    if ($status !== Resolver::OK) {
        Response::errorPage($status === Resolver::NOT_FOUND ? 404 : 410, 'Link non disponibile', 'Questo link non esiste, è scaduto o è stato bloccato.', $base, $https);
    }
    $why = $app->outbound()->check($token, $record['code'], $resolver->minDelay($state));
    if ($why === 'too_early') {
        Response::errorPage(425, 'Attendi qualche secondo', 'Leggi la destinazione prima di continuare, poi riprova.', $base, $https, $base . '?s=' . $record['code']);
    }
    if ($why !== null) {
        Response::errorPage(403, 'Conferma scaduta', 'Riapri il link breve e premi di nuovo «Continua».', $base, $https, $base . '?s=' . $record['code']);
    }
    $app->metrics()->inc('outbound_clicks');
    http_response_code(303);
    header('Cache-Control: no-store');
    header('Referrer-Policy: no-referrer');
    header('X-Robots-Tag: noindex, nofollow, noarchive');
    header('X-Content-Type-Options: nosniff');
    header('Location: ' . $record['url']);
    exit;
} catch (ApiError $e) {
    if ($e->status === 405) {
        Response::errorPage(405, 'Metodo non consentito', 'Apri il link breve e usa il pulsante «Continua».', $base, $https);
    }
    Response::errorPage($e->status, 'Richiesta non valida', $e->getMessage(), $base, $https);
} catch (\Throwable $e) {
    error_log('Shorty go error: ' . get_class($e) . ': ' . $e->getMessage());
    Response::errorPage(503, 'Servizio non disponibile', 'Riprova più tardi.', $base, $https);
}
