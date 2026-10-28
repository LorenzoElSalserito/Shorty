<?php
// Shorty entry point: landing app, interstitial (?s=CODE), legacy-link handling.
// Works without any rewrite rule; .htaccess only adds the optional /s/CODE form.

declare(strict_types=1);

use Shorty\Http\Response;
use Shorty\Service\Resolver;

$app = require __DIR__ . '/lib/bootstrap.php';
$base = $app->basePath();
$https = false;

try {
    $https = $app->isHttps();
    $app->host();
    if (!in_array($_SERVER['REQUEST_METHOD'] ?? 'GET', ['GET', 'HEAD'], true)) {
        header('Allow: GET, HEAD');
        Response::errorPage(405, 'Metodo non consentito', 'Questa pagina accetta solo richieste GET.', $base, $https);
    }

    $path = (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
    $rel = str_starts_with($path, $base) ? substr($path, strlen($base)) : ltrim($path, '/');
    $code = $_GET['s'] ?? null;
    if ($code === null && preg_match('#^s/([A-Za-z0-9]{1,32})/?$#', $rel, $m)) {
        $code = $m[1];
    }

    if ($code !== null) {
        $app->maybeCollectGarbage();
        if (!is_string($code)) {
            Response::errorPage(404, 'Link non trovato', 'Questo link non esiste o è scaduto.', $base, $https);
        }
        if ($app->lockdown()->full()) {
            Response::errorPage(503, 'Shorty in manutenzione di sicurezza', 'I link sono temporaneamente disabilitati.', $base, $https);
        }
        $resolver = new Resolver($app);
        [$status, $record, $state] = $resolver->resolve($code);
        if ($status === Resolver::NOT_FOUND) {
            Response::errorPage(404, 'Link non trovato', 'Questo link non esiste o è scaduto.', $base, $https);
        }
        if ($status === Resolver::EXPIRED) {
            Response::errorPage(410, 'Link scaduto', 'Questo link è scaduto ed è stato eliminato.', $base, $https);
        }
        if ($status === Resolver::DISABLED) {
            Response::errorPage(410, 'Link disabilitato per motivi di sicurezza', 'Questo link è stato bloccato o messo in quarantena e non può essere aperto.', $base, $https);
        }
        $app->metrics()->inc('interstitial_views');
        Response::page(200, 'interstitial', [
            'base' => $base,
            'code' => $record['code'],
            'host' => $record['host'],
            'url' => $record['url'],
            'state' => $state,
            'delay' => $resolver->minDelay($state),
            'token' => $app->outbound()->issue($record['code']),
            'expires_at' => (int) $record['expires_at'],
        ], $https, true, Shorty\Http\SecurityHeaders::CSP_INTERSTITIAL);
    }

    if ($rel === '' || $rel === 'index.php') {
        $app->maybeCollectGarbage();
        $tpl = __DIR__ . '/lib/templates/app.html';
        if (!is_file($tpl)) {
            Response::errorPage(503, 'Interfaccia non disponibile', 'Pacchetto incompleto: usa la build di release.', $base, $https);
        }
        http_response_code(200);
        Shorty\Http\SecurityHeaders::apply(isset($_GET['r']), $https);
        header('Content-Type: text/html; charset=utf-8');
        readfile($tpl);
        exit;
    }

    // Shorty 1 links (/AbCdEf, 6 chars) were all purged in the v2 cutover.
    if (preg_match('#^[A-Za-z0-9]{6}/?$#', $rel)) {
        Response::errorPage(410, 'Link non più disponibile', 'I link della versione precedente di Shorty sono stati disattivati definitivamente.', $base, $https);
    }
    Response::errorPage(404, 'Pagina non trovata', 'La pagina richiesta non esiste.', $base, $https);
} catch (Shorty\Http\ApiError $e) {
    Response::errorPage($e->status, 'Richiesta non valida', $e->getMessage(), $base, $https);
} catch (\Throwable $e) {
    error_log('Shorty error: ' . get_class($e) . ': ' . $e->getMessage());
    Response::errorPage(503, 'Servizio non disponibile', 'Shorty non può completare la richiesta in sicurezza. Riprova più tardi.', $base, $https);
}
