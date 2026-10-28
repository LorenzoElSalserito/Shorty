<?php
// GET ?action=create|report: issues a signed, session-bound ALTCHA challenge.

declare(strict_types=1);

use Shorty\Http\ApiError;
use Shorty\Http\Endpoint;
use Shorty\Http\Gate;
use Shorty\Http\Response;
use Shorty\Security\Session;
use Shorty\Service\Quotas;

$app = require dirname(__DIR__) . '/lib/bootstrap.php';

try {
    Gate::method('GET');
    Gate::transport($app);
    Gate::sameOrigin($app);
    $action = $_GET['action'] ?? '';
    if (!in_array($action, ['create', 'report'], true)) {
        throw new ApiError(400, 'BAD_REQUEST', 'Azione non valida.');
    }
    if ($app->lockdown()->creation() && $action === 'create') {
        throw new ApiError(503, 'SECURITY_LOCKDOWN', 'Creazione link sospesa per manutenzione di sicurezza.');
    }
    Session::start($app, false);
    $level = (new Quotas($app, $app->identity()))->challenge();
    $challenge = $app->altcha()->create($action, Session::binding($app), $action === 'report' ? 'report' : $level);
    $app->metrics()->inc('challenges_' . $level);
    // The widget expects the bare challenge object.
    Response::json(200, $challenge, $app->isHttps());
} catch (\Throwable $e) {
    Endpoint::json($app, static fn () => throw $e, false);
}
