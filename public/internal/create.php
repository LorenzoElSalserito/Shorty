<?php
// POST JSON {url, ttl, altcha, csrf}: protected link creation (not a public API).

declare(strict_types=1);

use Shorty\Http\ApiError;
use Shorty\Http\Endpoint;
use Shorty\Http\Gate;
use Shorty\Security\Session;
use Shorty\Service\CreateLink;

$app = require dirname(__DIR__) . '/lib/bootstrap.php';

Endpoint::json($app, static function () use ($app) {
    if ($app->lockdown()->creation()) {
        throw new ApiError(503, 'SECURITY_LOCKDOWN', 'Creazione link sospesa per manutenzione di sicurezza.');
    }
    Gate::method('POST');
    Gate::transport($app);
    $input = Gate::jsonBody((int) $app->config['max_body']);
    Session::start($app, false);
    Gate::sameOrigin($app);
    Session::consumeCsrf($input['csrf'] ?? null);
    $app->metrics()->inc('create_attempts');
    return (new CreateLink($app))->handle($input, Session::binding($app));
});
