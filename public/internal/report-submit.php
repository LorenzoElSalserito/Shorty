<?php
// POST JSON {code, category, altcha, csrf}: abuse report.

declare(strict_types=1);

use Shorty\Http\Endpoint;
use Shorty\Http\Gate;
use Shorty\Security\Session;

$app = require dirname(__DIR__) . '/lib/bootstrap.php';

Endpoint::json($app, static function () use ($app) {
    Gate::method('POST');
    Gate::transport($app);
    $input = Gate::jsonBody((int) $app->config['max_body']);
    Session::start($app, false);
    Gate::sameOrigin($app);
    Session::consumeCsrf($input['csrf'] ?? null);
    $code = Gate::string($input, 'code', 10);
    $category = Gate::string($input, 'category', 32);
    $app->altcha()->verify($input['altcha'] ?? null, 'report', Session::binding($app));
    $result = $app->abuse()->report($code, $category, $app->identity());
    return ['ok' => true] + $result;
});
