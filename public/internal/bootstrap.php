<?php
// GET: starts the security-only session and returns the first CSRF token + public limits.

declare(strict_types=1);

use Shorty\Http\Endpoint;
use Shorty\Http\Gate;
use Shorty\Security\Session;
use Shorty\Service\Quotas;

$app = require dirname(__DIR__) . '/lib/bootstrap.php';

Endpoint::json($app, static function () use ($app) {
    Gate::method('GET');
    Gate::transport($app);
    Gate::sameOrigin($app);
    $app->secrets()->key('identity'); // fail closed early if runtime is not writable
    Session::start($app, true);
    Session::binding($app);
    $q = $app->config['quota']['actor_links'];
    return [
        'ttls' => array_keys($app->config['allowed_ttls']),
        'default_ttl' => $app->config['default_ttl'],
        'quota' => ['max' => $q[0], 'window_hours' => intdiv($q[1], 3600)],
        'remaining' => (new Quotas($app, $app->identity()))->remaining(),
        'lockdown' => $app->lockdown()->creation(),
        'report_categories' => \Shorty\Security\AbuseService::CATEGORIES,
    ];
});
