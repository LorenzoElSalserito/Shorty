<?php

declare(strict_types=1);

namespace Shorty\Storage;

use Shorty\App;

/**
 * Daily aggregate counters (no identifiers): runtime/metrics/YYYY-MM-DD.php.
 */
final class Metrics
{
    public function __construct(private readonly App $app)
    {
    }

    public function inc(string $name, int $by = 1): void
    {
        try {
            $now = $this->app->now();
            $path = $this->app->runtimeDir() . '/metrics/' . gmdate('Y-m-d', $now) . '.php';
            $retention = (int) $this->app->config['retention']['metrics'];
            $this->app->locks()->with([$path], fn () => Records::update($this->app, $path, function (array $d) use ($name, $by, $now, $retention) {
                $d['counters'][$name] = (int) ($d['counters'][$name] ?? 0) + $by;
                $d['purge_after'] = $now + $retention;
                return $d;
            }), LockManager::METRICS);
        } catch (\Throwable) {
            // Metrics never block a request.
        }
    }
}
