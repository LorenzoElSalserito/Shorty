<?php

declare(strict_types=1);

namespace Shorty\Service;

use Shorty\App;
use Shorty\Http\ApiError;
use Shorty\Security\ClientIdentity;
use Shorty\Storage\GuardedFile;
use Shorty\Storage\Records;

/**
 * File-based rolling-window counters per pseudonymous actor / subnet / instance.
 * Every method that reads-then-writes runs under the LockManager stripes of its files.
 */
final class Quotas
{
    public function __construct(private readonly App $app, private readonly ClientIdentity $id)
    {
    }

    public function actorPath(): string
    {
        return GuardedFile::sharded($this->app->runtimeDir() . '/actors', $this->id->actorId());
    }

    public function subnetPath(): string
    {
        return GuardedFile::sharded($this->app->runtimeDir() . '/subnets', $this->id->subnetId());
    }

    public function globalPath(): string
    {
        return $this->app->runtimeDir() . '/global/links.php';
    }

    /** Flood limiter for create/report attempts. Records the attempt, then checks. */
    public function attempt(): void
    {
        $l = $this->app->config['limits'];
        $now = $this->app->now();
        $this->app->locks()->with([$this->actorPath(), $this->subnetPath()], function () use ($l, $now) {
            $actor = GuardedFile::read($this->actorPath()) ?? [];
            $subnet = GuardedFile::read($this->subnetPath()) ?? [];
            $short = count(Records::window($actor['attempts'] ?? [], $now, $l['actor_attempts_short'][1]));
            $long = count(Records::window($actor['attempts'] ?? [], $now, $l['actor_attempts_long'][1]));
            $sub = count(Records::window($subnet['attempts'] ?? [], $now, $l['subnet_attempts'][1]));
            if ($short >= $l['actor_attempts_short'][0] || $long >= $l['actor_attempts_long'][0] || $sub >= $l['subnet_attempts'][0]) {
                throw new ApiError(429, 'RATE_LIMIT', 'Troppi tentativi: riprova più tardi.');
            }
            $this->push($this->actorPath(), 'attempts', $now, (int) $l['actor_attempts_long'][1]);
            $this->push($this->subnetPath(), 'attempts', $now, (int) $l['subnet_attempts'][1]);
        });
    }

    /** Challenge issuance limiter; returns the difficulty level for this client. */
    public function challenge(): string
    {
        $l = $this->app->config['limits'];
        $a = $this->app->config['altcha'];
        $now = $this->app->now();
        return $this->app->locks()->with([$this->actorPath(), $this->subnetPath()], function () use ($l, $a, $now) {
            $actor = GuardedFile::read($this->actorPath()) ?? [];
            $subnet = GuardedFile::read($this->subnetPath()) ?? [];
            if (count(Records::window($actor['challenges'] ?? [], $now, $l['actor_challenges'][1])) >= $l['actor_challenges'][0]) {
                throw new ApiError(429, 'RATE_LIMIT', 'Troppe richieste di verifica: riprova più tardi.');
            }
            $this->push($this->actorPath(), 'challenges', $now, (int) $l['actor_challenges'][1]);
            $recent = count(Records::window($actor['attempts'] ?? [], $now, $l['actor_attempts_short'][1]));
            $subnetRecent = count(Records::window($subnet['attempts'] ?? [], $now, $l['subnet_attempts'][1]));
            if ($subnetRecent >= $a['high_after_subnet_attempts']) {
                return 'high';
            }
            return $recent >= $a['medium_after_attempts'] ? 'medium' : 'base';
        });
    }

    /** Cheap pre-check of the 3/24h success quota (re-checked inside the transaction). */
    public function precheckActor(): void
    {
        $actor = GuardedFile::read($this->actorPath()) ?? [];
        [$max, $window] = $this->app->config['quota']['actor_links'];
        if (count(Records::window($actor['success'] ?? [], $this->app->now(), $window)) >= $max) {
            throw new ApiError(429, 'DAILY_QUOTA', self::quotaMessage($max));
        }
    }

    /** Must run under locks for actor, subnet and global paths. */
    public function assertSuccessQuota(): void
    {
        $q = $this->app->config['quota'];
        $now = $this->app->now();
        $actor = GuardedFile::read($this->actorPath()) ?? [];
        $subnet = GuardedFile::read($this->subnetPath()) ?? [];
        $global = GuardedFile::read($this->globalPath()) ?? [];
        if (count(Records::window($actor['success'] ?? [], $now, $q['actor_links'][1])) >= $q['actor_links'][0]) {
            throw new ApiError(429, 'DAILY_QUOTA', self::quotaMessage($q['actor_links'][0]));
        }
        if (count(Records::window($subnet['success'] ?? [], $now, $q['subnet_links'][1])) >= $q['subnet_links'][0]) {
            throw new ApiError(429, 'DAILY_QUOTA', 'Limite giornaliero raggiunto per la tua rete. Riprova più tardi.');
        }
        if (count(Records::window($global['success'] ?? [], $now, $q['global_links'][1])) >= $q['global_links'][0]) {
            throw new ApiError(503, 'SECURITY_LOCKDOWN', 'Shorty ha raggiunto il limite giornaliero di creazione. Riprova più tardi.');
        }
    }

    /** Must run under the same locks as assertSuccessQuota(). */
    public function registerSuccess(): void
    {
        $q = $this->app->config['quota'];
        $now = $this->app->now();
        $this->push($this->actorPath(), 'success', $now, (int) $q['actor_links'][1]);
        $this->push($this->subnetPath(), 'success', $now, (int) $q['subnet_links'][1]);
        $this->push($this->globalPath(), 'success', $now, (int) $q['global_links'][1]);
    }

    /** Rolls back registerSuccess() for the current timestamp (compensation). */
    public function rollbackSuccess(): void
    {
        $now = $this->app->now();
        foreach ([$this->actorPath(), $this->subnetPath(), $this->globalPath()] as $path) {
            try {
                $d = GuardedFile::read($path);
                if ($d && ($i = array_search($now, $d['success'] ?? [], true)) !== false) {
                    array_splice($d['success'], $i, 1);
                    GuardedFile::write($path, $d);
                }
            } catch (\Throwable) {
                // Best effort: an over-count only makes the quota stricter.
            }
        }
    }

    public function remaining(): int
    {
        [$max, $window] = $this->app->config['quota']['actor_links'];
        $actor = GuardedFile::read($this->actorPath()) ?? [];
        return max(0, $max - count(Records::window($actor['success'] ?? [], $this->app->now(), $window)));
    }

    private function push(string $path, string $series, int $now, int $window): void
    {
        $retention = (int) $this->app->config['retention']['rate'];
        Records::update($this->app, $path, function (array $d) use ($series, $now, $window, $retention) {
            foreach (['attempts', 'success', 'challenges'] as $s) {
                if (isset($d[$s])) {
                    $d[$s] = Records::window($d[$s], $now, max($window, 86400));
                }
            }
            $d[$series][] = $now;
            $d['purge_after'] = $now + $retention;
            return $d;
        });
    }

    private static function quotaMessage(int $max): string
    {
        return "Per proteggere il servizio, ogni indirizzo può creare al massimo {$max} link ogni 24 ore.";
    }
}
