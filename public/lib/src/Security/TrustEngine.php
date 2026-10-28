<?php

declare(strict_types=1);

namespace Shorty\Security;

use Shorty\App;
use Shorty\Storage\GuardedFile;
use Shorty\Storage\Records;

/**
 * Local domain reputation. TRUSTED_LOCAL means "good local history and no known block",
 * never "safe". Trust only shortens the interstitial countdown and raises the per-domain
 * quota; ALTCHA, the 3/IP quota, the interstitial and the denylist always apply.
 */
final class TrustEngine
{
    public const BLOCKED = 'BLOCKED';
    public const SUSPICIOUS = 'SUSPICIOUS';
    public const UNKNOWN = 'UNKNOWN';
    public const TRUSTED = 'TRUSTED_LOCAL';

    public function __construct(private readonly App $app)
    {
    }

    public function path(string $domain): string
    {
        return GuardedFile::sharded($this->app->runtimeDir() . '/domains', hash('sha256', 'domain|' . $domain));
    }

    public function record(string $domain): array
    {
        return GuardedFile::read($this->path($domain)) ?? [];
    }

    /** @param array{domain: string, host: string, psl_known: bool} $c */
    public function state(array $c, ?array $record = null): string
    {
        $r = $record ?? $this->record($c['domain']);
        if ((int) ($r['quarantines'] ?? 0) > 0 || (int) ($r['abuse_reports'] ?? 0) >= 3) {
            return self::SUSPICIOUS;
        }
        $cfg = $this->app->config['trust'];
        $eligible = $c['psl_known']
            && $this->app->feed()->available()
            && !$this->app->urlPolicy()->isRiskyPlatform($c['host'])
            && (int) ($r['abuse_reports'] ?? 0) === 0
            && isset($r['first_seen'])
            && $this->app->now() - (int) $r['first_seen'] >= $cfg['min_age']
            && count($r['buckets'] ?? []) >= $cfg['min_distinct_subnets'];
        return $eligible ? self::TRUSTED : self::UNKNOWN;
    }

    /** Creations toward this domain inside the quota window. */
    public function recentCreations(array $r, int $window): int
    {
        return count(Records::window($r['creations'] ?? [], $this->app->now(), $window));
    }

    /** Must run under the domain lock (CreateLink transaction). */
    public function recordCreation(string $domain, string $bucket): void
    {
        $now = $this->app->now();
        $window = (int) max($this->app->config['quota']['domain_unknown_links'][1], $this->app->config['quota']['domain_trusted_links'][1]);
        Records::update($this->app, $this->path($domain), function (array $r) use ($domain, $bucket, $now, $window) {
            $r['domain'] = $domain;
            $r['first_seen'] ??= $now;
            $r['last_seen'] = $now;
            $r['successful_links'] = (int) ($r['successful_links'] ?? 0) + 1;
            $buckets = $r['buckets'] ?? [];
            if (!in_array($bucket, $buckets, true)) {
                $buckets[] = $bucket;
            }
            $r['buckets'] = array_slice($buckets, -16);
            $r['creations'] = array_merge(Records::window($r['creations'] ?? [], $now, $window), [$now]);
            $r['purge_after'] = $now + (int) $this->app->config['trust']['retention'];
            return $r;
        });
    }

    public function recordAbuse(string $domain, bool $quarantined): void
    {
        $path = $this->path($domain);
        $now = $this->app->now();
        $this->app->locks()->with([$path], fn () => Records::update($this->app, $path, function (array $r) use ($domain, $quarantined, $now) {
            $r['domain'] = $domain;
            $r['first_seen'] ??= $now;
            $r['last_seen'] = $now;
            $r['abuse_reports'] = (int) ($r['abuse_reports'] ?? 0) + 1;
            $r['quarantines'] = (int) ($r['quarantines'] ?? 0) + ($quarantined ? 1 : 0);
            $r['purge_after'] = $now + (int) $this->app->config['trust']['retention'];
            return $r;
        }));
    }
}
