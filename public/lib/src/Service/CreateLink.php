<?php

declare(strict_types=1);

namespace Shorty\Service;

use Shorty\App;
use Shorty\Http\ApiError;
use Shorty\Security\TrustEngine;
use Shorty\Storage\GuardedFile;
use Shorty\Storage\Records;

/**
 * Link creation after the request gate (method, size, type, session, origin, CSRF).
 * Order: attempt limiter → quota pre-check → parse → TTL enum → URL syntax → ALTCHA →
 * lists/DNS → domain trust → locked transaction (dedup, quotas, atomic insert).
 */
final class CreateLink
{
    public function __construct(private readonly App $app)
    {
    }

    /** @return array{code: string, short_path: string, expires_at: int, ttl: string, deduplicated: bool, remaining: int} */
    public function handle(array $input, string $binding): array
    {
        $app = $this->app;
        $quotas = new Quotas($app, $app->identity());
        $quotas->attempt();
        $quotas->precheckActor();

        $ttl = $input['ttl'] ?? null;
        $ttls = $app->config['allowed_ttls'];
        if (!is_string($ttl) || !isset($ttls[$ttl])) {
            throw new ApiError(400, 'TTL_NOT_ALLOWED', 'Durata non ammessa: scegli 5 ore, 1 giorno o 7 giorni.');
        }
        $url = $input['url'] ?? null;
        if (!is_string($url)) {
            throw new ApiError(400, 'INVALID_URL', 'URL non valido.', 'type');
        }
        $c = $app->urlPolicy()->canonicalize($url);

        $app->altcha()->verify($input['altcha'] ?? null, 'create', $binding);

        $app->urlPolicy()->enforce($c);

        $trust = $app->trust();
        $state = $trust->state($c);
        if ($state === TrustEngine::SUSPICIOUS) {
            throw new ApiError(403, 'SECURITY_POLICY', 'Destinazione sospesa per segnalazioni di abuso.', 'domain_suspicious');
        }

        $id = $app->identity();
        $links = $app->links();
        $code = $links->freshCode();
        $domainPath = $trust->path($c['domain']);
        $dedupPath = $links->dedupPath($id->actorId(), $c['url_hash']);
        $linkPath = $links->path($code);
        $now = $app->now();

        $result = $app->locks()->with(
            [$quotas->globalPath(), $quotas->subnetPath(), $quotas->actorPath(), $domainPath, $dedupPath, $linkPath],
            function () use ($app, $c, $ttl, $ttls, $state, $trust, $quotas, $links, $id, $code, $domainPath, $dedupPath, $now) {
                // Dedup: same actor + same canonical URL with an active link -> same link, no quota.
                $dup = GuardedFile::read($dedupPath);
                if ($dup !== null) {
                    $existing = $links->get((string) $dup['code']);
                    if ($existing && ($existing['status'] ?? '') === 'ACTIVE' && (int) $existing['expires_at'] > $now
                        && hash_equals((string) $existing['actor_id'], $id->actorId())) {
                        return ['record' => $existing, 'deduplicated' => true];
                    }
                }

                $quotas->assertSuccessQuota();
                $q = $app->config['quota'];
                [$max, $window] = $state === TrustEngine::TRUSTED ? $q['domain_trusted_links'] : $q['domain_unknown_links'];
                $domain = GuardedFile::read($domainPath) ?? [];
                if ($trust->recentCreations($domain, $window) >= $max) {
                    throw new ApiError(429, 'RATE_LIMIT', 'Troppi link recenti verso questo dominio. Riprova più tardi.', 'domain_quota');
                }

                $expires = $now + $ttls[$ttl];
                $flags = [];
                if (!isset($domain['first_seen']) || $now - (int) $domain['first_seen'] < $app->config['trust']['min_age']) {
                    $flags[] = 'new_domain';
                }
                if (!$c['psl_known']) {
                    $flags[] = 'unknown_suffix';
                }
                if (!$app->feed()->available()) {
                    $flags[] = 'feed_unavailable';
                }
                if ($app->urlPolicy()->isRiskyPlatform($c['host'])) {
                    $flags[] = 'hosting_platform';
                }
                $record = [
                    'v' => 2,
                    'code' => $code,
                    'url' => $c['url'],
                    'url_hash' => $c['url_hash'],
                    'host' => $c['host'],
                    'domain' => $c['domain'],
                    'created_at' => $now,
                    'expires_at' => $expires,
                    'ttl' => $ttl,
                    'actor_id' => $id->actorId(),
                    'trust_state' => $state,
                    'status' => 'ACTIVE',
                    'risk_flags' => $flags,
                    'purge_after' => $expires,
                ];
                $links->insert($record);
                try {
                    $quotas->registerSuccess();
                    $trust->recordCreation($c['domain'], $id->trustBucket());
                    Records::update($app, $dedupPath, fn () => ['code' => $code, 'purge_after' => $expires]);
                } catch (\Throwable $e) {
                    // Compensation: never keep a link whose quota was not recorded.
                    $links->remove($code);
                    $quotas->rollbackSuccess();
                    throw $e;
                }
                return ['record' => $record, 'deduplicated' => false];
            },
        );

        $r = $result['record'];
        $app->metrics()->inc($result['deduplicated'] ? 'create_dedup' : 'create_success');
        $app->metrics()->inc('active_links_' . $r['ttl']);
        return [
            'code' => $r['code'],
            'short_path' => '?s=' . $r['code'],
            'expires_at' => (int) $r['expires_at'],
            'ttl' => $r['ttl'],
            'deduplicated' => $result['deduplicated'],
            'remaining' => $quotas->remaining(),
        ];
    }
}
