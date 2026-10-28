<?php

declare(strict_types=1);

namespace Shorty\Service;

use Shorty\App;
use Shorty\Security\TrustEngine;
use Shorty\Storage\LinkStore;

/**
 * Short code resolution shared by the interstitial and the outbound endpoint.
 * Re-applies expiry, status and hard denylist on every use; a new denylist hit
 * quarantines the link immediately.
 */
final class Resolver
{
    public const OK = 'ok';
    public const NOT_FOUND = 'not_found';
    public const EXPIRED = 'expired';
    public const DISABLED = 'disabled';

    public function __construct(private readonly App $app)
    {
    }

    /** @return array{0: string, 1: ?array, 2: ?string} status, record, trust state */
    public function resolve(string $code): array
    {
        if (!preg_match(LinkStore::CODE_PATTERN, $code)) {
            return [self::NOT_FOUND, null, null];
        }
        $links = $this->app->links();
        $r = $links->get($code);
        if ($r === null) {
            return [self::NOT_FOUND, null, null];
        }
        if ((int) $r['expires_at'] <= $this->app->now()) {
            $links->deleteExpired($code);
            return [self::EXPIRED, null, null];
        }
        if (($r['status'] ?? '') !== 'ACTIVE') {
            return [self::DISABLED, $r, null];
        }
        if (!$this->app->urlPolicy()->stillAllowed($r)) {
            $links->setStatus($code, 'BLOCKED', 'denylist');
            $this->app->metrics()->inc('denylist_hits_open');
            return [self::DISABLED, $r, null];
        }
        $state = $this->app->trust()->state([
            'domain' => $r['domain'],
            'host' => $r['host'],
            'psl_known' => !in_array('unknown_suffix', $r['risk_flags'] ?? [], true),
        ]);
        if ($state === TrustEngine::SUSPICIOUS) {
            return [self::DISABLED, $r, $state];
        }
        return [self::OK, $r, $state];
    }

    public function minDelay(string $state): int
    {
        return $state === TrustEngine::TRUSTED ? 0 : (int) $this->app->config['interstitial_delay'];
    }
}
