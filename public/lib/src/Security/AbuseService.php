<?php

declare(strict_types=1);

namespace Shorty\Security;

use Shorty\App;
use Shorty\Http\ApiError;
use Shorty\Storage\GuardedFile;
use Shorty\Storage\Records;

/**
 * Abuse reports with conservative auto-quarantine. Reports store only pseudonymous
 * reporter/subnet HMACs, a predefined category and a timestamp.
 */
final class AbuseService
{
    public const CATEGORIES = ['phishing', 'malware', 'scam', 'impersonation', 'other'];

    public function __construct(private readonly App $app)
    {
    }

    /** @return array{quarantined: bool} */
    public function report(string $code, string $category, ClientIdentity $who): array
    {
        if (!in_array($category, self::CATEGORIES, true)) {
            throw new ApiError(400, 'BAD_REQUEST', 'Categoria non valida.');
        }
        $link = $this->app->links()->get($code);
        if ($link === null) {
            throw new ApiError(404, 'NOT_FOUND', 'Link non trovato o scaduto.');
        }
        $now = $this->app->now();
        $limits = $this->app->config['limits'];
        $cfg = $this->app->config['abuse'];
        $rateRetention = (int) $this->app->config['retention']['rate'];
        $reporterPath = GuardedFile::sharded($this->app->runtimeDir() . '/reporters', $who->reporterId());
        $subnetPath = GuardedFile::sharded($this->app->runtimeDir() . '/reporters', $who->reporterSubnetId());
        $reportPath = GuardedFile::sharded($this->app->runtimeDir() . '/reports', hash('sha256', 'report|' . $code));

        $quarantined = $this->app->locks()->with([$reporterPath, $subnetPath, $reportPath], function () use (
            $code, $category, $who, $now, $limits, $cfg, $rateRetention, $reporterPath, $subnetPath, $reportPath, $link
        ) {
            $rep = GuardedFile::read($reporterPath) ?? [];
            $sub = GuardedFile::read($subnetPath) ?? [];
            [$n1, $w1] = $limits['reporter_reports'];
            [$n2, $w2] = $limits['reporter_subnet_reports'];
            if (count(Records::window($rep['reports'] ?? [], $now, $w1)) >= $n1
                || count(Records::window($sub['reports'] ?? [], $now, $w2)) >= $n2) {
                throw new ApiError(429, 'RATE_LIMIT', 'Troppe segnalazioni: riprova più tardi.');
            }
            $reports = GuardedFile::read($reportPath) ?? [];
            foreach ($reports['items'] ?? [] as $item) {
                if (hash_equals((string) $item['reporter'], $who->reporterId())) {
                    return null; // already reported by this reporter: no double counting
                }
            }
            foreach ([[$reporterPath, $w1], [$subnetPath, $w2]] as [$p, $w]) {
                Records::update($this->app, $p, fn (array $d) => [
                    'reports' => array_merge(Records::window($d['reports'] ?? [], $now, $w), [$now]),
                    'purge_after' => $now + $rateRetention,
                ]);
            }
            $data = Records::update($this->app, $reportPath, function (array $d) use ($code, $category, $who, $now, $cfg) {
                $d['code'] = $code;
                $d['items'][] = [
                    'category' => $category,
                    'reporter' => $who->reporterId(),
                    'subnet' => $who->reporterSubnetId(),
                    'at' => $now,
                ];
                $d['purge_after'] = $now + (int) $cfg['retention'];
                return $d;
            });
            $subnets = count(array_unique(array_column($data['items'], 'subnet')));
            $signal = ($link['risk_flags'] ?? []) !== [];
            return $subnets >= $cfg['quarantine_subnets']
                || ($signal && $subnets >= $cfg['quarantine_subnets_with_signal']);
        });

        if ($quarantined === null) {
            return ['quarantined' => ($link['status'] ?? '') !== 'ACTIVE'];
        }
        $this->app->metrics()->inc('abuse_reports');
        if ($quarantined && ($link['status'] ?? '') === 'ACTIVE') {
            $this->app->links()->setStatus($code, 'QUARANTINED', 'abuse_reports');
            $this->app->metrics()->inc('quarantines');
        }
        $this->app->trust()->recordAbuse((string) $link['domain'], $quarantined);
        return ['quarantined' => $quarantined];
    }
}
