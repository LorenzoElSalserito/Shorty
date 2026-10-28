<?php

declare(strict_types=1);

namespace Shorty\Security;

use Shorty\App;
use Shorty\Http\ApiError;

/**
 * Default-deny destination policy. Order: cheap syntax first, DNS and lists last.
 *
 * trim → length → charset → parse → scheme → userinfo → host → port → punycode →
 * self-domain → risky extension → nested shortener → local denylist → threat feed →
 * DNS public-only → canonical output
 */
final class UrlPolicy
{
    private array $lists = [];

    public function __construct(private readonly App $app)
    {
    }

    /** Syntax-only stage (no I/O): run before ALTCHA verification. */
    public function canonicalize(string $input): array
    {
        $cfg = $this->app->config['url'];
        $url = trim($input, " \t\r\n");
        if ($url === '' || strlen($url) > $cfg['max_length']) {
            throw self::invalid('length');
        }
        // Printable ASCII only: no whitespace, controls, backslashes or raw Unicode, which
        // different parsers (PHP, browsers, crawlers) interpret differently.
        if (!preg_match('/^[\x21-\x7e]+$/', $url) || str_contains($url, '\\')) {
            throw self::invalid('charset');
        }
        if (!preg_match('#^https://#i', $url)) {
            throw self::policy('scheme', 'Sono accettati solo link https://.');
        }
        $p = parse_url($url);
        if ($p === false || !isset($p['host']) || strtolower($p['scheme'] ?? '') !== 'https') {
            throw self::invalid('parse');
        }
        $authority = substr($url, 8, strcspn($url, '/?#', 8));
        if (isset($p['user']) || isset($p['pass']) || str_contains($authority, '@')) {
            throw self::policy('userinfo', 'I link con credenziali (user@host) non sono ammessi.');
        }
        $host = strtolower($p['host']);
        if (str_ends_with($host, '.')) {
            $host = substr($host, 0, -1);
        }
        if (str_starts_with($host, '[') || filter_var($host, FILTER_VALIDATE_IP) !== false
            || preg_match('/^[0-9.]+$/', $host) || preg_match('/^0x/i', $host)) {
            throw self::policy('ip_literal', 'Gli indirizzi IP non sono ammessi: usa un nome di dominio.');
        }
        if (strlen($host) > 253 || !preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/', $host)) {
            throw self::invalid('host');
        }
        if (isset($p['port']) && (int) $p['port'] !== 443) {
            throw self::policy('port', 'Sono ammesse solo destinazioni sulla porta standard 443.');
        }
        if (preg_match('/(^|\.)xn--/', $host)) {
            throw self::policy('punycode', 'I domini internazionalizzati (punycode) non sono ammessi in questa versione.');
        }
        if (preg_match('/(^|\.)(localhost|local|internal|intranet|home|lan|corp|test|example|invalid|onion|arpa|home\.arpa)$/', $host)) {
            throw self::policy('local_host', 'Destinazione locale o riservata non ammessa.');
        }
        foreach ($this->app->selfHosts() as $self) {
            if ($host === $self || str_ends_with($host, '.' . $self)) {
                throw self::policy('self_domain', 'Non è possibile accorciare link verso Shorty stesso.');
            }
        }

        $path = $p['path'] ?? '/';
        $query = $p['query'] ?? null;
        if (strlen($path) > $cfg['max_path_length'] || ($query !== null && strlen($query) > $cfg['max_query_length'])) {
            throw self::invalid('length');
        }
        if ($path === '' || $path[0] !== '/') {
            $path = '/' . $path;
        }
        if ($this->riskyPath($path)) {
            throw self::policy('risky_extension', 'Link a file eseguibili o archivi non ammessi.');
        }
        if ($this->listed('nested-shorteners.txt', $host)) {
            throw new ApiError(403, 'NESTED_REDIRECTOR', 'Link verso altri URL shortener o redirector non ammessi.', 'nested_shortener');
        }

        // Canonical form: lowercase scheme/host, no explicit :443, no fragment.
        $canonical = 'https://' . $host . $path . ($query !== null && $query !== '' ? '?' . $query : '');
        if (strlen($canonical) > $cfg['max_length']) {
            throw self::invalid('length');
        }
        $registrable = $this->app->domains()->resolve($host);
        if ($registrable['domain'] === null) {
            throw self::policy('public_suffix', 'Il dominio indicato è un suffisso pubblico, non un sito.');
        }
        return [
            'url' => $canonical,
            'url_hash' => hash('sha256', $canonical),
            'host' => $host,
            'domain' => $registrable['domain'],
            'psl_known' => $registrable['known'],
        ];
    }

    /** Lists + DNS stage: run after ALTCHA. */
    public function enforce(array $c): void
    {
        $deny = $this->app->denylist();
        if ($deny->domainBlocked($c['host']) || $deny->urlBlocked($c['url_hash'])) {
            throw self::policy('denylist', 'Destinazione bloccata dalla policy di sicurezza.');
        }
        if ($this->app->feed()->domainListed($c['host'])) {
            throw self::policy('threat_feed', 'Destinazione segnalata come phishing o malware.');
        }
        $resolved = [];
        $reason = $this->app->dns()->check($c['host'], $resolved);
        if ($reason !== null) {
            throw self::policy($reason, $reason === 'dns_unresolved'
                ? 'Il dominio non risolve: controlla il link.'
                : 'Il dominio punta a una rete privata o riservata.');
        }
        if ($deny->ipsBlocked($resolved)) {
            throw self::policy('denylist_ip', 'Destinazione bloccata dalla policy di sicurezza.');
        }
    }

    /** Hard-block check repeated at every interstitial and outbound step. */
    public function stillAllowed(array $record): bool
    {
        $deny = $this->app->denylist();
        return !$deny->codeBlocked((string) $record['code'])
            && !$deny->domainBlocked((string) $record['host'])
            && !$deny->urlBlocked((string) $record['url_hash'])
            && !$this->app->feed()->domainListed((string) $record['host']);
    }

    public function isRiskyPlatform(string $host): bool
    {
        return $this->listed('risky-platforms.txt', $host);
    }

    private function riskyPath(string $path): bool
    {
        $exts = $this->list('risky-extensions.txt');
        // Decode once (catches %2e), drop ;params, look at every segment's extension.
        $decoded = strtolower(rawurldecode($path));
        foreach (explode('/', $decoded) as $segment) {
            $segment = rtrim(explode(';', $segment)[0], '. ');
            $dot = strrpos($segment, '.');
            if ($dot !== false && isset($exts[substr($segment, $dot + 1)])) {
                return true;
            }
        }
        return false;
    }

    private function listed(string $file, string $host): bool
    {
        $set = $this->list($file);
        foreach (Denylist::parents($host) as $candidate) {
            if (isset($set[$candidate])) {
                return true;
            }
        }
        return false;
    }

    private function list(string $file): array
    {
        if (!isset($this->lists[$file])) {
            $lines = @file($this->app->securityDir() . '/' . $file, FILE_IGNORE_NEW_LINES);
            if ($lines === false) {
                throw new \Shorty\Storage\StorageError('Policy list missing: ' . $file);
            }
            $set = [];
            foreach ($lines as $line) {
                $line = strtolower(trim(preg_replace('/#.*/', '', $line)));
                if ($line !== '') {
                    $set[ltrim($line, '.')] = true;
                }
            }
            $this->lists[$file] = $set;
        }
        return $this->lists[$file];
    }

    private static function invalid(string $reason): ApiError
    {
        return new ApiError(400, 'INVALID_URL', 'URL non valido.', $reason);
    }

    private static function policy(string $reason, string $message): ApiError
    {
        return new ApiError(403, 'SECURITY_POLICY', $message, $reason);
    }
}
