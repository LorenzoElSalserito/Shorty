<?php

declare(strict_types=1);

namespace Shorty;

use Shorty\Http\ApiError;
use Shorty\Security\AbuseService;
use Shorty\Security\AltchaService;
use Shorty\Security\ClientIdentity;
use Shorty\Security\Denylist;
use Shorty\Security\DnsPolicy;
use Shorty\Security\Lockdown;
use Shorty\Security\OutboundToken;
use Shorty\Security\RegistrableDomain;
use Shorty\Security\SecretStore;
use Shorty\Security\ThreatFeed;
use Shorty\Security\TrustEngine;
use Shorty\Security\UrlPolicy;
use Shorty\Storage\LegacyPurge;
use Shorty\Storage\LinkStore;
use Shorty\Storage\LockManager;
use Shorty\Storage\Metrics;
use Shorty\Storage\RetentionQueue;

/**
 * Application container: configuration, environment facts and lazily built services.
 */
final class App
{
    public const VERSION = '2.0.0';

    private array $services = [];
    private ?int $timeOffset = null;

    private function __construct(
        public readonly array $config,
        public readonly bool $devMode,
        public readonly bool $testHooks,
        public readonly string $libDir,
    ) {
    }

    public static function fromConfig(array $config): self
    {
        // Development/test overrides exist only under PHP's built-in server with an explicit
        // environment flag: no production SAPI (FPM, mod_php, CGI) can ever enable them.
        $dev = PHP_SAPI === 'cli-server' && getenv('SHORTY_DEV') === '1';
        if ($dev) {
            $runtime = getenv('SHORTY_RUNTIME_DIR');
            if (is_string($runtime) && $runtime !== '') {
                $config['runtime_dir'] = $runtime;
            }
            $override = getenv('SHORTY_TEST_CONFIG');
            if (is_string($override) && $override !== '' && is_file($override)) {
                $extra = json_decode((string) file_get_contents($override), true);
                if (is_array($extra)) {
                    $config = array_replace_recursive($config, $extra);
                }
            }
        }
        return new self($config, $dev, $dev && getenv('SHORTY_TEST_HOOKS') === '1', dirname(__DIR__));
    }

    /** Builds an App for CLI tests with an explicit runtime directory. */
    public static function forTests(array $config, string $runtimeDir): self
    {
        $config['runtime_dir'] = $runtimeDir;
        return new self($config, true, true, dirname(__DIR__));
    }

    public function now(): int
    {
        if ($this->timeOffset === null) {
            $this->timeOffset = 0;
            if ($this->testHooks && PHP_SAPI === 'cli-server') {
                $this->timeOffset = (int) ($_SERVER['HTTP_X_SHORTY_TEST_TIME_OFFSET'] ?? 0);
            }
        }
        return time() + $this->timeOffset;
    }

    /** Test helper: shift the clock (CLI tests only). */
    public function setTimeOffset(int $seconds): void
    {
        if (!$this->testHooks) {
            throw new \LogicException('Clock override is test-only.');
        }
        $this->timeOffset = $seconds;
    }

    public function runtimeDir(): string
    {
        return rtrim((string) $this->config['runtime_dir'], '/');
    }

    public function securityDir(): string
    {
        return $this->libDir . '/security';
    }

    /**
     * Client address used for every quota. Only REMOTE_ADDR, unless the direct peer is an
     * explicitly configured trusted proxy.
     */
    public function remoteAddr(): string
    {
        $addr = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        if ($this->testHooks && PHP_SAPI === 'cli-server' && isset($_SERVER['HTTP_X_SHORTY_TEST_IP'])) {
            $addr = (string) $_SERVER['HTTP_X_SHORTY_TEST_IP'];
        }
        $proxies = $this->config['trusted_proxies'] ?? [];
        if ($proxies && in_array($addr, $proxies, true) && isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $hops = array_map('trim', explode(',', (string) $_SERVER['HTTP_X_FORWARDED_FOR']));
            // Walk from the nearest hop, skipping our own proxies.
            for ($i = count($hops) - 1; $i >= 0; $i--) {
                if (!in_array($hops[$i], $proxies, true)) {
                    $addr = $hops[$i];
                    break;
                }
            }
        }
        if (filter_var($addr, FILTER_VALIDATE_IP) === false) {
            throw new ApiError(400, 'BAD_REQUEST', 'Indirizzo client non valido.');
        }
        return $addr;
    }

    public function isHttps(): bool
    {
        if (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off') {
            return true;
        }
        $proxies = $this->config['trusted_proxies'] ?? [];
        if ($proxies && in_array($_SERVER['REMOTE_ADDR'] ?? '', $proxies, true)) {
            return strtolower((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
        }
        return false;
    }

    /** Plain HTTP is accepted only by the dev server; production requires HTTPS. */
    public function transportAllowed(): bool
    {
        return $this->isHttps() || $this->devMode;
    }

    /**
     * Validated Host header (lowercase host[:port]). Used only for same-origin comparison,
     * never to build URLs.
     */
    public function host(): string
    {
        $host = strtolower((string) ($_SERVER['HTTP_HOST'] ?? ''));
        if (!preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?::\d{1,5})?$/', $host)
            && !preg_match('/^\[[0-9a-f:.]+\](?::\d{1,5})?$/', $host)) {
            throw new ApiError(400, 'BAD_REQUEST', 'Host non valido.');
        }
        $allowed = $this->config['allowed_hosts'] ?? [];
        if ($allowed && !in_array(preg_replace('/:\d+$/', '', $host), $allowed, true)) {
            throw new ApiError(400, 'BAD_REQUEST', 'Host non valido.');
        }
        return $host;
    }

    public function origin(): string
    {
        return ($this->isHttps() ? 'https' : 'http') . '://' . $this->host();
    }

    /** Hostnames that identify this instance (for the self-link check). */
    public function selfHosts(): array
    {
        $hosts = $this->config['allowed_hosts'] ?? [];
        foreach ([$_SERVER['HTTP_HOST'] ?? '', $_SERVER['SERVER_NAME'] ?? ''] as $h) {
            $h = strtolower(preg_replace('/:\d+$/', '', (string) $h));
            if ($h !== '') {
                $hosts[] = $h;
            }
        }
        return array_values(array_unique($hosts));
    }

    /**
     * URL path of the install root, derived from the executing script (server-controlled),
     * e.g. "/" or "/shorty/".
     */
    public function basePath(): string
    {
        $script = str_replace('\\', '/', (string) ($_SERVER['SCRIPT_NAME'] ?? '/index.php'));
        $dir = dirname($script);
        if (str_ends_with($dir, '/internal')) {
            $dir = dirname($dir);
        }
        $dir = rtrim($dir, '/');
        return $dir . '/';
    }

    private function service(string $name, callable $factory): object
    {
        return $this->services[$name] ??= $factory();
    }

    public function locks(): LockManager
    {
        return $this->service('locks', fn () => new LockManager($this->runtimeDir() . '/locks'));
    }

    public function secrets(): SecretStore
    {
        return $this->service('secrets', fn () => new SecretStore($this->runtimeDir(), $this->locks()));
    }

    public function identity(): ClientIdentity
    {
        return $this->service('identity', fn () => new ClientIdentity($this->secrets()->key('identity'), $this->remoteAddr()));
    }

    public function retention(): RetentionQueue
    {
        return $this->service('retention', fn () => new RetentionQueue($this, $this->runtimeDir() . '/retention'));
    }

    public function metrics(): Metrics
    {
        return $this->service('metrics', fn () => new Metrics($this));
    }

    public function links(): LinkStore
    {
        return $this->service('links', fn () => new LinkStore($this));
    }

    public function lockdown(): Lockdown
    {
        return $this->service('lockdown', fn () => new Lockdown($this->runtimeDir()));
    }

    public function altcha(): AltchaService
    {
        return $this->service('altcha', fn () => new AltchaService($this));
    }

    public function domains(): RegistrableDomain
    {
        return $this->service('domains', fn () => new RegistrableDomain($this->securityDir() . '/psl/rules.php'));
    }

    public function denylist(): Denylist
    {
        return $this->service('denylist', fn () => new Denylist($this->securityDir() . '/local'));
    }

    public function feed(): ThreatFeed
    {
        return $this->service('feed', fn () => new ThreatFeed($this->securityDir() . '/feeds'));
    }

    public function dns(): DnsPolicy
    {
        return $this->service('dns', function () {
            $stub = $this->devMode ? getenv('SHORTY_DNS_STUB') : false;
            return is_string($stub) && $stub !== '' ? DnsPolicy::fromStubFile($stub) : new DnsPolicy();
        });
    }

    public function urlPolicy(): UrlPolicy
    {
        return $this->service('urlPolicy', fn () => new UrlPolicy($this));
    }

    public function trust(): TrustEngine
    {
        return $this->service('trust', fn () => new TrustEngine($this));
    }

    public function abuse(): AbuseService
    {
        return $this->service('abuse', fn () => new AbuseService($this));
    }

    public function outbound(): OutboundToken
    {
        return $this->service('outbound', fn () => new OutboundToken($this->secrets()->key('outbound'), $this));
    }

    /**
     * Budgeted cleanup piggybacking on normal traffic: one stat() per request, a pass every
     * gc_interval seconds. Never scans the whole runtime tree.
     */
    public function maybeCollectGarbage(): void
    {
        try {
            $stamp = $this->runtimeDir() . '/gc-stamp';
            $interval = (int) ($this->config['gc_interval'] ?? 300);
            $last = @filemtime($stamp);
            if ($last !== false && $this->now() - $last < $interval && $last <= $this->now()) {
                return;
            }
            if (!is_dir($this->runtimeDir())) {
                return;
            }
            @touch($stamp, $this->now());
            $budget = (int) ($this->config['gc_budget'] ?? 200);
            (new LegacyPurge($this, dirname($this->libDir)))->run($budget);
            $this->retention()->collect($budget);
        } catch (\Throwable) {
            // GC is best effort; security decisions never depend on it.
        }
    }
}
