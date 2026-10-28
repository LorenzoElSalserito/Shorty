<?php

declare(strict_types=1);

use AltchaOrg\Altcha\Algorithm\Pbkdf2;
use AltchaOrg\Altcha\Altcha;
use AltchaOrg\Altcha\Challenge;
use AltchaOrg\Altcha\ChallengeParameters;
use AltchaOrg\Altcha\SolveChallengeOptions;

/**
 * Browser-like HTTP client for black-box tests: cookie jar, Origin header, ALTCHA solving
 * with the official library (the same proof-of-work the widget computes).
 */
final class Client
{
    public ?string $csrf = null;
    private string $jar;
    public array $headers = [];

    /**
     * @param string $base install URL ending with "/" (e.g. https://s.example.test/ or https://main.test/shorty/)
     * @param array $curlResolve CURLOPT_RESOLVE entries (host:port:ip)
     */
    public function __construct(public readonly string $base, private readonly array $curlResolve = [], ?string $testIp = null)
    {
        $this->jar = tempnam(getenv('SHORTY_TEST_TMP') ?: sys_get_temp_dir(), 'jar');
        if ($testIp !== null) {
            $this->headers[] = 'X-Shorty-Test-Ip: ' . $testIp;
        }
    }

    public function origin(): string
    {
        $p = parse_url($this->base);
        return $p['scheme'] . '://' . $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '');
    }

    /** @return array{status: int, headers: array<string,string>, body: string, json: ?array} */
    public function request(string $method, string $path, ?string $body = null, array $headers = [], bool $origin = true): array
    {
        $ch = curl_init(str_starts_with($path, 'http') ? $path : $this->base . $path);
        $h = array_merge($this->headers, $headers);
        if ($origin && $method !== 'GET') {
            $h[] = 'Origin: ' . $this->origin();
        }
        $respHeaders = [];
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_COOKIEJAR => $this->jar,
            CURLOPT_COOKIEFILE => $this->jar,
            CURLOPT_HTTPHEADER => $h,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_RESOLVE => $this->curlResolve,
            CURLOPT_TIMEOUT => 60,
            CURLOPT_HEADERFUNCTION => function ($ch, $line) use (&$respHeaders) {
                if (str_contains($line, ':')) {
                    [$k, $v] = explode(':', $line, 2);
                    $respHeaders[strtolower(trim($k))] = trim($v);
                }
                return strlen($line);
            },
        ]);
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        $out = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $json = is_string($out) ? json_decode($out, true) : null;
        if (is_array($json) && isset($json['csrf'])) {
            $this->csrf = $json['csrf'];
        }
        return ['status' => $status, 'headers' => $respHeaders, 'body' => (string) $out, 'json' => is_array($json) ? $json : null];
    }

    public function bootstrap(): array
    {
        return $this->request('GET', 'internal/bootstrap.php');
    }

    public function solve(string $action = 'create'): ?string
    {
        $r = $this->request('GET', 'internal/challenge.php?action=' . $action);
        if ($r['status'] !== 200 || !$r['json']) {
            return null;
        }
        return self::solveChallenge($r['json']);
    }

    public static function solveChallenge(array $c): string
    {
        $p = $c['parameters'];
        $params = new ChallengeParameters(
            algorithm: $p['algorithm'], nonce: $p['nonce'], salt: $p['salt'], cost: (int) $p['cost'],
            keyLength: (int) $p['keyLength'], keyPrefix: $p['keyPrefix'], keySignature: $p['keySignature'] ?? null,
            expiresAt: $p['expiresAt'] ?? null, data: $p['data'] ?? null,
        );
        $challenge = new Challenge($params, $c['signature']);
        $solution = (new Altcha())->solveChallenge(new SolveChallengeOptions(algorithm: new Pbkdf2(), challenge: $challenge, timeout: 120));
        if ($solution === null) {
            throw new RuntimeException('ALTCHA not solved');
        }
        return base64_encode(json_encode([
            'challenge' => ['parameters' => $p, 'signature' => $c['signature']],
            'solution' => ['counter' => $solution->counter, 'derivedKey' => $solution->derivedKey],
        ]));
    }

    public function postJson(string $path, array $data, array $headers = []): array
    {
        return $this->request('POST', $path, json_encode($data), array_merge(['Content-Type: application/json'], $headers));
    }

    /** Full creation: fresh challenge + current CSRF. */
    public function create(string $url, string $ttl = '5h', array $extraHeaders = []): array
    {
        if ($this->csrf === null) {
            $this->bootstrap();
        }
        $payload = $this->solve('create');
        return $this->postJson('internal/create.php', ['url' => $url, 'ttl' => $ttl, 'altcha' => $payload, 'csrf' => $this->csrf], $extraHeaders);
    }

    /** Extracts hidden form fields from the interstitial. */
    public static function form(string $html): array
    {
        preg_match('/name="code" value="([^"]+)"/', $html, $c);
        preg_match('/name="token" value="([^"]+)"/', $html, $t);
        return ['code' => $c[1] ?? '', 'token' => html_entity_decode($t[1] ?? '')];
    }

    public function go(string $code, string $token, array $extra = [], array $headers = []): array
    {
        return $this->request('POST', 'go.php', http_build_query(['code' => $code, 'token' => $token] + $extra), array_merge(['Content-Type: application/x-www-form-urlencoded'], $headers));
    }

    public function __destruct()
    {
        @unlink($this->jar);
    }
}
