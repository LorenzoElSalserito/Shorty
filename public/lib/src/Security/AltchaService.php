<?php

declare(strict_types=1);

namespace Shorty\Security;

use AltchaOrg\Altcha\Algorithm\Pbkdf2;
use AltchaOrg\Altcha\Altcha;
use AltchaOrg\Altcha\CreateChallengeOptions;
use AltchaOrg\Altcha\VerifySolutionOptions;
use Shorty\App;
use Shorty\Http\ApiError;
use Shorty\Storage\GuardedFile;

/**
 * Self-hosted ALTCHA (open-source core, PBKDF2/SHA-256, deterministic counter mode).
 * The server derives one key when issuing a challenge and verifies with a single HMAC
 * (keySignature fast path): the client pays the proof-of-work, the server does not.
 *
 * Every challenge is signed, expires, is bound to an action and to the session, and is
 * accepted once (replay registry in runtime/challenges/).
 */
final class AltchaService
{
    public function __construct(private readonly App $app)
    {
    }

    private function altcha(): Altcha
    {
        $s = $this->app->secrets();
        return new Altcha(bin2hex($s->key('altcha-signature')), bin2hex($s->key('altcha-key-signature')));
    }

    public function create(string $action, string $binding, string $level): array
    {
        $cfg = $this->app->config['altcha'];
        [$min, $max] = $cfg['levels'][$level] ?? $cfg['levels']['high'];
        $challenge = $this->altcha()->createChallenge(new CreateChallengeOptions(
            algorithm: new Pbkdf2(),
            cost: (int) $cfg['cost'],
            counter: random_int((int) $min, (int) $max),
            expiresAt: $this->app->now() + (int) $cfg['ttl'],
            data: ['a' => $action, 'b' => $binding],
        ));
        return [
            'parameters' => $challenge->parameters->toArray(),
            'signature' => $challenge->signature,
        ];
    }

    /** Verifies and consumes a widget payload. Throws ApiError on any failure. */
    public function verify(mixed $payload, string $action, string $binding): void
    {
        if (!is_string($payload) || $payload === '' || strlen($payload) > 4096) {
            throw new ApiError(403, 'ALTCHA_REQUIRED', 'Completa la verifica anti-bot.');
        }
        $decoded = json_decode((string) base64_decode($payload, true), true);
        $params = $decoded['challenge']['parameters'] ?? null;
        if (!is_array($params) || ($params['algorithm'] ?? null) !== $this->app->config['altcha']['algorithm']
            || (int) ($params['cost'] ?? 0) !== (int) $this->app->config['altcha']['cost']) {
            throw new ApiError(403, 'ALTCHA_INVALID', 'Verifica anti-bot non valida.');
        }
        if (empty($params['expiresAt']) || empty($params['keySignature'])) {
            throw new ApiError(403, 'ALTCHA_INVALID', 'Verifica anti-bot non valida.');
        }
        try {
            $result = $this->altcha()->verifySolution(new VerifySolutionOptions(algorithm: new Pbkdf2(), payload: $payload));
        } catch (\Throwable) {
            throw new ApiError(403, 'ALTCHA_INVALID', 'Verifica anti-bot non valida.');
        }
        if ($result->expired || (float) $params['expiresAt'] < $this->app->now()) {
            throw new ApiError(403, 'ALTCHA_EXPIRED', 'Verifica anti-bot scaduta: ripetila.');
        }
        if (!$result->verified) {
            throw new ApiError(403, 'ALTCHA_INVALID', 'Verifica anti-bot non valida.');
        }
        $data = $params['data'] ?? [];
        if (($data['a'] ?? null) !== $action || !hash_equals($binding, (string) ($data['b'] ?? ''))) {
            throw new ApiError(403, 'ALTCHA_INVALID', 'Verifica anti-bot non valida per questa azione.');
        }
        $this->consume((string) $params['nonce'], (int) ceil((float) $params['expiresAt']));
    }

    private function consume(string $nonce, int $expiresAt): void
    {
        if (!preg_match('/^[a-f0-9]{16,128}$/', $nonce)) {
            throw new ApiError(403, 'ALTCHA_INVALID', 'Verifica anti-bot non valida.');
        }
        $path = GuardedFile::sharded($this->app->runtimeDir() . '/challenges', hash('sha256', $nonce));
        $this->app->locks()->with([$path], function () use ($path, $expiresAt) {
            if (file_exists($path)) {
                throw new ApiError(409, 'CHALLENGE_REPLAY', 'Verifica anti-bot già utilizzata: ripetila.');
            }
            GuardedFile::write($path, ['purge_after' => $expiresAt + 60]);
            $this->app->retention()->schedule($path, $expiresAt + 60);
        });
    }
}
