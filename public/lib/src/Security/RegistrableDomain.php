<?php

declare(strict_types=1);

namespace Shorty\Security;

/**
 * Public Suffix List lookup on a build-time snapshot (lib/security/psl/rules.php, compiled
 * by tools/update-psl.mjs). Pure PHP, no ext-intl: Shorty only accepts ASCII hostnames
 * and rejects punycode, so Unicode rules are irrelevant and excluded at build time.
 */
final class RegistrableDomain
{
    /** @var array<string, int>|null rule => 1 (ICANN) | 2 (private); "*.x" wildcard, "!x" exception */
    private ?array $rules = null;

    public function __construct(private readonly string $rulesFile)
    {
    }

    /**
     * @return array{domain: ?string, suffix: string, known: bool}
     *         domain null when the host is itself a public suffix
     */
    public function resolve(string $host): array
    {
        $rules = $this->rules();
        $labels = explode('.', strtolower($host));
        $n = count($labels);
        $suffixLen = 0;
        $known = false;
        for ($i = 0; $i < $n; $i++) {
            $candidate = implode('.', array_slice($labels, $i));
            if (isset($rules['!' . $candidate])) {
                $suffixLen = $n - $i - 1;
                $known = true;
                break;
            }
            $wild = $i + 1 < $n ? '*.' . implode('.', array_slice($labels, $i + 1)) : null;
            if (isset($rules[$candidate]) || ($wild !== null && isset($rules[$wild]))) {
                $suffixLen = $n - $i;
                $known = true;
                break;
            }
        }
        if ($suffixLen === 0) {
            $suffixLen = 1; // default rule "*"
        }
        $suffix = implode('.', array_slice($labels, $n - $suffixLen));
        $domain = $n > $suffixLen ? implode('.', array_slice($labels, $n - $suffixLen - 1)) : null;
        return ['domain' => $domain, 'suffix' => $suffix, 'known' => $known];
    }

    public function fromHost(string $host): ?string
    {
        return $this->resolve($host)['domain'];
    }

    public function available(): bool
    {
        try {
            return $this->rules() !== [];
        } catch (\RuntimeException) {
            return false;
        }
    }

    private function rules(): array
    {
        if ($this->rules === null) {
            $rules = is_file($this->rulesFile) ? include $this->rulesFile : null;
            if (!is_array($rules) || !$rules) {
                throw new \RuntimeException('Public Suffix List snapshot missing.');
            }
            $this->rules = $rules;
        }
        return $this->rules;
    }
}
