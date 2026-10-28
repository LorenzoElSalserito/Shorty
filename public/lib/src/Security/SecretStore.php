<?php

declare(strict_types=1);

namespace Shorty\Security;

use Shorty\Storage\GuardedFile;
use Shorty\Storage\LockManager;
use Shorty\Storage\StorageError;

/**
 * Auto-generated application secret (runtime/secrets.php). Never printed, never versioned.
 * Purpose-specific keys are derived with HKDF so no key is reused across mechanisms.
 */
final class SecretStore
{
    private ?string $master = null;

    public function __construct(private readonly string $runtimeDir, private readonly LockManager $locks)
    {
    }

    public function key(string $purpose): string
    {
        return hash_hkdf('sha256', $this->master(), 32, 'shorty:' . $purpose . ':v1');
    }

    private function master(): string
    {
        if ($this->master !== null) {
            return $this->master;
        }
        $path = $this->runtimeDir . '/secrets.php';
        $this->master = $this->locks->with([$path], function () use ($path) {
            $data = is_file($path) ? $this->load($path) : null;
            if ($data === null) {
                GuardedFile::ensureDir($this->runtimeDir);
                $this->protectDir();
                $data = ['master' => 'base64:' . base64_encode(random_bytes(32)), 'created_at' => time()];
                $php = "<?php\nreturn " . var_export($data, true) . ";\n";
                $tmp = $this->runtimeDir . '/.tmp-' . bin2hex(random_bytes(8)) . '.php';
                if (@file_put_contents($tmp, $php, LOCK_EX) !== strlen($php)) {
                    @unlink($tmp);
                    throw new StorageError('Cannot write secret.');
                }
                @chmod($tmp, 0600);
                if (!@rename($tmp, $path)) {
                    @unlink($tmp);
                    throw new StorageError('Cannot write secret.');
                }
                if (function_exists('opcache_invalidate')) {
                    @opcache_invalidate($path, true);
                }
            }
            $raw = base64_decode(substr((string) $data['master'], 7), true);
            if ($raw === false || strlen($raw) < 32) {
                throw new StorageError('Invalid secret.');
            }
            return $raw;
        });
        return $this->master;
    }

    private function load(string $path): array
    {
        $data = include $path;
        if (!is_array($data) || !isset($data['master']) || !str_starts_with((string) $data['master'], 'base64:')) {
            throw new StorageError('Corrupted secret file.');
        }
        return $data;
    }

    /** Defense in depth for the runtime directory (Apache deny + empty index). */
    private function protectDir(): void
    {
        $files = [
            '.htaccess' => "Require all denied\n<IfModule !mod_authz_core.c>\n    Deny from all\n</IfModule>\n",
            'index.php' => "<?php http_response_code(404); exit;\n",
            'index.html' => '',
        ];
        foreach ($files as $name => $content) {
            $p = $this->runtimeDir . '/' . $name;
            if (!is_file($p) && @file_put_contents($p, $content) === false) {
                throw new StorageError('Runtime directory not writable.');
            }
        }
    }
}
