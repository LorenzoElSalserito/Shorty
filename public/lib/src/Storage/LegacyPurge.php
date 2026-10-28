<?php

declare(strict_types=1);

namespace Shorty\Storage;

use Shorty\App;

/**
 * Shorty 1 cutover: when the v2 package is copied over an old install, the v1 link
 * records (data/**.json, with raw IPs) and the v1 code files are removed, a bounded number
 * per request, so legacy short links can never come back online.
 */
final class LegacyPurge
{
    private const V1_FILES = ['config.php', 'lib/Shorty.php', 'index.html'];

    public function __construct(private readonly App $app, private readonly string $installDir)
    {
    }

    public function run(int $budget): void
    {
        $marker = $this->app->runtimeDir() . '/legacy-purged';
        if (is_file($marker)) {
            return;
        }
        $removed = 0;
        foreach (self::V1_FILES as $f) {
            $p = $this->installDir . '/' . $f;
            if (is_file($p) && $this->isV1($f, $p)) {
                @unlink($p);
            }
        }
        $data = $this->installDir . '/data';
        if (is_dir($data)) {
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($data, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($it as $f) {
                if ($removed >= $budget) {
                    return; // continue on a later request
                }
                $path = $f->getPathname();
                if ($f->isDir()) {
                    @rmdir($path);
                } elseif (preg_match('/\.(json|txt|tmp)$/', $path)) {
                    @unlink($path);
                    $removed++;
                }
            }
            @rmdir($data);
            if (is_dir($data) && (scandir($data) ?: []) !== ['.', '..']) {
                return; // something unexpected left: retry later, never mark done
            }
        }
        @file_put_contents($marker, gmdate('c', $this->app->now()) . "\n");
    }

    private function isV1(string $name, string $path): bool
    {
        $head = (string) @file_get_contents($path, false, null, 0, 4096);
        return match ($name) {
            'config.php' => str_contains($head, "'allowed_ttls' => [7, 15, 30, 90]") || str_contains($head, "'redirect_status'"),
            'lib/Shorty.php' => str_contains($head, 'class Shorty'),
            'index.html' => str_contains($head, '<title>Shorty - URL Shortener</title>'),
        };
    }
}
