<?php

declare(strict_types=1);

namespace Shorty\Storage;

/**
 * Runtime records: `.php` files whose first line exits, followed by JSON.
 * A direct HTTP request executes the guard and returns nothing, even without .htaccess.
 *
 * Writers must hold the LockManager stripe for the path: writes use a unique temp file
 * in the same directory + rename, so readers never observe a partial record.
 */
final class GuardedFile
{
    public const GUARD = "<?php http_response_code(404); exit; ?>\n";

    /** @return array|null null when the file does not exist */
    public static function read(string $path): ?array
    {
        $raw = @file_get_contents($path);
        if ($raw === false) {
            if (!file_exists($path)) {
                return null;
            }
            throw new StorageError('Unreadable record.');
        }
        if (!str_starts_with($raw, self::GUARD)) {
            throw new StorageError('Record without guard.');
        }
        $data = json_decode(substr($raw, strlen(self::GUARD)), true);
        if (!is_array($data)) {
            throw new StorageError('Corrupted record.');
        }
        return $data;
    }

    public static function write(string $path, array $data): void
    {
        $dir = dirname($path);
        self::ensureDir($dir);
        $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            throw new StorageError('Unencodable record.');
        }
        $tmp = $dir . '/.tmp-' . bin2hex(random_bytes(8)) . '.php';
        $fh = @fopen($tmp, 'xb');
        if ($fh === false) {
            throw new StorageError('Cannot create temp file.');
        }
        $payload = self::GUARD . $json;
        $ok = fwrite($fh, $payload) === strlen($payload) && fflush($fh);
        fclose($fh);
        if (!$ok) {
            @unlink($tmp);
            throw new StorageError('Short write.');
        }
        @chmod($tmp, 0640);
        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            throw new StorageError('Atomic rename failed.');
        }
    }

    public static function delete(string $path): void
    {
        if (file_exists($path) && !@unlink($path) && file_exists($path)) {
            throw new StorageError('Cannot delete record.');
        }
    }

    public static function ensureDir(string $dir): void
    {
        if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) {
            throw new StorageError('Cannot create runtime directory.');
        }
    }

    /** Two-level shard path: <base>/<ab>/<id>.php (ids are hex or base62). */
    public static function sharded(string $base, string $id): string
    {
        return $base . '/' . substr($id, 0, 2) . '/' . $id . '.php';
    }
}
