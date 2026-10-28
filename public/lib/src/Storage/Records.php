<?php

declare(strict_types=1);

namespace Shorty\Storage;

use Shorty\App;

/**
 * Locked read-modify-write helper for runtime records with retention.
 * Must be called inside LockManager::with() covering $path.
 */
final class Records
{
    public static function update(App $app, string $path, callable $mutate): array
    {
        $existing = GuardedFile::read($path);
        $data = $mutate($existing ?? []);
        if (!isset($data['purge_after'])) {
            throw new StorageError('Record without retention.');
        }
        GuardedFile::write($path, $data);
        if ($existing === null) {
            $app->retention()->schedule($path, (int) $data['purge_after']);
        }
        return $data;
    }

    /** Keeps timestamps inside the window and returns them. */
    public static function window(array $timestamps, int $now, int $window): array
    {
        return array_values(array_filter(
            array_map('intval', $timestamps),
            static fn (int $t) => $t > $now - $window && $t <= $now + 60,
        ));
    }
}
