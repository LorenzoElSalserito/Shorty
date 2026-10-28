<?php

declare(strict_types=1);

/** Minimal zero-dependency test kit (no PHPUnit: keeps vendor/ runtime-only). */
final class T
{
    public static int $pass = 0;
    public static array $fail = [];
    private static string $group = '';

    public static function group(string $name): void
    {
        self::$group = $name;
        fwrite(STDOUT, "\n== {$name}\n");
    }

    public static function ok(bool $cond, string $label): void
    {
        if ($cond) {
            self::$pass++;
            fwrite(STDOUT, "  ok   {$label}\n");
        } else {
            self::$fail[] = self::$group . ': ' . $label;
            fwrite(STDOUT, "  FAIL {$label}\n");
        }
    }

    public static function eq(mixed $expected, mixed $actual, string $label): void
    {
        self::ok($expected === $actual, $label . ($expected === $actual ? '' : ' (expected ' . var_export($expected, true) . ', got ' . var_export($actual, true) . ')'));
    }

    /** Asserts that $fn throws ApiError with the given code. */
    public static function throws(string $code, callable $fn, string $label): void
    {
        try {
            $fn();
            self::ok(false, "{$label} (no exception)");
        } catch (\Shorty\Http\ApiError $e) {
            self::eq($code, $e->errorCode, $label);
        } catch (\Throwable $e) {
            self::ok(false, "{$label} (" . get_class($e) . ': ' . $e->getMessage() . ')');
        }
    }

    public static function tmpdir(string $prefix): string
    {
        $base = getenv('SHORTY_TEST_TMP') ?: sys_get_temp_dir();
        $dir = $base . '/' . $prefix . '-' . bin2hex(random_bytes(4));
        mkdir($dir, 0700, true);
        return $dir;
    }

    public static function rmrf(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $f) {
            $f->isDir() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
        }
        @rmdir($dir);
    }

    /** grep -R equivalent over a directory. */
    public static function dirContains(string $dir, string $needle): bool
    {
        if (!is_dir($dir)) {
            return false;
        }
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)) as $f) {
            if ($f->isFile() && str_contains((string) file_get_contents($f->getPathname()), $needle)) {
                return true;
            }
        }
        return false;
    }

    public static function finish(): never
    {
        fwrite(STDOUT, sprintf("\n%d passed, %d failed\n", self::$pass, count(self::$fail)));
        foreach (self::$fail as $f) {
            fwrite(STDOUT, "  - {$f}\n");
        }
        exit(self::$fail ? 1 : 0);
    }
}
