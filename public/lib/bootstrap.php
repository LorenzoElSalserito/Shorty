<?php
// Shorty bootstrap: runtime checks, autoload, application container.
// Included by every entry point; never produces output on its own.

declare(strict_types=1);

if (PHP_VERSION_ID < 80300) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    exit('Shorty requires PHP 8.3 or newer.');
}

spl_autoload_register(static function (string $class): void {
    if (str_starts_with($class, 'Shorty\\')) {
        $file = __DIR__ . '/src/' . str_replace('\\', '/', substr($class, 7)) . '.php';
        if (is_file($file)) {
            require $file;
        }
    }
});

$vendorAutoload = __DIR__ . '/vendor/autoload.php';
if (!is_file($vendorAutoload)) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    exit('Shorty package incomplete: lib/vendor is missing. Use the release build.');
}
require $vendorAutoload;

return Shorty\App::fromConfig(require __DIR__ . '/config/security.php');
