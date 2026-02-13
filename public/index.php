<?php
// Main Router

$config = require_once 'config.php';
require_once 'lib/Shorty.php';

$requestUri = $_SERVER['REQUEST_URI'];
$scriptName = $_SERVER['SCRIPT_NAME'];

// Remove script path from URI to get the code
// e.g. URI: /shorty/abc, Script: /shorty/index.php -> Code: abc
$basePath = dirname($scriptName);
$path = str_replace($basePath, '', $requestUri);
$path = trim($path, '/');

// If path is empty or 'index.php', serve the UI
if (empty($path) || $path === 'index.php' || $path === 'index.html') {
    // Serve the Vue app
    if (file_exists('index.html')) {
        readfile('index.html');
    } else {
        echo "Shorty UI not built. Run 'npm run build'.";
    }
    exit;
}

// If path starts with 'api', it's an API request (handled by web server rewrite or direct access if configured)
// But if we are here, it might be a code lookup
if (strpos($path, 'api') === 0) {
    // Let the web server handle api.php if rewrite rules are set,
    // or if we are using a simple router, we might need to include api.php here.
    // For simplicity, we assume api.php is accessed directly or via rewrite.
    // If we are here, it means no file was found, so maybe it's a code that starts with 'api'? Unlikely but possible.
}

// Try to resolve as short code
$shorty = new Shorty($config);
$url = $shorty->resolve($path);

if ($url) {
    header("Location: " . $url, true, $config['redirect_status']);
    exit;
}

// 404
http_response_code(404);
echo "Link not found or expired.";
