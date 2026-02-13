<?php
header('Content-Type: application/json');

// Load config
$config = require_once 'config.php';
require_once 'lib/Shorty.php';

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception("Method not allowed", 405);
    }

    $input = json_decode(file_get_contents('php://input'), true);
    if (!$input) {
        throw new Exception("Invalid JSON", 400);
    }

    $url = $input['url'] ?? '';
    $ttl = isset($input['ttl_days']) ? (int)$input['ttl_days'] : $config['default_ttl'];

    $shorty = new Shorty($config);
    $result = $shorty->shorten($url, $ttl);

    echo json_encode($result);

} catch (Exception $e) {
    http_response_code($e->getCode() ?: 500);
    echo json_encode([
        'error_code' => $e->getCode(),
        'message' => $e->getMessage()
    ]);
}
