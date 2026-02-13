<?php
// Shorty Configuration

return [
    // Base URL of the installation (e.g., 'https://s.mydomain.com' or 'https://mydomain.com/shorty')
    // Leave empty to auto-detect
    'base_url' => '',

    // Path to data directory (must be writable)
    // Relative to this file or absolute
    'data_dir' => __DIR__ . '/../data',

    // Allowed TTLs in days
    'allowed_ttls' => [7, 15, 30, 90],

    // Default TTL if not specified
    'default_ttl' => 7,

    // Max URL length
    'max_url_length' => 2048,

    // Redirect status code (302 Found or 301 Moved Permanently)
    'redirect_status' => 302,

    // Rate limiting (requests per minute per IP)
    'rate_limit' => 60,

    // Cleanup probability (0 to 1). 0.01 means 1% chance per request.
    // Set to 0 if using cron job.
    'cleanup_probability' => 0.01,
];
