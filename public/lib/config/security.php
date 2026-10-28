<?php
// Shorty security configuration.
// The package works without editing this file. Every value is a conservative default:
// raise limits only after a security review (see OPS_MANUAL.md).

return [
    // Runtime directory (must be writable by PHP). Prefer a path outside the document root
    // when the hosting allows it; the default lives inside the install and is protected by
    // PHP guard files + .htaccess.
    'runtime_dir' => dirname(__DIR__, 2) . '/runtime',

    // Hostnames this instance answers on (lowercase, no port). Empty = accept any Host,
    // which is safe because Shorty never builds absolute URLs from the Host header.
    'allowed_hosts' => [],

    // Proxy support is OFF: only REMOTE_ADDR is trusted. List proxy IPs here only if Shorty
    // really sits behind your own reverse proxy; X-Forwarded-For is then read from them only.
    'trusted_proxies' => [],

    // TTL enum accepted by the create endpoint (key => seconds). Nothing else is accepted.
    'allowed_ttls' => [
        '5h' => 5 * 3600,
        '1d' => 24 * 3600,
        '7d' => 7 * 24 * 3600,
    ],
    'default_ttl' => '5h',

    // Success quotas (rolling windows, seconds).
    'quota' => [
        'actor_links' => [3, 86400],            // max 3 links / IP / 24h
        'subnet_links' => [12, 86400],          // max 12 links / (/24 or /64) / 24h
        'domain_unknown_links' => [6, 86400],   // max 6 new links / unknown domain / 24h (global)
        'domain_trusted_links' => [30, 86400],  // finite cap for TRUSTED_LOCAL domains
        'global_links' => [100, 86400],         // circuit breaker for the whole instance
    ],

    // Attempt / flood limits (counted before the expensive checks).
    'limits' => [
        'actor_attempts_short' => [10, 600],
        'actor_attempts_long' => [30, 86400],
        'subnet_attempts' => [60, 3600],
        'actor_challenges' => [30, 600],
        'reporter_reports' => [5, 86400],
        'reporter_subnet_reports' => [20, 86400],
    ],

    // ALTCHA proof-of-work (PBKDF2/SHA-256, deterministic counter mode).
    // The client iterates on average counter/2 key derivations of `cost` iterations.
    // Values calibrated with tools/altcha-bench (see OPS_MANUAL.md, "Calibrazione ALTCHA").
    'altcha' => [
        'algorithm' => 'PBKDF2/SHA-256',
        'cost' => 1000,
        'ttl' => 600,
        'levels' => [
            'base' => [300, 600],      // desktop ~0.4 s (1 worker), low-end phone ~2.5 s
            'medium' => [1000, 1800],  // desktop ~1.4 s
            'high' => [2500, 4000],    // desktop ~3.2 s
            'report' => [60, 120],
        ],
        // Failed attempts in the short window that raise the difficulty.
        'medium_after_attempts' => 4,
        'high_after_subnet_attempts' => 30,
    ],

    // URL policy.
    'url' => [
        'max_length' => 2048,
        'max_path_length' => 1024,
        'max_query_length' => 1024,
    ],

    // Interstitial: seconds before "Continua" works for non-trusted destinations
    // (enforced server-side too) and lifetime of the signed outbound token.
    'interstitial_delay' => 3,
    'outbound_token_ttl' => 300,

    // Trust engine.
    'trust' => [
        'min_age' => 7 * 86400,
        'min_distinct_subnets' => 3,
        'retention' => 90 * 86400,
    ],

    // Abuse reports.
    'abuse' => [
        'quarantine_subnets_with_signal' => 2,
        'quarantine_subnets' => 3,
        'retention' => 30 * 86400,
    ],

    // Session (security-only cookie) idle timeout.
    'session_idle' => 1800,

    // Max request body for internal endpoints (bytes).
    'max_body' => 16384,

    // Retention bookkeeping.
    'retention' => [
        'rate' => 30 * 3600,
        'link_actor_extra' => 86400,
        'metrics' => 90 * 86400,
    ],

    // Garbage collection (no cron needed): any request runs a budgeted pass when the
    // previous pass is older than gc_interval seconds.
    'gc_interval' => 300,
    'gc_budget' => 200,
];
