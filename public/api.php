<?php
// The public JSON API was removed in Shorty 2 (abuse prevention).

declare(strict_types=1);

http_response_code(410);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Robots-Tag: noindex, nofollow, noarchive');
header('X-Content-Type-Options: nosniff');
echo '{"error":"GONE","message":"Public API removed"}';
