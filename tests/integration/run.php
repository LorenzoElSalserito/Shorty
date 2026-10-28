<?php
// Black-box integration + abuse tests against a package directory (default: dist/).
//   php tests/integration/run.php [docroot]
// Runs PHP's built-in server in dev mode (test hooks: client IP + clock headers, DNS stub).

declare(strict_types=1);

$root = dirname(__DIR__, 2);
$docroot = realpath($argv[1] ?? $root . '/dist') ?: exit("docroot not found\n");
require __DIR__ . '/../lib/TestKit.php';
require __DIR__ . '/../lib/Client.php';
require $docroot . '/lib/vendor/autoload.php';

$tmp = T::tmpdir('shorty-int');
$dnsStub = "{$tmp}/dns.json";
file_put_contents($dnsStub, json_encode([
    'example.com' => ['93.184.216.34'],
    'www.example.com' => ['93.184.216.34'],
    'example.org' => ['93.184.216.35'],
    'example.net' => ['93.184.216.36'],
    'blocked-later.example.net' => ['93.184.216.36'],
    'rebind.example.org' => ['192.168.0.10'],
    'shorty-lock.com' => ['93.184.216.40'],
    'shorty-purge.com' => ['93.184.216.41'],
    'shorty-report.com' => ['93.184.216.42'],
]));

/** Starts php -S on a free port; returns [baseUrl, runtimeDir, process]. */
function server(string $docroot, string $tmp, string $dnsStub, array $config = [], int $workers = 8): array
{
    $runtime = "{$tmp}/runtime-" . bin2hex(random_bytes(3));
    $cfgFile = "{$tmp}/cfg-" . bin2hex(random_bytes(3)) . '.json';
    file_put_contents($cfgFile, json_encode((object) $config));
    $sock = stream_socket_server('tcp://127.0.0.1:0');
    $port = (int) substr(strrchr(stream_socket_get_name($sock, false), ':'), 1);
    fclose($sock);
    $env = array_merge(getenv(), [
        'SHORTY_DEV' => '1', 'SHORTY_TEST_HOOKS' => '1', 'SHORTY_RUNTIME_DIR' => $runtime,
        'SHORTY_DNS_STUB' => $dnsStub, 'SHORTY_TEST_CONFIG' => $cfgFile, 'PHP_CLI_SERVER_WORKERS' => (string) $workers,
    ]);
    $proc = proc_open(['php', '-S', "127.0.0.1:{$port}", '-t', $docroot], [1 => ['file', "{$tmp}/server-{$port}.log", 'a'], 2 => ['file', "{$tmp}/server-{$port}.log", 'a']], $pipes, $docroot, $env);
    for ($i = 0; $i < 100; $i++) {
        if (@fsockopen('127.0.0.1', $port)) {
            break;
        }
        usleep(50000);
    }
    return ["http://127.0.0.1:{$port}/", $runtime, $proc];
}

[$base, $runtime, $proc] = server($docroot, $tmp, $dnsStub);
$servers = [$proc];
$ipSeq = 1;
$client = function (?string $ip = null) use (&$base, &$ipSeq): Client {
    return new Client($base, [], $ip ?? '198.51.100.' . ($ipSeq++));
};

try {
    // -----------------------------------------------------------------------
    T::group('Landing + headers');
    $c = $client('203.0.113.42');
    $r = $c->request('GET', '');
    T::eq(200, $r['status'], 'landing 200');
    T::ok(str_contains($r['body'], '<div id="app">'), 'landing serves the app shell via index.php');
    T::ok(str_contains($r['headers']['content-security-policy'] ?? '', "frame-ancestors 'none'"), 'CSP present');
    T::eq('no-referrer', $r['headers']['referrer-policy'] ?? null, 'Referrer-Policy');
    T::eq('nosniff', $r['headers']['x-content-type-options'] ?? null, 'nosniff');
    T::eq(404, $c->request('GET', 'index.html')['status'], 'no standalone index.html');
    T::ok(!isset($c->request('GET', '')['headers']['access-control-allow-origin']), 'no CORS header');
    $b = $c->bootstrap();
    T::ok(isset($b['json']['csrf']) && $b['json']['ttls'] === ['5h', '1d', '7d'] && $b['json']['default_ttl'] === '5h', 'bootstrap: CSRF + TTL enum 5h/1d/7d');
    T::eq(410, $c->request('POST', 'api.php', '{"url":"https://example.com","ttl_days":7}', ['Content-Type: application/json'])['status'], 'legacy api.php -> 410 Gone');
    T::eq(410, $c->request('GET', 'AbCdEf')['status'], 'legacy 6-char link -> 410');
    T::eq(404, $c->request('GET', 'whatever/else')['status'], 'unknown path -> 404');
    $robots = $c->request('GET', 'robots.txt')['body'];
    T::ok(str_contains($robots, 'Disallow: /internal/') && str_contains($robots, 'Disallow: /?s='), 'robots.txt policy');

    // -----------------------------------------------------------------------
    T::group('Create flow + interstitial + outbound');
    $r = $c->create('https://www.example.com/page?x=1#frag', '5h');
    T::eq(200, $r['status'], 'create 200');
    $code = $r['json']['code'] ?? '';
    T::ok(preg_match('/^[A-Za-z0-9]{10}$/', $code) === 1, 'code 10 base62');
    T::eq('?s=' . $code, $r['json']['short_path'] ?? null, 'relative short_path, no Host-derived URL');
    T::ok(!isset($r['json']['short_url']), 'no absolute URL built from Host');
    $i = $c->request('GET', '?s=' . $code);
    T::eq(200, $i['status'], 'interstitial 200');
    T::ok(!isset($i['headers']['location']), 'GET short link never redirects');
    T::eq('noindex, nofollow, noarchive', $i['headers']['x-robots-tag'] ?? null, 'X-Robots-Tag on interstitial');
    T::ok(str_contains($i['headers']['content-security-policy'] ?? '', "form-action 'self' https:") && !str_contains($i['headers']['content-security-policy'] ?? '', 'unsafe-inline'), 'interstitial CSP: strict, outbound redirect allowed');
    T::ok(str_contains($i['headers']['cache-control'] ?? '', 'no-store'), 'interstitial no-store');
    T::ok(str_contains($i['body'], 'www.example.com') && str_contains($i['body'], 'non ha verificato'), 'shows host + unknown warning');
    T::ok(!preg_match('#<(img|iframe|script)[^>]+(src|href)="https?://#', $i['body']), 'no remote content embedded');
    $pretty = $c->request('GET', 's/' . $code);
    T::eq(200, $pretty['status'], 'path form /s/CODE resolves');
    $f = Client::form($i['body']);
    T::eq($code, $f['code'], 'form carries code');
    T::eq(425, $c->go($code, $f['token'])['status'], 'continue before 3s -> refused (server-side delay)');
    sleep(3);
    $g = $c->go($code, $f['token'], ['url' => 'https://evil.example.org/']);
    T::eq(303, $g['status'], 'continue after delay -> 303');
    T::eq('https://www.example.com/page?x=1', $g['headers']['location'] ?? null, 'Location from server record (extra url= ignored, fragment dropped)');
    T::eq('no-referrer', $g['headers']['referrer-policy'] ?? null, 'outbound Referrer-Policy');
    T::ok(str_contains($g['headers']['cache-control'] ?? '', 'no-store'), 'outbound no-store');
    T::eq(405, $c->request('GET', 'go.php?code=' . $code . '&token=' . urlencode($f['token']))['status'], 'GET go.php refused');
    $other = $c->create('https://example.org/other', '1d')['json']['code'] ?? '';
    T::eq(403, $c->go($other, $f['token'])['status'], 'token/code mismatch refused');
    T::eq(403, $c->go($code, $f['token'], [], ['Origin: https://evil.test'])['status'], 'cross-origin continue refused');
    T::eq(403, $c->go($code, $f['token'], [], ['Sec-Fetch-Site: cross-site'])['status'], 'cross-site continue refused');
    T::eq(403, $c->go($code, $f['token'], [], ['X-Shorty-Test-Time-Offset: 400'])['status'], 'expired outbound token refused');
    T::eq(404, $c->request('GET', '?s=ZZZZZZZZZZ')['status'], 'unknown code -> 404');
    T::eq(404, $c->request('GET', '?s=../../x')['status'], 'invalid code -> uniform 404');
    T::eq(410, $c->request('GET', '?s=' . $code, null, ['X-Shorty-Test-Time-Offset: 18001'])['status'], 'expired link -> 410');
    T::ok(!file_exists("{$runtime}/links/{$code[0]}/{$code[1]}/{$code}.php"), 'expired link deleted on access');

    // -----------------------------------------------------------------------
    T::group('Quota 3 / IP / 24h');
    $q = $client('192.0.2.50');
    $codes = [];
    foreach (['a', 'b', 'c'] as $n) {
        $codes[] = $q->create("https://example.com/q{$n}")['json']['code'] ?? null;
    }
    T::eq(3, count(array_filter($codes)), '3 links created');
    $r = $q->create('https://example.com/qd');
    T::eq(429, $r['status'], '4th link -> 429');
    T::eq('DAILY_QUOTA', $r['json']['error'] ?? null, 'error DAILY_QUOTA');
    $q->headers[] = 'X-Shorty-Test-Time-Offset: 86410';
    $r = $q->create('https://example.com/qe', '5h');
    T::eq(200, $r['status'], 'quota slides after 24h (rolling window)');
    $dup = $q->create('https://example.com/qe', '1d');
    T::ok(($dup['json']['deduplicated'] ?? false) && ($dup['json']['code'] ?? '') === ($r['json']['code'] ?? 'x'), 'same URL again -> same link (dedup, no quota)');
    $q->create('https://example.com/qf');
    $q->create('https://example.com/qg');
    T::eq('DAILY_QUOTA', $q->create('https://example.com/qh')['json']['error'] ?? null, 'new window holds 3 again');
    array_pop($q->headers);

    // -----------------------------------------------------------------------
    T::group('CSRF / session / origin / request gate');
    $x = $client();
    $x->bootstrap();
    $payload = $x->solve();
    T::eq(403, $x->postJson('internal/create.php', ['url' => 'https://example.com/', 'ttl' => '5h', 'altcha' => $payload])['status'], 'missing CSRF -> 403');
    T::eq(403, $x->postJson('internal/create.php', ['url' => 'https://example.com/', 'ttl' => '5h', 'altcha' => $payload, 'csrf' => 'wrong'])['status'], 'wrong CSRF -> 403');
    $x->bootstrap();
    $used = $x->csrf;
    $x->postJson('internal/create.php', ['url' => 'http://example.com/', 'ttl' => '5h', 'altcha' => $x->solve(), 'csrf' => $used]);
    T::eq('CSRF_INVALID', $x->postJson('internal/create.php', ['url' => 'https://example.com/', 'ttl' => '5h', 'altcha' => $x->solve(), 'csrf' => $used])['json']['error'] ?? null, 'CSRF replay -> 403');
    $nos = new Client($base, [], '198.51.100.250');
    T::eq('SESSION_REQUIRED', $nos->postJson('internal/create.php', ['url' => 'https://example.com/', 'ttl' => '5h', 'csrf' => 'x'])['json']['error'] ?? null, 'no session -> 403');
    T::eq(403, $nos->request('GET', 'internal/challenge.php?action=create')['status'], 'challenge requires a session');
    $x->bootstrap();
    T::eq(403, $x->postJson('internal/create.php', ['url' => 'https://example.com/', 'ttl' => '5h', 'csrf' => $x->csrf], ['Origin: https://evil.test'])['status'], 'foreign Origin -> 403');
    $x->bootstrap();
    $r = $x->request('POST', 'internal/create.php', json_encode(['csrf' => $x->csrf]), ['Content-Type: application/json', 'Origin: https://evil.test', 'Sec-Fetch-Site: cross-site']);
    T::eq(403, $r['status'], 'cross-site fetch -> 403');
    T::eq(405, $x->request('GET', 'internal/create.php')['status'], 'GET create -> 405');
    T::eq(405, $x->request('PUT', 'internal/create.php', '{}', ['Content-Type: application/json'])['status'], 'PUT create -> 405');
    T::eq(415, $x->request('POST', 'internal/create.php', 'url=x', ['Content-Type: application/x-www-form-urlencoded'])['status'], 'form body -> 415');
    T::eq(413, $x->request('POST', 'internal/create.php', str_repeat('a', 20000), ['Content-Type: application/json'])['status'], 'huge body -> 413');
    T::eq(400, $x->request('POST', 'internal/create.php', '{"broken', ['Content-Type: application/json'])['status'], 'malformed JSON -> 400');
    T::eq(400, $x->request('GET', 'internal/bootstrap.php', null, ['Host: evil.test/../x'])['status'], 'Host injection -> 400');
    $r = $x->request('OPTIONS', 'internal/create.php', null, ['Origin: https://evil.test', 'Access-Control-Request-Method: POST']);
    T::ok(!isset($r['headers']['access-control-allow-origin']), 'preflight not authorised');

    // -----------------------------------------------------------------------
    T::group('ALTCHA via HTTP');
    $y = $client();
    $y->bootstrap();
    T::eq('ALTCHA_REQUIRED', $y->postJson('internal/create.php', ['url' => 'https://example.com/', 'ttl' => '5h', 'csrf' => $y->csrf])['json']['error'] ?? null, 'missing ALTCHA');
    T::eq('ALTCHA_INVALID', $y->postJson('internal/create.php', ['url' => 'https://example.com/', 'ttl' => '5h', 'csrf' => $y->csrf, 'altcha' => base64_encode('{"challenge":{}}')])['json']['error'] ?? null, 'invalid ALTCHA');
    $p = $y->solve();
    T::eq(200, $y->postJson('internal/create.php', ['url' => 'https://example.com/al1', 'ttl' => '5h', 'csrf' => $y->csrf, 'altcha' => $p])['status'], 'valid ALTCHA accepted');
    T::eq('CHALLENGE_REPLAY', $y->postJson('internal/create.php', ['url' => 'https://example.com/al2', 'ttl' => '5h', 'csrf' => $y->csrf, 'altcha' => $p])['json']['error'] ?? null, 'ALTCHA replay -> 409');
    $z = $client();
    $z->bootstrap();
    T::eq('ALTCHA_INVALID', $z->postJson('internal/create.php', ['url' => 'https://example.com/al3', 'ttl' => '5h', 'csrf' => $z->csrf, 'altcha' => $y->solve()])['json']['error'] ?? null, 'ALTCHA from another session refused');
    $z->bootstrap();
    T::eq('ALTCHA_INVALID', $z->postJson('internal/create.php', ['url' => 'https://example.com/al4', 'ttl' => '5h', 'csrf' => $z->csrf, 'altcha' => $z->solve('report')])['json']['error'] ?? null, 'report challenge cannot create');

    // -----------------------------------------------------------------------
    T::group('URL policy via HTTP');
    $bad = [
        ['http://example.com/', 'SECURITY_POLICY'], ['https://127.0.0.1/', 'SECURITY_POLICY'], ['https://192.168.1.1/', 'SECURITY_POLICY'],
        ['https://[::1]/', 'SECURITY_POLICY'], ['https://u:p@example.com/', 'SECURITY_POLICY'], ['https://example.com:8443/', 'SECURITY_POLICY'],
        ['https://xn--80ak6aa92e.com/', 'SECURITY_POLICY'], ['https://bit.ly/x', 'NESTED_REDIRECTOR'], ['https://example.com/a.exe', 'SECURITY_POLICY'],
        ['https://rebind.example.org/', 'SECURITY_POLICY'], ['https://nxdomain-shorty.example.net/', 'SECURITY_POLICY'],
    ];
    foreach ($bad as [$u, $err]) {
        $w = $client();
        $r = $w->create($u);
        T::eq($err, $r['json']['error'] ?? null, "reject {$u}");
    }
    $w = $client();
    $w->bootstrap();
    T::eq('TTL_NOT_ALLOWED', $w->postJson('internal/create.php', ['url' => 'https://example.com/', 'ttl_days' => 90, 'csrf' => $w->csrf, 'altcha' => $w->solve()])['json']['error'] ?? null, 'old ttl_days=90 -> 400');
    foreach (['90', '30', '15', '7', '1'] as $t) {
        $w->bootstrap();
        T::eq(400, $w->postJson('internal/create.php', ['url' => 'https://example.com/', 'ttl' => $t, 'csrf' => $w->csrf, 'altcha' => $w->solve()])['status'], "ttl {$t} -> 400");
    }

    // -----------------------------------------------------------------------
    T::group('Denylist after creation + report/quarantine');
    $d = $client('192.0.2.77');
    $dc = $d->create('https://blocked-later.example.net/x')['json']['code'] ?? '';
    $page = $d->request('GET', '?s=' . $dc);
    T::eq(200, $page['status'], 'link opens before denylist');
    file_put_contents($docroot . '/lib/security/local/blocked-domains.txt', "# test\nexample.net\n", FILE_APPEND);
    sleep(3);
    $fd = Client::form($page['body']);
    T::eq(410, $d->go($dc, $fd['token'])['status'], 'blocked after page load -> outbound refused');
    T::eq(410, $d->request('GET', '?s=' . $dc)['status'], 'interstitial now shows disabled (410)');
    $w = $client();
    T::eq('SECURITY_POLICY', $w->create('https://example.net/new')['json']['error'] ?? null, 'denylisted domain cannot be shortened');
    file_put_contents($docroot . '/lib/security/local/blocked-domains.txt', "# One entry per line. Lines starting with # are ignored. See OPS_MANUAL.md.\n");

    $rc = $client('192.0.2.88')->create('https://shorty-report.com/report-me')['json']['code'] ?? '';
    $rep = function (string $ip, string $cat = 'phishing') use ($client, $rc) {
        $u = $client($ip);
        $u->bootstrap();
        return $u->postJson('internal/report-submit.php', ['code' => $rc, 'category' => $cat, 'csrf' => $u->csrf, 'altcha' => $u->solve('report')]);
    };
    $u = $client('10.1.1.1');
    $u->bootstrap();
    T::eq(400, $u->postJson('internal/report-submit.php', ['code' => $rc, 'category' => 'free text', 'csrf' => $u->csrf, 'altcha' => $u->solve('report')])['status'], 'free-text category refused');
    $r1 = $rep('10.1.1.2');
    T::ok(($r1['json']['ok'] ?? false) && !$r1['json']['quarantined'], '1st report: flag only');
    // the link has the new_domain risk signal, so 2 distinct subnets quarantine it
    $r2 = $rep('10.2.2.2', 'scam');
    T::ok($r2['json']['quarantined'] ?? false, '2 reports from distinct subnets + risk signal -> quarantine');
    T::eq(410, $client()->request('GET', '?s=' . $rc)['status'], 'quarantined link: no outbound');
    T::ok(!T::dirContains("{$runtime}/reports", '10.1.1.2'), 'reports store no raw IP');

    // -----------------------------------------------------------------------
    T::group('Lockdown kill switches');
    $l = $client();
    $lc = $l->create('https://shorty-lock.com/lock')['json']['code'] ?? '';
    touch("{$runtime}/LOCKDOWN");
    T::eq('SECURITY_LOCKDOWN', $client()->create('https://shorty-lock.com/lock2')['json']['error'] ?? null, 'LOCKDOWN: creation 503');
    T::eq(503, $l->request('GET', 'internal/challenge.php?action=create')['status'], 'LOCKDOWN: no create challenge');
    T::eq(200, $l->request('GET', '?s=' . $lc)['status'], 'LOCKDOWN: existing links still show interstitial');
    touch("{$runtime}/FULL_LOCKDOWN");
    T::eq(503, $l->request('GET', '?s=' . $lc)['status'], 'FULL_LOCKDOWN: links blocked');
    T::eq(503, $l->go($lc, 'x')['status'], 'FULL_LOCKDOWN: no outbound');
    unlink("{$runtime}/LOCKDOWN");
    unlink("{$runtime}/FULL_LOCKDOWN");
    T::eq(200, $l->request('GET', '?s=' . $lc)['status'], 'lockdown removed: service back');

    // -----------------------------------------------------------------------
    T::group('Storage disclosure + privacy');
    $sample = glob("{$runtime}/links/*/*/*.php")[0] ?? null;
    T::ok($sample !== null, 'a link record exists');
    $rel = substr($sample, strlen($runtime) + 1);
    // Simulate a misconfigured server exposing runtime/ under the docroot (no .htaccess at all).
    @symlink($runtime, $docroot . '/runtime');
    $direct = $c->request('GET', 'runtime/' . $rel);
    T::ok(!str_contains($direct['body'], '"url"') && !str_contains($direct['body'], 'actor_id'), 'direct HTTP request to a record: no payload (PHP guard)');
    T::ok(!str_contains($c->request('GET', 'runtime/secrets.php')['body'], 'base64:'), 'secrets.php never printed');
    T::eq('', trim($c->request('GET', 'lib/config/security.php')['body']), 'lib/config prints nothing');
    T::ok(!str_contains($c->request('GET', 'lib/security/psl/rules.php')['body'], "'com'"), 'lib PHP data prints nothing');
    @unlink($docroot . '/runtime');
    T::ok(!T::dirContains($runtime, '203.0.113.42'), 'grep runtime: no raw IP 203.0.113.42');
    T::ok(!T::dirContains($runtime, '192.0.2.50'), 'grep runtime: no raw IP 192.0.2.50');
    T::ok(!T::dirContains($runtime, 'REMOTE_ADDR') && !T::dirContains($runtime, 'User-Agent'), 'no request dumps');

    // -----------------------------------------------------------------------
    T::group('Server-side purge (GC on normal traffic)');
    $p = $client('192.0.2.99');
    $pc = $p->create('https://shorty-purge.com/purge-me')['json']['code'] ?? '';
    $file = "{$runtime}/links/{$pc[0]}/{$pc[1]}/{$pc}.php";
    T::ok(is_file($file), 'link stored');
    $p->request('GET', '', null, ['X-Shorty-Test-Time-Offset: 3600']);
    T::ok(is_file($file), 'not purged before expiry');
    // Nobody opens the link again: a visit to the landing after expiry must purge it.
    $p->request('GET', '', null, ['X-Shorty-Test-Time-Offset: ' . (5 * 3600 + 3700)]);
    T::ok(!is_file($file), 'expired link purged by GC triggered from the landing page');
    $p->request('GET', '', null, ['X-Shorty-Test-Time-Offset: ' . (60 * 3600)]);
    $p->request('GET', '', null, ['X-Shorty-Test-Time-Offset: ' . (60 * 3600 + 400)]);
    T::ok(!glob("{$runtime}/actors/*/*.php"), 'actor rate files purged after retention');
    T::ok(!glob("{$runtime}/links/*/*/*.php"), 'all expired links purged');
} finally {
    foreach ($servers as $s) {
        proc_terminate($s);
    }
}

// ---------------------------------------------------------------------------
T::group('Concurrency: 100 parallel creates, same IP');
[$base, $runtime2, $proc2] = server($docroot, $tmp, $dnsStub, [
    'limits' => ['actor_attempts_short' => [1000, 600], 'actor_attempts_long' => [1000, 86400], 'subnet_attempts' => [1000, 3600], 'actor_challenges' => [1000, 600]],
    'quota' => ['domain_unknown_links' => [1000, 86400]],
], 16);
try {
    $clients = [];
    $bodies = [];
    for ($i = 0; $i < 100; $i++) {
        $cl = new Client($base, [], '203.0.113.42');
        $cl->bootstrap();
        $bodies[$i] = json_encode(['url' => "https://example.com/race{$i}", 'ttl' => '5h', 'csrf' => $cl->csrf, 'altcha' => $cl->solve()]);
        $clients[$i] = $cl;
    }
    $mh = curl_multi_init();
    $handles = [];
    foreach ($clients as $i => $cl) {
        $ch = curl_init($base . 'internal/create.php');
        $jar = (new ReflectionProperty(Client::class, 'jar'))->getValue($cl);
        curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $bodies[$i], CURLOPT_RETURNTRANSFER => true, CURLOPT_COOKIEFILE => $jar,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'X-Shorty-Test-Ip: 203.0.113.42', 'Origin: ' . $cl->origin()]]);
        curl_multi_add_handle($mh, $ch);
        $handles[] = $ch;
    }
    $t0 = microtime(true);
    do {
        curl_multi_exec($mh, $running);
        curl_multi_select($mh);
    } while ($running);
    $codes = array_map(fn ($h) => (int) curl_getinfo($h, CURLINFO_RESPONSE_CODE), $handles);
    $stats = array_count_values($codes);
    ksort($stats);
    T::eq(3, $stats[200] ?? 0, '100 parallel creates -> exactly 3 successes (' . json_encode($stats) . sprintf(', %.1fs)', microtime(true) - $t0));
    T::eq(3, count(glob("{$runtime2}/links/*/*/*.php")), 'exactly 3 link files on disk');
    T::eq(0, $stats[500] ?? 0, 'no 500 errors');
    $actor = glob("{$runtime2}/actors/*/*.php")[0] ?? '';
    $data = json_decode(substr((string) file_get_contents($actor), strlen("<?php http_response_code(404); exit; ?>\n")), true);
    T::eq(3, count($data['success'] ?? []), 'counter file consistent (3 success timestamps)');
} finally {
    proc_terminate($proc2);
}

T::rmrf($tmp);
T::finish();
