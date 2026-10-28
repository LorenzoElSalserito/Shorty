<?php
// Production-mode checks for tests/certify/apache.sh (real DNS, HTTPS, no test hooks).

declare(strict_types=1);

[$_, $work, $port, $httpPort, $pkg] = $argv;
require __DIR__ . '/../lib/TestKit.php';
require __DIR__ . '/../lib/Client.php';
require $pkg . '/lib/vendor/autoload.php';

$installs = [
    'domain root' => ['https://shorty.test:' . $port . '/', "{$work}/root", true],
    'subdomain' => ['https://s.example.test:' . $port . '/', "{$work}/sub", true],
    'subfolder' => ['https://www.example.test:' . $port . '/shorty/', "{$work}/site/shorty", true],
    'no .htaccess (nginx-like)' => ['https://plain.test:' . $port . '/', "{$work}/plain", false],
];
$resolve = array_map(fn ($h) => "{$h}:{$port}:127.0.0.1", ['shorty.test', 's.example.test', 'www.example.test', 'plain.test']);
$resolve[] = "shorty.test:{$httpPort}:127.0.0.1";

$record = static function (string $path): ?array {
    $raw = @file_get_contents($path);
    return $raw === false ? null : json_decode(substr($raw, strpos($raw, "\n") + 1), true);
};
$rewrite = static function (string $path, callable $fn) use ($record): void {
    $raw = file_get_contents($path);
    $guard = substr($raw, 0, strpos($raw, "\n") + 1);
    file_put_contents($path, $guard . json_encode($fn($record($path)), JSON_UNESCAPED_SLASHES));
};

foreach ($installs as $name => [$base, $dir, $htaccess]) {
    T::group("Apache · {$name} · {$base}");
    $c = new Client($base, $resolve);

    // Landing and static assets, all relative to the install folder.
    $r = $c->request('GET', '');
    T::eq(200, $r['status'], 'landing 200 (no configuration after copy)');
    T::ok(str_contains($r['body'], '<div id="app">'), 'app shell served by index.php');
    T::ok(str_contains($r['headers']['strict-transport-security'] ?? '', 'max-age'), 'HSTS on HTTPS');
    T::ok(str_contains($r['headers']['content-security-policy'] ?? '', "default-src 'self'"), 'CSP');
    preg_match_all('#(?:src|href)="(\./assets/[^"]+)"#', $r['body'], $m);
    $assetsOk = $m[1] !== [];
    foreach ($m[1] as $asset) {
        $assetsOk = $assetsOk && $c->request('GET', substr($asset, 2))['status'] === 200;
    }
    T::ok($assetsOk, 'bundled JS/CSS load from the install folder (' . count($m[1]) . ' assets)');
    T::eq(200, $c->request('GET', 'static/logo-128.png')['status'], 'logo');
    T::eq(200, $c->request('GET', 'static/shorty.css')['status'], 'interstitial stylesheet');
    T::eq(200, $c->request('GET', 'LICENSE')['status'], 'LICENSE');

    $b = $c->bootstrap();
    T::eq(200, $b['status'], 'bootstrap');
    T::ok(preg_match('/__Host-shorty=.*;\s*secure.*;\s*httponly.*samesite=strict/i', $b['headers']['set-cookie'] ?? '') === 1, 'session cookie __Host-, Secure, HttpOnly, SameSite=Strict');
    T::ok(is_file("{$dir}/runtime/secrets.php"), 'runtime + secret auto-created inside the install');

    // Create → interstitial → continue, with the real resolver.
    $r = $c->create('https://example.com/certify/' . rawurlencode($name), '5h');
    T::eq(200, $r['status'], 'link created (real ALTCHA + real DNS)' . ($r['status'] !== 200 ? ' ' . $r['body'] : ''));
    $code = $r['json']['code'] ?? 'XXXXXXXXXX';
    $short = $base . ($r['json']['short_path'] ?? '');
    T::ok(str_starts_with($short, $base . '?s='), "short URL stays inside the install: {$short}");
    $i = $c->request('GET', $short);
    T::eq(200, $i['status'], 'interstitial');
    T::ok(!isset($i['headers']['location']), 'no redirect on GET');
    T::ok(str_contains($i['body'], 'static/shorty.css') && str_contains($i['body'], 'go.php'), 'interstitial assets/form point inside the install');
    preg_match('#href="([^"]+)static/shorty\.css"#', $i['body'], $cssBase);
    $p = parse_url($base, PHP_URL_PATH);
    T::eq($p, $cssBase[1] ?? null, 'interstitial base path = install path');
    $pretty = $c->request('GET', 's/' . $code);
    if ($htaccess) {
        T::eq(200, $pretty['status'], 'optional pretty URL /s/CODE (.htaccess)');
    } else {
        T::ok(in_array($pretty['status'], [200, 404], true), 'pretty URL not required without rewrite (got ' . $pretty['status'] . ')');
    }
    sleep(3);
    $f = Client::form($i['body']);
    $g = $c->go($f['code'], $f['token']);
    T::eq(303, $g['status'], 'continue -> 303');
    T::eq('https://example.com/certify/' . rawurlencode($name), $g['headers']['location'] ?? null, 'destination from server record');

    // Report.
    $c->bootstrap();
    $rep = $c->postJson('internal/report-submit.php', ['code' => $code, 'category' => 'phishing', 'csrf' => $c->csrf, 'altcha' => $c->solve('report')]);
    T::eq(200, $rep['status'], 'abuse report accepted');

    // Exposure checks.
    $rec = glob("{$dir}/runtime/links/*/*/*.php")[0] ?? '';
    $relRec = substr($rec, strlen($dir) + 1);
    foreach (['runtime/' . basename(dirname($rec, 3)) . '/../secrets.php', $relRec, 'runtime/secrets.php', 'lib/config/security.php', 'lib/bootstrap.php', 'lib/vendor/autoload.php', 'lib/src/App.php'] as $path) {
        $resp = $c->request('GET', $path);
        $leak = str_contains($resp['body'], '"url"') || str_contains($resp['body'], 'base64:') || str_contains($resp['body'], '<?php') || str_contains($resp['body'], 'actor_id');
        T::ok(!$leak, "no data via HTTP: {$path} (status {$resp['status']})");
        if ($htaccess && str_starts_with($path, 'runtime/')) {
            T::eq(403, $resp['status'], "{$path} denied by .htaccess");
        }
    }
    $listing = $c->request('GET', 'runtime/');
    T::ok(!str_contains($listing['body'], 'Index of'), 'no directory listing of runtime/');
    T::eq(410, $c->request('GET', 'api.php')['status'], 'api.php -> 410');
    T::eq(410, $c->request('GET', '?s=' . $code . 'x')['status'] === 404 ? 410 : 0, 'malformed code -> 404');
    T::ok(!T::dirContains("{$dir}/runtime", '127.0.0.1'), 'no raw client IP in runtime');

    // Server-side purge: let the link expire and every retention bucket fall due, then send
    // ordinary traffic (no cron, nobody opens the link). Simulated by moving stored times
    // back by 6 hours, which is what the clock would do.
    $c2 = $c->create('https://example.com/purge/' . rawurlencode($name), '5h');
    $purgeCode = $c2['json']['code'] ?? '';
    $purgeFile = "{$dir}/runtime/links/{$purgeCode[0]}/{$purgeCode[1]}/{$purgeCode}.php";
    T::ok(is_file($purgeFile), 'second link stored for the purge test');
    $shift = 6 * 3600;
    foreach (glob("{$dir}/runtime/links/*/*/*.php") as $lf) {
        $rewrite($lf, function (array $d) use ($shift) {
            foreach (['created_at', 'expires_at', 'purge_after'] as $k) {
                $d[$k] -= $shift;
            }
            return $d;
        });
    }
    foreach (glob("{$dir}/runtime/retention/*.php") as $bf) {
        $hour = DateTimeImmutable::createFromFormat('YmdH', basename($bf, '.php'), new DateTimeZone('UTC'));
        rename($bf, dirname($bf) . '/' . $hour->modify("-{$shift} seconds")->format('YmdH') . '.php');
    }
    touch("{$dir}/runtime/gc-stamp", time() - 3600);
    $c->request('GET', '');
    T::ok(!is_file($purgeFile), 'expired link purged by normal traffic (landing visit)');
    T::eq([], glob("{$dir}/runtime/links/*/*/*.php"), 'no expired link left on disk');
    T::eq(404, $c->request('GET', '?s=' . $purgeCode)['status'], 'purged link -> 404');
}

T::group('Apache · Shorty 1 → 2 upgrade by copy (domain root)');
$root = "{$work}/root";
T::ok(!is_dir("{$root}/data"), 'v1 data/ (raw IPs) purged automatically');
T::ok(!is_file("{$root}/config.php") && !is_file("{$root}/lib/Shorty.php"), 'v1 code files removed');
T::ok(!is_file("{$root}/index.html"), 'v1 standalone index.html removed');
$c = new Client('https://shorty.test:' . $port . '/', $resolve);
T::eq(410, $c->request('GET', 'AbCdEf')['status'], 'v1 short link -> 410 Gone');
T::eq(410, $c->request('GET', '?s=AbCdEf')['status'] === 404 ? 410 : 0, 'v1 code via query -> not resolvable');
T::eq(200, (new Client('https://www.example.test:' . $port . '/', $resolve))->request('GET', '')['status'], 'host site untouched by the subfolder install');

T::group('Apache · plain HTTP is refused for creation');
$h = new Client('http://shorty.test:' . $httpPort . '/', $resolve);
$r = $h->bootstrap();
T::eq('HTTPS_REQUIRED', $r['json']['error'] ?? null, 'bootstrap over HTTP -> HTTPS_REQUIRED');

T::finish();
