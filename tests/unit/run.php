<?php
// Unit tests: php tests/unit/run.php   (no network, no web server)

declare(strict_types=1);

use Shorty\App;
use Shorty\Security\ClientIdentity;
use Shorty\Security\DnsPolicy;
use Shorty\Security\IpClassifier;
use Shorty\Security\Session;
use Shorty\Security\TrustEngine;
use Shorty\Service\CreateLink;
use Shorty\Service\Quotas;
use Shorty\Service\Resolver;
use Shorty\Storage\GuardedFile;
use Shorty\Storage\LinkStore;
use Shorty\Storage\StorageError;

$root = dirname(__DIR__, 2);
$lib = getenv('SHORTY_LIB') ?: $root . '/public/lib';
require __DIR__ . '/../lib/TestKit.php';
require __DIR__ . '/../lib/Client.php';
spl_autoload_register(static function (string $c) use ($lib): void {
    if (str_starts_with($c, 'Shorty\\')) {
        require $lib . '/src/' . str_replace('\\', '/', substr($c, 7)) . '.php';
    }
});
require $lib . '/vendor/autoload.php';
$config = require $lib . '/config/security.php';

$_SERVER['REMOTE_ADDR'] = '203.0.113.42';
$_SERVER['HTTP_HOST'] = 'shorty.test';
$_SERVER['SERVER_NAME'] = 'shorty.test';

$runtime = T::tmpdir('shorty-unit');
$newApp = static function (array $override = []) use ($config, &$runtime): App {
    return App::forTests(array_replace_recursive($config, $override), $runtime);
};

// ---------------------------------------------------------------------------
T::group('ClientIdentity');
$a = new ClientIdentity(str_repeat('k', 32), '192.0.2.10');
$b = new ClientIdentity(str_repeat('k', 32), '192.0.2.10');
$c = new ClientIdentity(str_repeat('k', 32), '192.0.2.11');
$v6a = new ClientIdentity(str_repeat('k', 32), '2001:db8:1:2:aaaa::1');
$v6b = new ClientIdentity(str_repeat('k', 32), '2001:0db8:0001:0002:bbbb::2');
T::eq($a->actorId(), $b->actorId(), 'same IP -> same actor');
T::ok($a->actorId() !== $c->actorId(), 'different IP -> different actor');
T::eq($a->subnetId(), $c->subnetId(), 'same /24 -> same subnet');
T::ok($a->actorId() !== $a->reporterId(), 'actor and reporter ids differ (scope separation)');
T::ok($a->subnetId() !== $a->reporterSubnetId(), 'subnet and reporter-subnet ids differ');
T::eq($v6a->subnetId(), $v6b->subnetId(), 'IPv6 same /64 -> same subnet');
T::eq((new ClientIdentity('k', '::ffff:192.0.2.10'))->actorId(), (new ClientIdentity('k', '192.0.2.10'))->actorId(), 'IPv4-mapped IPv6 normalised');
T::ok(!str_contains($a->actorId() . $a->subnetId(), '192.0.2'), 'ids do not contain the raw IP');
T::ok((new ClientIdentity('other-key', '192.0.2.10'))->actorId() !== $a->actorId(), 'ids depend on the secret');

// ---------------------------------------------------------------------------
T::group('IpClassifier / DNS');
foreach (['127.0.0.1', '10.0.0.1', '192.168.1.1', '172.16.5.4', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1',
    '255.255.255.255', '192.0.2.1', '198.51.100.7', '203.0.113.9', '::1', '::', 'fc00::1', 'fd12::1', 'fe80::1', 'ff02::1',
    '2001:db8::1', '::ffff:127.0.0.1', '64:ff9b::a00:1', '2002:a00:1::1'] as $ip) {
    T::ok(!IpClassifier::isPublic($ip), "reject {$ip}");
}
foreach (['93.184.216.34', '1.1.1.1', '8.8.8.8', '2606:2800:220:1:248:1893:25c8:1946', '2a00:1450:4001:80b::200e'] as $ip) {
    T::ok(IpClassifier::isPublic($ip), "accept {$ip}");
}
$dns = new DnsPolicy(static fn (string $h) => ['ok.test' => ['93.184.216.34'], 'mixed.test' => ['93.184.216.34', '10.0.0.1'], 'none.test' => []][$h] ?? []);
T::eq(null, $dns->check('ok.test'), 'public-only host accepted');
T::eq('dns_non_public', $dns->check('mixed.test'), 'any private address rejects');
T::eq('dns_unresolved', $dns->check('none.test'), 'unresolved rejects');

// ---------------------------------------------------------------------------
T::group('RegistrableDomain (PSL snapshot)');
$app = $newApp();
$psl = $app->domains();
T::eq('example.com', $psl->fromHost('www.example.com'), 'www.example.com');
T::eq('example.co.uk', $psl->fromHost('a.b.example.co.uk'), 'a.b.example.co.uk');
T::eq('user.github.io', $psl->fromHost('x.user.github.io'), 'private suffix github.io');
T::eq(false, $psl->resolve('foo.unknowntld123')['known'], 'unknown TLD flagged as not known');
T::eq(null, $psl->fromHost('co.uk'), 'public suffix itself has no registrable domain');
$vectors = 0;
$vecFail = 0;
foreach (file($root . '/tests/fixtures/psl-tests.txt', FILE_IGNORE_NEW_LINES) as $line) {
    $line = trim($line);
    if ($line === '' || str_starts_with($line, '//')) {
        continue;
    }
    [$in, $out] = preg_split('/\s+/', $line);
    if ($in === 'null' || str_starts_with($in, '.') || preg_match('/[^\x20-\x7e]|xn--/i', $in . $out)) {
        continue; // Shorty rejects these hosts before the PSL is consulted
    }
    $vectors++;
    $got = $psl->fromHost(strtolower($in));
    if ($got !== ($out === 'null' ? null : $out)) {
        $vecFail++;
        fwrite(STDOUT, "    vector {$in}: expected {$out}, got " . var_export($got, true) . "\n");
    }
}
T::ok($vectors > 40 && $vecFail === 0, "official PSL test vectors ({$vectors} ASCII cases)");

// ---------------------------------------------------------------------------
T::group('UrlPolicy (table-driven, syntax stage)');
$policy = $app->urlPolicy();
$cases = [
    ['https://example.com', true],
    ['https://www.example.com/path?q=1#frag', true],
    ['HTTPS://EXAMPLE.COM:443/a', true],
    ['https://sub.example.co.uk/x/y.html', true],
    ['https://example.com/download.pdf', true],
    ['  https://example.org/  ', true],
    ['http://example.com', 'SECURITY_POLICY'],
    ['ftp://example.com', 'SECURITY_POLICY'],
    ['javascript:alert(1)', 'SECURITY_POLICY'],
    ['data:text/html,x', 'SECURITY_POLICY'],
    ['https://127.0.0.1/', 'SECURITY_POLICY'],
    ['https://192.168.1.1/', 'SECURITY_POLICY'],
    ['https://[::1]/', 'SECURITY_POLICY'],
    ['https://[fd00::1]/', 'SECURITY_POLICY'],
    ['https://2130706433/', 'SECURITY_POLICY'],
    ['https://0x7f.0.0.1/', 'SECURITY_POLICY'],
    ['https://user:pass@example.com/', 'SECURITY_POLICY'],
    ['https://user@example.com/', 'SECURITY_POLICY'],
    ['https://example.com@evil.com/', 'SECURITY_POLICY'],
    ['https://example.com:8443/', 'SECURITY_POLICY'],
    ['https://example.com:80/', 'SECURITY_POLICY'],
    ['https://xn--pple-43d.com/', 'SECURITY_POLICY'],
    ['https://sub.xn--80ak6aa92e.com/', 'SECURITY_POLICY'],
    ['https://аpple.com/', 'INVALID_URL'],
    ['https://localhost/', 'INVALID_URL'],
    ['https://printer.local/', 'SECURITY_POLICY'],
    ['https://db.internal/', 'SECURITY_POLICY'],
    ['https://router.lan/', 'SECURITY_POLICY'],
    ['https://intranet/', 'INVALID_URL'],
    ['https://shorty.test/?s=AbCdEf1234', 'SECURITY_POLICY'],
    ['https://example.com/setup.exe', 'SECURITY_POLICY'],
    ['https://example.com/a/APP.APK', 'SECURITY_POLICY'],
    ['https://example.com/x.zip?download=1', 'SECURITY_POLICY'],
    ['https://example.com/x%2Eexe', 'SECURITY_POLICY'],
    ['https://example.com/x.exe;jsessionid=1', 'SECURITY_POLICY'],
    ['https://example.com/x.tar.gz', 'SECURITY_POLICY'],
    ['https://example.com/payload.ps1', 'SECURITY_POLICY'],
    ['https://example.com/x.exe/', 'SECURITY_POLICY'],
    ['https://bit.ly/abc', 'NESTED_REDIRECTOR'],
    ['https://www.tinyurl.com/abc', 'NESTED_REDIRECTOR'],
    ['https://t.co/abc', 'NESTED_REDIRECTOR'],
    ['https://example.com/a b', 'INVALID_URL'],
    ['https://example.com/a\\b', 'INVALID_URL'],
    ["https://example.com/\x00", 'INVALID_URL'],
    ["https://example.com/a\x00b", 'INVALID_URL'],
    ['https://example.com/' . str_repeat('a', 2100), 'INVALID_URL'],
    ['https://', 'INVALID_URL'],
    ['https:///path', 'INVALID_URL'],
    ['https://-bad-.com/', 'INVALID_URL'],
    ['https://exa_mple.com/', 'INVALID_URL'],
    ['https://com/', 'INVALID_URL'],
    ['https://co.uk/', 'SECURITY_POLICY'],
    ['', 'INVALID_URL'],
];
foreach ($cases as [$in, $expect]) {
    $label = 'policy ' . substr(var_export($in, true), 0, 60);
    if ($expect === true) {
        try {
            $r = $policy->canonicalize($in);
            T::ok(str_starts_with($r['url'], 'https://') && !str_contains($r['url'], '#') && !str_contains($r['url'], ':443'), "{$label} -> {$r['url']}");
        } catch (\Throwable $e) {
            T::ok(false, "{$label} rejected: " . $e->getMessage());
        }
    } else {
        T::throws($expect, fn () => $policy->canonicalize($in), "{$label} -> {$expect}");
    }
}
T::eq('https://example.com/a', $policy->canonicalize('HTTPS://EXAMPLE.COM:443/a')['url'], 'canonical lowercase host, no :443');

// ---------------------------------------------------------------------------
T::group('Denylist + threat feed');
$secDir = T::tmpdir('shorty-sec');
foreach (['local', 'psl', 'feeds'] as $d) {
    mkdir("{$secDir}/{$d}");
}
copy($lib . '/security/psl/rules.php', "{$secDir}/psl/rules.php");
foreach (['nested-shorteners.txt', 'risky-extensions.txt', 'risky-platforms.txt'] as $f) {
    copy($lib . '/security/' . $f, "{$secDir}/{$f}");
}
file_put_contents("{$secDir}/local/blocked-domains.txt", "# test\nevil-example.com\n");
file_put_contents("{$secDir}/local/blocked-codes.txt", "AbCdEf1234\n");
file_put_contents("{$secDir}/local/blocked-ips.txt", "93.184.216.0/24\n");
$deny = new Shorty\Security\Denylist("{$secDir}/local");
T::ok($deny->domainBlocked('evil-example.com'), 'blocked domain');
T::ok($deny->domainBlocked('a.b.evil-example.com'), 'blocked subdomain');
T::ok(!$deny->domainBlocked('notevil-example.com'), 'no suffix-string false positive');
T::ok($deny->codeBlocked('AbCdEf1234'), 'blocked code');
T::ok($deny->ipsBlocked(['93.184.216.34']), 'blocked destination CIDR');
file_put_contents("{$secDir}/local/blocked-domains.txt", "not a domain!!\n");
$threw = false;
try {
    (new Shorty\Security\Denylist("{$secDir}/local"))->domainBlocked('example.com');
} catch (StorageError) {
    $threw = true;
}
T::ok($threw, 'corrupted denylist fails closed');
// Feed: compile a tiny feed with the real builder format.
mkdir("{$secDir}/feeds/domains");
$feedDomains = ['phish-sample.com', 'login.bad-bank.net'];
$shards = array_fill(0, 256, []);
foreach ($feedDomains as $d) {
    $h = substr(hash('sha256', $d, true), 0, 16);
    $shards[ord($h[0])][] = $h;
}
foreach ($shards as $i => $list) {
    sort($list, SORT_STRING);
    file_put_contents(sprintf('%s/feeds/domains/%02x.bin', $secDir, $i), implode('', $list));
}
file_put_contents("{$secDir}/feeds/METADATA.json", '{"format":"shorty-feed-v1"}');
$feed = new Shorty\Security\ThreatFeed("{$secDir}/feeds");
T::ok($feed->domainListed('phish-sample.com'), 'feed hit');
T::ok($feed->domainListed('www.phish-sample.com'), 'feed hit on subdomain');
T::ok($feed->domainListed('login.bad-bank.net'), 'feed hit exact host');
T::ok(!$feed->domainListed('bad-bank.net'), 'parent of listed host not blocked');
T::ok(!$feed->domainListed('example.com'), 'feed miss');
unlink("{$secDir}/feeds/domains/" . bin2hex(hash('sha256', 'example.com', true)[0]) . '.bin');
$threw = false;
try {
    $feed->domainListed('example.com');
} catch (StorageError) {
    $threw = true;
}
T::ok($threw, 'missing feed shard fails closed');
T::ok(!(new Shorty\Security\ThreatFeed($secDir . '/nope'))->available(), 'missing feed -> unavailable (conservative mode)');
$realFeed = $app->feed();
if ($realFeed->available()) {
    $t0 = microtime(true);
    $mem0 = memory_get_usage();
    for ($i = 0; $i < 2000; $i++) {
        $realFeed->domainListed("host{$i}.example-perf.com");
    }
    $ms = (microtime(true) - $t0) * 1000 / 2000;
    T::ok($ms < 2, sprintf('real feed lookup %.3f ms/lookup (%d domains)', $ms, $realFeed->metadata()['domains'] ?? 0));
    T::ok(memory_get_usage() - $mem0 < 1024 * 1024, 'feed lookup memory stays O(1)');
} else {
    T::ok(true, 'real feed not built (skipped perf)');
}

// ---------------------------------------------------------------------------
T::group('SecretStore');
$app = $newApp();
$k1 = $app->secrets()->key('identity');
T::ok(is_file("{$runtime}/secrets.php"), 'secrets.php created on first use');
T::ok((fileperms("{$runtime}/secrets.php") & 0777) === 0600, 'secrets.php mode 0600');
T::eq($k1, $newApp()->secrets()->key('identity'), 'secret stable across requests');
T::ok($k1 !== $app->secrets()->key('outbound'), 'purpose keys differ');
T::ok(is_file("{$runtime}/.htaccess") && is_file("{$runtime}/index.php"), 'runtime protected (.htaccess + index.php)');
$ro = T::tmpdir('shorty-ro');
chmod($ro, 0500);
$threw = false;
try {
    App::forTests($config, $ro . '/rt')->secrets()->key('x');
} catch (StorageError) {
    $threw = true;
}
T::ok($threw || posix_getuid() === 0, 'unwritable runtime fails closed');
chmod($ro, 0700);

// ---------------------------------------------------------------------------
T::group('GuardedFile / LinkStore');
$p = "{$runtime}/t/x.php";
GuardedFile::write($p, ['a' => 1]);
T::eq(['a' => 1], GuardedFile::read($p), 'round trip');
T::ok(str_starts_with(file_get_contents($p), '<?php'), 'record starts with PHP guard');
$out = shell_exec('php ' . escapeshellarg($p));
T::eq('', (string) $out, 'executing a record prints nothing');
file_put_contents($p, "garbage");
$threw = false;
try {
    GuardedFile::read($p);
} catch (StorageError) {
    $threw = true;
}
T::ok($threw, 'malformed record detected');
T::ok(preg_match(LinkStore::CODE_PATTERN, LinkStore::generateCode()) === 1, '10-char base62 code');
$codes = [];
for ($i = 0; $i < 5000; $i++) {
    $codes[LinkStore::generateCode()] = true;
}
T::eq(5000, count($codes), 'no collisions in 5000 codes');
T::eq(null, $app->links()->get('../../etc'), 'invalid code -> null');
T::eq(null, $app->links()->get('AAAAAAAAAA'), 'missing code -> null');
$code = $app->links()->freshCode();
$app->locks()->with([$app->links()->path($code)], fn () => $app->links()->insert(['v' => 2, 'code' => $code, 'url' => 'https://example.com/', 'url_hash' => 'h', 'host' => 'example.com', 'domain' => 'example.com', 'expires_at' => time() + 100, 'purge_after' => time() + 100, 'status' => 'ACTIVE']));
$threw = false;
try {
    $app->locks()->with([$app->links()->path($code)], fn () => $app->links()->insert(['code' => $code, 'purge_after' => 1]));
} catch (StorageError) {
    $threw = true;
}
T::ok($threw, 'insert on existing code refused (collision handling)');
file_put_contents($app->links()->path($code), GuardedFile::GUARD . '{"v":2,"code":"WRONGCODE0"');
T::eq(null, $app->links()->get($code), 'corrupted record -> not found');

// ---------------------------------------------------------------------------
T::group('OutboundToken');
$app = $newApp();
$tok = $app->outbound()->issue('AbCdEf1234');
T::eq(null, $app->outbound()->check($tok, 'AbCdEf1234', 0), 'valid token');
T::eq('mismatch', $app->outbound()->check($tok, 'ZZZZZZZZZZ', 0), 'code mismatch');
T::eq('too_early', $app->outbound()->check($tok, 'AbCdEf1234', 3), 'minimum delay enforced server-side');
T::eq('invalid', $app->outbound()->check($tok . 'x', 'AbCdEf1234', 0), 'tampered token');
$app->setTimeOffset(301);
T::eq('expired', $app->outbound()->check($tok, 'AbCdEf1234', 0), 'expired after 5 minutes');

// ---------------------------------------------------------------------------
T::group('ALTCHA service');
$app = $newApp();
$binding = str_repeat('a', 32);
$ch = $app->altcha()->create('create', $binding, 'base');
T::ok(isset($ch['parameters']['keySignature'], $ch['parameters']['expiresAt']), 'challenge signed with keySignature + expiry');
T::ok($ch['parameters']['expiresAt'] - time() <= 1200, 'expiry <= 20 minutes');
$payload = Client::solveChallenge($ch);
$t0 = microtime(true);
$app->altcha()->verify($payload, 'create', $binding);
T::ok((microtime(true) - $t0) < 0.05, sprintf('verification is cheap (%.1f ms)', (microtime(true) - $t0) * 1000));
T::throws('CHALLENGE_REPLAY', fn () => $app->altcha()->verify($payload, 'create', $binding), 'replay rejected');
$p2 = Client::solveChallenge($app->altcha()->create('report', $binding, 'report'));
T::throws('ALTCHA_INVALID', fn () => $app->altcha()->verify($p2, 'create', $binding), 'action binding enforced');
$p3 = Client::solveChallenge($app->altcha()->create('create', $binding, 'base'));
T::throws('ALTCHA_INVALID', fn () => $app->altcha()->verify($p3, 'create', str_repeat('b', 32)), 'session binding enforced');
T::throws('ALTCHA_REQUIRED', fn () => $app->altcha()->verify(null, 'create', $binding), 'missing payload');
T::throws('ALTCHA_INVALID', fn () => $app->altcha()->verify(base64_encode('{"x":1}'), 'create', $binding), 'garbage payload');
$d = json_decode(base64_decode($p3), true);
$d['solution']['derivedKey'] = str_repeat('0', 64);
T::throws('ALTCHA_INVALID', fn () => $app->altcha()->verify(base64_encode(json_encode($d)), 'create', $binding), 'wrong solution');
$d = json_decode(base64_decode($p3), true);
$d['challenge']['parameters']['data']['a'] = 'report';
T::throws('ALTCHA_INVALID', fn () => $app->altcha()->verify(base64_encode(json_encode($d)), 'create', $binding), 'tampered parameters (signature)');
$p4 = Client::solveChallenge($app->altcha()->create('create', $binding, 'base'));
$app->setTimeOffset(700);
T::throws('ALTCHA_EXPIRED', fn () => $app->altcha()->verify($p4, 'create', $binding), 'expired challenge');

// ---------------------------------------------------------------------------
T::group('Quotas: rolling window');
T::rmrf($runtime);
$runtime = T::tmpdir('shorty-unit');
$app = $newApp(['limits' => ['actor_attempts_short' => [1000, 600], 'actor_attempts_long' => [1000, 86400], 'subnet_attempts' => [1000, 3600]]]);
$q = new Quotas($app, $app->identity());
$register = function () use ($app, $q) {
    return $app->locks()->with([$q->globalPath(), $q->subnetPath(), $q->actorPath()], function () use ($q) {
        $q->assertSuccessQuota();
        $q->registerSuccess();
    });
};
$register();
$app->setTimeOffset(3600);
$register();
$app->setTimeOffset(7200);
$register();
T::throws('DAILY_QUOTA', $register, '4th success within 24h refused');
$app->setTimeOffset(86399);
T::throws('DAILY_QUOTA', $register, 'still refused just before 24h from the first');
$app->setTimeOffset(86401);
$register();
T::ok(true, 'quota slides after 24h from the first link');
T::throws('DAILY_QUOTA', $register, 'and refuses again (window holds 3)');
T::ok(!T::dirContains($runtime, '203.0.113.42'), 'no raw IP in runtime files');

T::group('Quotas: attempt limiter');
$app = $newApp();
$q = new Quotas($app, new ClientIdentity($app->secrets()->key('identity'), '198.51.100.77'));
for ($i = 0; $i < 10; $i++) {
    $q->attempt();
}
T::throws('RATE_LIMIT', fn () => $q->attempt(), '11th attempt in 10 minutes refused');

// ---------------------------------------------------------------------------
T::group('CreateLink + Resolver + trust');
T::rmrf($runtime);
$runtime = T::tmpdir('shorty-unit');
$app = $newApp();
$stub = T::tmpdir('dns') . '/dns.json';
file_put_contents($stub, json_encode(['example.com' => ['93.184.216.34'], 'www.example.com' => ['93.184.216.34'], 'private.example.org' => ['10.1.2.3'], 'example.org' => ['93.184.216.35']]));
$withDns = function (App $app) use ($stub): App {
    $r = new ReflectionProperty(App::class, 'services');
    $s = $r->getValue($app);
    $s['dns'] = DnsPolicy::fromStubFile($stub);
    $r->setValue($app, $s);
    return $app;
};
$app = $withDns($newApp());
$_SESSION = [];
$binding = str_repeat('c', 32);
$make = function (App $app, string $url, string $ttl = '5h') use ($binding) {
    $payload = Client::solveChallenge($app->altcha()->create('create', $binding, 'base'));
    return (new CreateLink($app))->handle(['url' => $url, 'ttl' => $ttl, 'altcha' => $payload], $binding);
};
$r1 = $make($app, 'https://example.com/one', '5h');
T::ok(preg_match('/^\?s=[A-Za-z0-9]{10}$/', $r1['short_path']) === 1, 'short_path is relative ?s=CODE');
$rec = $app->links()->get($r1['code']);
T::eq(5 * 3600, $rec['expires_at'] - $rec['created_at'], 'TTL 5h -> +18000s');
T::ok(!str_contains(json_encode($rec), '203.0.113.42'), 'record has no raw IP');
T::eq('UNKNOWN', $rec['trust_state'], 'new domain is UNKNOWN');
$dup = $make($app, 'https://example.com/one', '1d');
T::ok($dup['deduplicated'] && $dup['code'] === $r1['code'], 'same actor + same URL -> same link (dedup)');
T::eq(2, $dup['remaining'], 'dedup did not consume quota');
$r2 = $make($app, 'https://example.com/two', '1d');
T::eq(86400, $app->links()->get($r2['code'])['expires_at'] - $app->links()->get($r2['code'])['created_at'], 'TTL 1d');
$r3 = $make($app, 'https://example.com/three', '7d');
T::eq(604800, $app->links()->get($r3['code'])['expires_at'] - $app->links()->get($r3['code'])['created_at'], 'TTL 7d');
T::throws('DAILY_QUOTA', fn () => $make($app, 'https://example.com/four'), '4th link same IP -> 429 DAILY_QUOTA');
foreach (['90', '15', '5', '2h', '', 'ttl_days'] as $bad) {
    $_SERVER['REMOTE_ADDR'] = '198.51.100.' . random_int(2, 250);
    $fresh = $withDns($newApp());
    T::throws('TTL_NOT_ALLOWED', fn () => (new CreateLink($fresh))->handle(['url' => 'https://example.com/', 'ttl' => $bad], $binding), "TTL '{$bad}' refused");
}
$_SERVER['REMOTE_ADDR'] = '198.51.100.20';
$app2 = $withDns($newApp());
T::throws('SECURITY_POLICY', fn () => $make($app2, 'https://private.example.org/'), 'host resolving to private IP refused');

// Resolver
$res = new Resolver($app);
[$st, $recd, $state] = $res->resolve($r1['code']);
T::eq(Resolver::OK, $st, 'resolver OK for active link');
T::eq(3, $res->minDelay($state), 'unknown -> 3s interstitial delay');
T::eq(Resolver::NOT_FOUND, $res->resolve('ZZZZZZZZZZ')[0], 'unknown code');
$app->setTimeOffset(5 * 3600 + 5);
T::eq(Resolver::EXPIRED, $res->resolve($r1['code'])[0], 'expired link');
T::ok(!file_exists($app->links()->path($r1['code'])), 'expired link lazily deleted');
$app->setTimeOffset(0);

// Trust: promotion only after 7 days + 3 distinct subnets, never bypasses controls.
T::rmrf($runtime);
$runtime = T::tmpdir('shorty-unit');
$trustUrl = static fn (int $i) => "https://example.org/p{$i}";
$offset = 0;
foreach (['198.51.100.1', '192.0.2.1', '203.0.113.1'] as $i => $ip) {
    $_SERVER['REMOTE_ADDR'] = $ip;
    $a = $withDns($newApp(['feed_dir_unused' => 1]));
    $make($a, $trustUrl($i));
}
$c = ['domain' => 'example.org', 'host' => 'example.org', 'psl_known' => true];
$feedOn = $app->feed()->available();
T::eq('UNKNOWN', $a->trust()->state($c), 'three subnets but < 7 days -> UNKNOWN');
$a->setTimeOffset(7 * 86400 + 10);
T::eq($feedOn ? 'TRUSTED_LOCAL' : 'UNKNOWN', $a->trust()->state($c), '7 days + 3 subnets -> TRUSTED_LOCAL (feed present)');
if ($feedOn) {
    T::eq(0, (new Resolver($a))->minDelay('TRUSTED_LOCAL'), 'trusted -> no countdown, interstitial still shown');
    $_SERVER['REMOTE_ADDR'] = '198.51.100.1';
    $t = $withDns($newApp());
    $t->setTimeOffset(7 * 86400 + 10);
    T::throws('ALTCHA_REQUIRED', fn () => (new CreateLink($t))->handle(['url' => 'https://example.org/x', 'ttl' => '5h'], $binding), 'trusted domain still requires ALTCHA');
    $make($t, 'https://example.org/t1');
    $make($t, 'https://example.org/t2');
    $make($t, 'https://example.org/t3');
    T::throws('DAILY_QUOTA', fn () => $make($t, 'https://example.org/t4'), 'trusted domain still capped at 3/IP/24h');
}
T::eq('UNKNOWN', $a->trust()->state(['domain' => 'x.github.io', 'host' => 'x.github.io', 'psl_known' => true]), 'no history -> UNKNOWN');
$a->trust()->recordAbuse('example.org', true);
T::eq('SUSPICIOUS', $a->trust()->state($c), 'quarantine history -> SUSPICIOUS');
$_SERVER['REMOTE_ADDR'] = '192.0.2.200';
$s = $withDns($newApp());
T::throws('SECURITY_POLICY', fn () => $make($s, 'https://example.org/new'), 'SUSPICIOUS domain: creation refused');

// Domain quota (6 unknown links / 24h, global across actors)
T::rmrf($runtime);
$runtime = T::tmpdir('shorty-unit');
for ($i = 0; $i < 6; $i++) {
    $_SERVER['REMOTE_ADDR'] = "10.{$i}.0.1";
    $make($withDns($newApp()), "https://example.com/d{$i}");
}
$_SERVER['REMOTE_ADDR'] = '10.99.0.1';
T::throws('RATE_LIMIT', fn () => $make($withDns($newApp()), 'https://example.com/d7'), '7th link to an unknown domain in 24h refused');

// ---------------------------------------------------------------------------
T::group('Retention / purge (GC)');
T::rmrf($runtime);
$runtime = T::tmpdir('shorty-unit');
$_SERVER['REMOTE_ADDR'] = '203.0.113.42';
$g = $withDns($newApp());
$created = $make($g, 'https://example.com/gc');
$linkPath = $g->links()->path($created['code']);
T::ok(file_exists($linkPath), 'link stored');
$g->setTimeOffset(3600);
$g->retention()->collect(1000);
T::ok(file_exists($linkPath), 'not purged before expiry');
$g->setTimeOffset(5 * 3600 + 3601);
$g->retention()->collect(1000);
T::ok(!file_exists($linkPath), 'purged by GC after expiry (no access needed)');
$g->setTimeOffset(31 * 3600 + 7200);
$g->retention()->collect(1000);
T::ok(!glob("{$runtime}/actors/*/*.php") && !glob("{$runtime}/subnets/*/*.php"), 'rate files purged after 30h retention');
T::ok(!glob("{$runtime}/challenges/*/*.php"), 'challenge replay registry purged');
T::ok(!glob("{$runtime}/dedup/*/*.php"), 'dedup index purged');
T::ok(glob("{$runtime}/domains/*/*.php") !== [], 'domain history kept (90 days)');
$g->setTimeOffset(91 * 86400);
$g->retention()->collect(1000);
T::ok(!glob("{$runtime}/domains/*/*.php"), 'domain history purged after 90 days');
// Budget: GC never handles more than the budget per pass.
$h = $withDns($newApp(['quota' => ['actor_links' => [50, 86400], 'domain_unknown_links' => [50, 86400]], 'limits' => ['actor_attempts_short' => [100, 600], 'actor_attempts_long' => [100, 86400]]]));
for ($i = 0; $i < 12; $i++) {
    $make($h, "https://example.com/b{$i}");
}
$h->setTimeOffset(6 * 3600 + 3600);
T::ok($h->retention()->collect(5) <= 5, 'GC pass bounded by budget');
$h->retention()->collect(10000);
T::ok(!glob("{$runtime}/links/*/*/*.php"), 'repeated passes purge everything expired');

// ---------------------------------------------------------------------------
T::group('Lockdown');
$app = $newApp();
T::ok(!$app->lockdown()->creation(), 'no lockdown by default');
touch("{$runtime}/LOCKDOWN");
T::ok($app->lockdown()->creation() && !$app->lockdown()->full(), 'LOCKDOWN blocks creation only');
touch("{$runtime}/FULL_LOCKDOWN");
T::ok($app->lockdown()->full(), 'FULL_LOCKDOWN blocks outbound');

T::rmrf($runtime);
T::rmrf(dirname($stub));
T::rmrf($secDir);
T::finish();
