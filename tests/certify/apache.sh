#!/usr/bin/env bash
# Certifies a Shorty package on a real Apache + mod_php server in production mode (HTTPS,
# no dev/test hooks). Installs are plain copies of the package (cp -a), no configuration:
#   https://shorty.test:PORT/          domain root (with an old Shorty 1 install underneath)
#   https://s.example.test:PORT/       subdomain
#   https://www.example.test:PORT/shorty/  subfolder of an existing site
#   https://plain.test:PORT/           AllowOverride None (.htaccess ignored, nginx-like)
# Usage: tests/certify/apache.sh <package-dir>
set -euo pipefail
PKG=$(realpath "${1:?package dir}")
HERE=$(cd "$(dirname "$0")" && pwd)
MODS=/usr/lib/apache2/modules
[ -f "$MODS/libphp8.4.so" ] || { echo "SKIP: mod_php 8.4 not available"; exit 77; }

WORK=$(mktemp -d "${SHORTY_TEST_TMP:-${TMPDIR:-/tmp}}/shorty-apache-XXXX")
trap 'apache2 -f "$WORK/httpd.conf" -k stop >/dev/null 2>&1 || true; sleep 1; rm -rf "$WORK"' EXIT
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')
HPORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')
mkdir -p "$WORK"/{root,sub,site/shorty,plain,logs,run}

# Old Shorty 1 install in the domain root: v2 is copied over it (upgrade by copy-paste).
mkdir -p "$WORK/root/data/A/b" "$WORK/root/lib"
printf '{"url":"https://evil.example/phish","code":"AbCdEf","ip":"203.0.113.42"}' > "$WORK/root/data/A/b/AbCdEf.json"
printf '{"AbCdEf":{"url":"https://evil.example/phish"}}' > "$WORK/root/data/index.json"
printf "<?php\nreturn ['allowed_ttls' => [7, 15, 30, 90], 'redirect_status' => 302];\n" > "$WORK/root/config.php"
printf "<?php\nclass Shorty {}\n" > "$WORK/root/lib/Shorty.php"
printf '<!DOCTYPE html><title>Shorty - URL Shortener</title><script src="/assets/old.js"></script>' > "$WORK/root/index.html"
printf '<!doctype html><title>Existing site</title><h1>Main site</h1>' > "$WORK/site/index.html"

for d in root sub site/shorty plain; do cp -a "$PKG/." "$WORK/$d/"; done

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=shorty.test" \
  -addext "subjectAltName=DNS:shorty.test,DNS:s.example.test,DNS:www.example.test,DNS:plain.test" \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" >/dev/null 2>&1

vhost() { # name docroot override
cat <<V
<VirtualHost 127.0.0.1:$PORT>
  ServerName $1
  DocumentRoot "$2"
  SSLEngine on
  SSLCertificateFile "$WORK/cert.pem"
  SSLCertificateKeyFile "$WORK/key.pem"
  <Directory "$2">
    AllowOverride $3
    Require all granted
  </Directory>
</VirtualHost>
V
}

cat > "$WORK/httpd.conf" <<C
ServerRoot "$WORK"
PidFile "$WORK/run/httpd.pid"
Mutex file:$WORK/run
DefaultRuntimeDir "$WORK/run"
Listen 127.0.0.1:$PORT
Listen 127.0.0.1:$HPORT
LoadModule mpm_prefork_module $MODS/mod_mpm_prefork.so
LoadModule authz_core_module $MODS/mod_authz_core.so
LoadModule authz_host_module $MODS/mod_authz_host.so
LoadModule dir_module $MODS/mod_dir.so
LoadModule mime_module $MODS/mod_mime.so
LoadModule rewrite_module $MODS/mod_rewrite.so
LoadModule headers_module $MODS/mod_headers.so
LoadModule ssl_module $MODS/mod_ssl.so
LoadModule socache_shmcb_module $MODS/mod_socache_shmcb.so
LoadModule php_module $MODS/libphp8.4.so
TypesConfig /etc/mime.types
StartServers 4
MinSpareServers 4
MaxSpareServers 8
MaxRequestWorkers 16
ServerName localhost
ErrorLog "$WORK/logs/error.log"
LogFormat "%h %r %>s" short
CustomLog "$WORK/logs/access.log" short
SSLSessionCache "shmcb:$WORK/run/ssl(512000)"
DirectoryIndex index.php index.html
<FilesMatch "\.php\$">
  SetHandler application/x-httpd-php
</FilesMatch>
php_admin_value error_log "$WORK/logs/php.log"
php_admin_flag display_errors off
$(vhost shorty.test "$WORK/root" All)
$(vhost s.example.test "$WORK/sub" All)
$(vhost www.example.test "$WORK/site" All)
$(vhost plain.test "$WORK/plain" None)
<VirtualHost 127.0.0.1:$HPORT>
  ServerName shorty.test
  DocumentRoot "$WORK/root"
  <Directory "$WORK/root">
    AllowOverride All
    Require all granted
  </Directory>
</VirtualHost>
C

apache2 -f "$WORK/httpd.conf" -k start
for i in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break; sleep 0.1; done

set +e
php "$HERE/server.php" "$WORK" "$PORT" "$HPORT" "$PKG"
RC=$?
set -e
if [ -s "$WORK/logs/php.log" ]; then echo "--- PHP log (must be empty of fatals)"; cat "$WORK/logs/php.log"; grep -q "Fatal" "$WORK/logs/php.log" && RC=1; fi
exit $RC
