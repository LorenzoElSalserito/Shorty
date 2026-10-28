#!/usr/bin/env bash
# Certification of a built Shorty package (run by `npm run build:release`, or directly:
# `bash tests/certify.sh dist`). Every step runs on the FINAL artifact, not on the sources.
#   1. package unit tests against the packaged lib/
#   2. black-box integration + abuse + concurrency (PHP server, dev hooks)
#   3. production Apache + mod_php over HTTPS: domain root, subdomain, subfolder,
#      no-.htaccess host, v1 -> v2 upgrade by copy, server-side purge
#   4. browser e2e under Xvfb (never on the real display)
set -uo pipefail
PKG=$(realpath "${1:-dist}")
ROOT=$(cd "$(dirname "$0")/.." && pwd)
export SHORTY_TEST_TMP=${SHORTY_TEST_TMP:-$(mktemp -d "${TMPDIR:-/tmp}/shorty-cert-XXXX")}
mkdir -p "$SHORTY_TEST_TMP"
declare -A RESULT
STATUS=0

step() { # name command...
  local name=$1; shift
  echo -e "\n================ $name"
  "$@"
  local rc=$?
  case $rc in
    0) RESULT[$name]=PASS ;;
    77) RESULT[$name]="SKIP (environment)" ;;
    *) RESULT[$name]="FAIL (exit $rc)"; STATUS=1 ;;
  esac
}

# The packaged lib/ is copied so tests never write into the artifact.
CERT_PKG="$SHORTY_TEST_TMP/package"
rm -rf "$CERT_PKG"; cp -a "$PKG" "$CERT_PKG"

step "unit" env SHORTY_LIB="$CERT_PKG/lib" php "$ROOT/tests/unit/run.php"
step "integration" php "$ROOT/tests/integration/run.php" "$CERT_PKG"
step "apache-https" bash "$ROOT/tests/certify/apache.sh" "$PKG"
if command -v xvfb-run >/dev/null && [ -x "${CHROMIUM:-/usr/bin/chromium}" ]; then
  step "e2e-browser" xvfb-run -a node "$ROOT/tests/e2e/run.mjs" "$PKG"
else
  RESULT[e2e-browser]="SKIP (xvfb-run/chromium missing)"
fi

echo -e "\n================ Certification summary ($PKG)"
for k in unit integration apache-https e2e-browser; do printf '  %-14s %s\n' "$k" "${RESULT[$k]:-not run}"; done
[ $STATUS -eq 0 ] && echo "CERTIFIED" || echo "NOT CERTIFIED"
exit $STATUS
