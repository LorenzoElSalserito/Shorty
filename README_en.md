# Shorty

![Shorty Logo](./Shorty.png)

> **Short-lived links, self-hosted, database-free, designed to be inconvenient to abuse.**

Shorty 2 is not an anonymous redirector: it is a short-lived *link disclosure gateway*.
Whoever opens a short link always sees the destination and chooses whether to continue.
It installs by copying one folder onto any PHP hosting.

---

## Features

* **No automatic redirect**: every link shows an interstitial page with the domain and full
  URL; leaving Shorty takes a click (signed POST, the destination is always reloaded
  server-side).
* **At most 3 links per IP address every 24 hours** (rolling window), plus per-network,
  per-destination-domain and global limits.
* **Short lifetimes**: 5 hours (default), 1 day, 7 days.
* **Self-hosted ALTCHA**: open-source proof-of-work bundled in the package; no third-party
  CAPTCHA, no tracking cookies.
* **Strict URL policy**: `https://` with a domain name only; IPs, private networks,
  credentials in URLs, non-standard ports, punycode, other shorteners, executables and
  archives are rejected.
* **Local denylist + FOSS feed** (Phishing.Database) compiled at every release; no external
  API at runtime, destinations are never fetched (no SSRF).
* **Abuse reports and automatic quarantine**, FTP kill switch (`runtime/LOCKDOWN`).
* **Privacy**: IPs are never stored in clear; Shorty uses expiring pseudonymous HMAC
  identifiers. Web-server logs are outside the application's control.
* **Zero configuration**: no database, Composer, npm, cron or Docker on the server. Expired
  links are cleaned up automatically by normal traffic.
* **Open Source**: AGPLv3. FOSS components only, listed in `THIRD_PARTY_NOTICES.md`.

There is no public API: internal endpoints require a session, a one-time CSRF token and a
valid ALTCHA proof, and enforce the quotas.

## Installation

Requirements: PHP **8.3+** and HTTPS.

1. Download `shorty-dist.zip` (or build it with `npm run build:release`).
2. Copy its **contents** into the site folder: a domain root, a subdomain root or a
   subfolder (e.g. `public_html/shorty/`). Nothing to configure.
3. Open the address in a browser. Shorty creates `runtime/` and its secret by itself. If
   PHP cannot write the folder it shows an error and refuses to create links.

Links look like `https://yoursite/?s=AbCdEf1234`, which works everywhere. On Apache or
LiteSpeed `https://yoursite/s/AbCdEf1234` works too (rules already in `.htaccess`).

**Upgrading from Shorty 1**: copy the new package over the old one. On first access Shorty 2
deletes the old links (`data/`, which held raw IPs) and the v1 files. Old short links answer
`410 Gone`. Take an offline backup first if you need it for investigation.

Operations, blocking, lockdown and manual tests: [`OPS_MANUAL.md`](./OPS_MANUAL.md) (Italian).

## Development

Prerequisites: Node.js 20.19+ / 22.12+, PHP 8.3+, Composer.

```bash
npm install
composer install --no-dev      # ALTCHA PHP into public/lib/vendor
npm run psl:update             # Public Suffix List snapshot (already in the repo)
npm run feed:update            # compiled anti-phishing feed (not versioned)

# Backend (terminal 1) — SHORTY_DEV=1 allows HTTP on PHP's dev server only
SHORTY_DEV=1 php -S localhost:8000 -t public
# Frontend (terminal 2)
npm run dev
```

### Build and certification

```bash
npm run build:release          # builds dist/ + shorty-dist.zip and certifies the artifact
```

Certification runs on the final package: unit tests, integration and abuse tests (including
100 parallel requests), a real Apache + mod_php over HTTPS with installs in a domain root, a
subdomain, a subfolder, without `.htaccess` and as a v1 upgrade, and browser tests under Xvfb.
The build never changes the version.

## License

Distributed under the **AGPLv3** license. See `LICENSE` and `THIRD_PARTY_NOTICES.md`.

## © Copyright

**Copyright © 2026 Lorenzo De Marco (Lorenzo DM)**
