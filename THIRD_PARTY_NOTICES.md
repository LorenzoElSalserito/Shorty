# Third-party notices

Shorty is licensed under the GNU AGPLv3 (see `LICENSE`). The release package bundles the
following third-party components and data, each under its own license.

| Component | Version | License | Use |
|---|---|---|---|
| [ALTCHA widget](https://github.com/altcha-org/altcha) (`altcha`, npm) | 3.5.0 | MIT | Proof-of-work widget, bundled locally (no CDN) |
| [hash-wasm](https://github.com/Daninet/hash-wasm) (ALTCHA dependency) | 4.x | MIT | Bundled with the widget |
| [ALTCHA PHP library](https://github.com/altcha-org/altcha-lib-php) (`altcha-org/altcha`) | 2.3.0 | MIT | Challenge creation / verification (`lib/vendor`) |
| [Vue.js](https://vuejs.org) | 3.5.x | MIT | Frontend |
| [Bootstrap](https://getbootstrap.com) | 5.3.x | MIT | Frontend styles |
| [Bootstrap Icons](https://icons.getbootstrap.com) | 1.11.x | MIT | Icon font, bundled locally |
| [Public Suffix List](https://publicsuffix.org) | snapshot, see `lib/security/psl/METADATA.json` | MPL-2.0 | Registrable-domain computation (compiled snapshot) |
| [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) | snapshot, see `lib/security/feeds/METADATA.json` | MIT | Threat feed, compiled to hashed shards at release time |

The Public Suffix List is subject to the Mozilla Public License 2.0
(https://mozilla.org/MPL/2.0/). The compiled `rules.php` is a mechanical transformation of
the list; the original source is available at https://publicsuffix.org/list/.

Phishing.Database: Copyright (c) Mitchell Krog, Nissar Chababy and contributors, MIT License.
Its entries are used as a local signal, not as a statement about any specific site.
