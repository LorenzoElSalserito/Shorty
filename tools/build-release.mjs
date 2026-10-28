#!/usr/bin/env node
// npm run build:release [-- --refresh-feed] [-- --no-certify]
// Produces dist/ (drag-and-drop package) + shorty-dist.zip, then certifies the artifact.
// Never changes the version: package.json / composer.json must be byte-identical afterwards.
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const dist = join(root, 'dist')
const args = new Set(process.argv.slice(2))
const run = (cmd, argv, opts = {}) => execFileSync(cmd, argv, { cwd: root, stdio: 'inherit', ...opts })
const sha = (f) => createHash('sha256').update(readFileSync(f)).digest('hex')
const step = (s) => console.log(`\n▶ ${s}`)

const versionFiles = ['package.json', 'composer.json', 'public/lib/src/App.php'].map((f) => join(root, f))
const versionsBefore = versionFiles.map(sha)

step('PHP dependencies (vendor, no dev)')
const composer = process.env.COMPOSER_BIN
if (composer) run('php', [composer, 'install', '--no-dev', '--no-interaction', '--no-progress'])
if (!existsSync(join(root, 'public/lib/vendor/autoload.php'))) {
  throw new Error('public/lib/vendor missing: run `composer install --no-dev` (or set COMPOSER_BIN=/path/composer.phar)')
}

step('Public Suffix List snapshot')
if (!existsSync(join(root, 'public/lib/security/psl/rules.php'))) run('node', ['tools/update-psl.mjs'])

step('Threat feed')
if (args.has('--refresh-feed') || !existsSync(join(root, 'public/lib/security/feeds/METADATA.json'))) {
  run('node', ['tools/build-threat-feed.mjs'])
}

step('Frontend build (Vite)')
rmSync(dist, { recursive: true, force: true })
run('npx', ['vite', 'build'])

step('Dependency inventory')
run('node', ['tools/dependencies.mjs'])

step('Assemble package')
// The SPA shell is served only through index.php (security headers), never directly.
renameSync(join(dist, 'index.html'), join(dist, 'lib/templates/app.html'))
rmSync(join(dist, 'runtime'), { recursive: true, force: true })
const vendor = join(dist, 'lib/vendor')
for (const pkgDir of readdirSync(vendor, { recursive: true }).map((p) => join(vendor, p))) {
  if (!existsSync(pkgDir)) continue
  const base = pkgDir.split('/').pop()
  if (/^(tests?|examples?|docs?|\.github)$/i.test(base) || /\.(md|dist|xml|neon)$/i.test(base)) {
    if (!/LICENSE/i.test(base)) rmSync(pkgDir, { recursive: true, force: true })
  }
}
for (const f of ['LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md', 'DEPENDENCIES.md', 'README.md', 'README_en.md', 'OPS_MANUAL.md']) {
  if (existsSync(join(root, f))) cpSync(join(root, f), join(dist, f))
}

step('Package policy checks')
const files = readdirSync(dist, { recursive: true }).map((p) => join(dist, p)).filter((p) => statSync(p).isFile())
const problems = []
for (const f of files) {
  const rel = relative(dist, f)
  if (/(^|\/)(runtime|\.env|node_modules)(\/|$)|secrets?\.php$|\.secret\.php$/.test(rel)) problems.push(`forbidden file: ${rel}`)
  if (/\.(js|css|html|php)$/.test(rel) && !/^lib\/(vendor|security)\//.test(rel)) {
    const text = readFileSync(f, 'utf8')
    for (const cdn of ['cdn.jsdelivr', 'unpkg.com', 'cdnjs', 'googleapis', 'gstatic', 'cloudflare', 'recaptcha', 'hcaptcha', 'turnstile']) {
      if (text.includes(cdn)) problems.push(`external runtime reference "${cdn}" in ${rel}`)
    }
  }
}
for (const must of ['index.php', 'go.php', 'api.php', 'robots.txt', '.htaccess', 'internal/create.php', 'lib/.htaccess',
  'lib/templates/app.html', 'lib/vendor/autoload.php', 'lib/security/psl/rules.php', 'lib/security/feeds/METADATA.json',
  'lib/security/feeds/domains/00.bin', 'lib/security/feeds/domains/ff.bin', 'LICENSE', 'THIRD_PARTY_NOTICES.md']) {
  if (!existsSync(join(dist, must))) problems.push(`missing: ${must}`)
}
if (existsSync(join(dist, 'index.html'))) problems.push('index.html must not be a standalone entry point')
if (problems.length) {
  console.error(problems.join('\n'))
  process.exit(1)
}

step('Zip')
rmSync(join(root, 'shorty-dist.zip'), { force: true })
run('zip', ['-qr', join(root, 'shorty-dist.zip'), '.'], { cwd: dist })

if (versionFiles.some((f, i) => sha(f) !== versionsBefore[i])) throw new Error('Version files changed during the build')
console.log('\n✔ Package built: dist/ and shorty-dist.zip (version files unchanged)')

if (!args.has('--no-certify')) {
  step('Certification on the final artifact')
  run('bash', ['tests/certify.sh', dist])
}
