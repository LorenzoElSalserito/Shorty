#!/usr/bin/env node
// Browser e2e on the built package. ALWAYS run under a virtual X server:
//   xvfb-run -a node tests/e2e/run.mjs [packageDir]
// (headed/real-display browser windows crash the developer's Wayland session).
import { spawn } from 'node:child_process'
import { cpSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { chromium } from 'playwright-core'

if (!process.env.DISPLAY) {
  console.error('Refusing to run without a virtual display: use `xvfb-run -a node tests/e2e/run.mjs`')
  process.exit(2)
}

const pkg = resolve(process.argv[2] || 'dist')
const work = mkdtempSync(join(process.env.SHORTY_TEST_TMP || tmpdir(), 'shorty-e2e-'))
const shots = process.env.SHORTY_E2E_SHOTS || join(work, 'shots')
mkdirSync(shots, { recursive: true })
let pass = 0
const fails = []
const ok = (cond, label) => {
  if (cond) { pass++; console.log(`  ok   ${label}`) } else { fails.push(label); console.log(`  FAIL ${label}`) }
}

const freePort = () => new Promise((res) => { const s = createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)) }) })

// Two installs: domain root and a subfolder of another site.
mkdirSync(join(work, 'root'))
mkdirSync(join(work, 'site/shorty'), { recursive: true })
cpSync(pkg, join(work, 'root'), { recursive: true })
cpSync(pkg, join(work, 'site/shorty'), { recursive: true })
writeFileSync(join(work, 'site/index.html'), '<!doctype html><title>Main</title><h1>Main site</h1>')
const dns = join(work, 'dns.json')
writeFileSync(dns, JSON.stringify({ 'example.com': ['93.184.216.34'], 'www.example.com': ['93.184.216.34'], 'example.org': ['93.184.216.35'] }))

const servers = []
const startPhp = async (docroot) => {
  const port = await freePort()
  const p = spawn('php', ['-S', `127.0.0.1:${port}`, '-t', docroot], {
    env: { ...process.env, SHORTY_DEV: '1', SHORTY_DNS_STUB: dns, SHORTY_RUNTIME_DIR: join(work, `runtime-${port}`), PHP_CLI_SERVER_WORKERS: '4' },
    stdio: 'ignore',
  })
  servers.push(p)
  for (let i = 0; i < 100; i++) {
    try { await fetch(`http://127.0.0.1:${port}/robots.txt`); break } catch { await new Promise((r) => setTimeout(r, 50)) }
  }
  return `http://127.0.0.1:${port}/`
}

const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || '/usr/bin/chromium', headless: false, args: ['--no-sandbox', '--host-resolver-rules=MAP example.com ~NOTFOUND, MAP *.example.com ~NOTFOUND, MAP example.org ~NOTFOUND'] })
try {
  const rootBase = await startPhp(join(work, 'root'))
  const siteBase = await startPhp(join(work, 'site'))

  const flow = async (label, base, scheme) => {
    console.log(`\n== ${label} (${scheme})`)
    const ctx = await browser.newContext({ colorScheme: scheme, viewport: { width: 1280, height: 900 } })
    const page = await ctx.newPage()
    const problems = []
    page.on('console', (m) => { if (m.type() === 'error') problems.push(m.text()) })
    page.on('pageerror', (e) => problems.push(e.message))
    // Destinations never hit the network: their names do not resolve in this browser.

    await page.goto(base)
    await page.waitForSelector('#url')
    ok(await page.locator('h1').innerText() === 'Shorty', 'landing renders')
    ok((await page.getAttribute('html', 'data-bs-theme')) === scheme, `theme follows OS (${scheme})`)
    ok(await page.getByText('al massimo 3 link ogni 24 ore').count() === 1, 'quota notice visible')
    ok(await page.locator('label.btn-ttl').allInnerTexts().then((t) => t.join('|')) === '5 ore|1 giorno|7 giorni', 'TTL buttons 5h/1d/7d')
    ok(await page.locator('#ttl-5h').isChecked(), 'default TTL 5h')
    await page.screenshot({ path: join(shots, `${label.replace(/\W+/g, '-')}-${scheme}-landing.png`), fullPage: true })

    // Keyboard: the TTL radio group and submit are reachable.
    await page.fill('#url', 'https://www.example.com/e2e?x=1')
    await page.click('label[for="ttl-1d"]')
    const t0 = Date.now()
    await page.click('button[type=submit]')
    await page.waitForSelector('#short', { timeout: 60000 })
    const solveMs = Date.now() - t0
    const shortUrl = await page.inputValue('#short')
    ok(shortUrl.startsWith(new URL('?s=', base).toString()), `short URL inside install: ${shortUrl}`)
    ok(solveMs < 15000, `create incl. proof-of-work in ${solveMs} ms`)
    await page.screenshot({ path: join(shots, `${label.replace(/\W+/g, '-')}-${scheme}-result.png`), fullPage: true })

    // Interstitial.
    await page.goto(shortUrl)
    ok(await page.locator('.dest-host').innerText() === 'www.example.com', 'interstitial shows destination host')
    ok(await page.locator('#dest').inputValue() === 'https://www.example.com/e2e?x=1', 'full URL in read-only field')
    ok(await page.locator('#continue').isDisabled(), 'continue disabled during countdown')
    await page.screenshot({ path: join(shots, `${label.replace(/\W+/g, '-')}-${scheme}-interstitial.png`), fullPage: true })
    await page.waitForFunction(() => !document.getElementById('continue').disabled, null, { timeout: 6000 })
    ok(true, 'continue enabled after countdown')
    ok(problems.length === 0, `no console/CSP errors on Shorty pages${problems.length ? ': ' + problems.join(' | ') : ''}`)
    const nav = page.waitForRequest((r) => r.isNavigationRequest() && r.url().startsWith('https://www.example.com/'))
    await page.click('#continue')
    ok((await nav).url() === 'https://www.example.com/e2e?x=1', 'continue navigates to the stored destination')
    await page.waitForURL(/chrome-error|example\.com/, { waitUntil: 'commit' }).catch(() => {})
    await page.waitForTimeout(500)
    problems.length = 0

    // Report.
    const code = new URL(shortUrl).searchParams.get('s')
    await page.goto(new URL(`?r=${code}`, base).toString())
    await page.check('#cat-phishing')
    await page.click('button[type=submit]')
    await page.waitForSelector('.alert-success', { timeout: 60000 })
    ok(true, 'report submitted')

    // Small screen: no horizontal scrolling.
    await page.setViewportSize({ width: 360, height: 740 })
    await page.goto(base)
    await page.waitForSelector('#url')
    ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), 'no horizontal scroll at 360px')
    await page.goto(shortUrl)
    ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), 'interstitial fits 360px')
    await page.screenshot({ path: join(shots, `${label.replace(/\W+/g, '-')}-${scheme}-mobile.png`), fullPage: true })

    ok(problems.length === 0, `no console/CSP errors (report, mobile)${problems.length ? ': ' + problems.join(' | ') : ''}`)
    await ctx.close()
    return solveMs
  }

  await flow('domain root', rootBase, 'light')
  await flow('subfolder', new URL('shorty/', siteBase).toString(), 'dark')

  // Proof-of-work calibration on the real widget worker, ONE worker (worst case: no
  // parallelism). CDP CPU throttling does not reach Web Workers, so phone figures are
  // extrapolated from the single-thread desktop time (x4 mid-range, x6 low-end).
  console.log('\n== ALTCHA calibration (single worker)')
  const ctx = await browser.newContext()
  const page = await ctx.newPage()
  const results = {}
  for (const level of ['base']) {
    const times = []
    for (let i = 0; i < 5; i++) {
      await page.goto(rootBase)
      await page.waitForSelector('altcha-widget')
      times.push(Math.round(await page.evaluate(async () => {
        const w = document.querySelector('altcha-widget')
        await w.configure({ workers: 1, minDuration: 0 })
        const t = performance.now()
        await w.verify({ minDuration: 0, concurrency: 1 })
        return performance.now() - t
      })))
    }
    times.sort((a, b) => a - b)
    results[level] = { desktop_ms: times, median: times[2], est_midrange_x4: times[2] * 4, est_lowend_x6: times[2] * 6 }
  }
  console.log('  ' + JSON.stringify(results))
  writeFileSync(join(shots, 'altcha-calibration.json'), JSON.stringify(results, null, 2))
  ok(results.base.median >= 100 && results.base.median <= 1000, `desktop base median ${results.base.median} ms (target 300–800)`)
  ok(results.base.est_lowend_x6 < 8000, `low-end phone estimate ${results.base.est_lowend_x6} ms`)
  await ctx.close()
} finally {
  await browser.close()
  servers.forEach((s) => s.kill())
  if (!process.env.SHORTY_E2E_KEEP) rmSync(work, { recursive: true, force: true })
}

console.log(`\n${pass} passed, ${fails.length} failed${process.env.SHORTY_E2E_SHOTS ? `; screenshots in ${shots}` : ''}`)
fails.forEach((f) => console.log(`  - ${f}`))
process.exit(fails.length ? 1 : 0)
