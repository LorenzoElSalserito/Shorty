#!/usr/bin/env node
// Release step: compile the Phishing.Database (MIT) active-domain list into sorted,
// fixed-width binary shards (public/lib/security/feeds/domains/XX.bin).
// Each record = first 16 bytes of SHA-256(lowercase hostname). Never downloaded at runtime.
import { createHash } from 'node:crypto'
import { mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const out = join(root, 'public/lib/security/feeds')
const SOURCE = 'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt'
const RECORD = 16

const fromFile = process.argv[2]
const text = fromFile ? readFileSync(fromFile, 'utf8') : await (async () => {
  const res = await fetch(SOURCE)
  if (!res.ok) throw new Error(`Feed download failed: HTTP ${res.status}`)
  return res.text()
})()

const host = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/
const shards = Array.from({ length: 256 }, () => [])
let accepted = 0
const seen = new Set()
for (const raw of text.split('\n')) {
  const d = raw.trim().toLowerCase().replace(/\.$/, '')
  if (!d || d.startsWith('#') || !host.test(d) || seen.has(d)) continue
  seen.add(d)
  const h = createHash('sha256').update(d).digest().subarray(0, RECORD)
  shards[h[0]].push(h)
  accepted++
}
if (accepted < 1000 && !process.env.SHORTY_FEED_ALLOW_SMALL) throw new Error(`Feed too small (${accepted})`)

rmSync(join(out, 'domains'), { recursive: true, force: true })
mkdirSync(join(out, 'domains'), { recursive: true })
shards.forEach((list, i) => {
  list.sort(Buffer.compare)
  writeFileSync(join(out, 'domains', i.toString(16).padStart(2, '0') + '.bin'), Buffer.concat(list))
})
writeFileSync(join(out, 'METADATA.json'), JSON.stringify({
  format: 'shorty-feed-v1',
  source: fromFile ? `file:${fromFile}` : SOURCE,
  license: 'MIT (Phishing.Database, https://github.com/Phishing-Database/Phishing.Database)',
  built_at: new Date().toISOString(),
  input_sha256: createHash('sha256').update(text).digest('hex'),
  domains: accepted,
  record: 'sha256(hostname)[0:16], sorted, sharded by first byte',
}, null, 2) + '\n')
console.log(`Threat feed compiled: ${accepted} domains`)
