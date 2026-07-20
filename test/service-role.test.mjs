import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  decodeJwtRole,
  scanText,
  findingFor,
  extractScriptUrls,
  scanSiteForServiceRole,
  isFetchableUrl,
} from '../src/service-role.mjs'

// Build a well-formed (unsigned) Supabase-style JWT for a given role.
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url')
const mkKey = (role) => `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ role, iss: 'supabase' })}.sig_not_verified`

const SERVICE_JWT = mkKey('service_role')
const ANON_JWT = mkKey('anon')

test('decodeJwtRole reads the role claim', () => {
  assert.equal(decodeJwtRole(SERVICE_JWT), 'service_role')
  assert.equal(decodeJwtRole(ANON_JWT), 'anon')
  assert.equal(decodeJwtRole('not.a.jwt'), null)
  assert.equal(decodeJwtRole('garbage'), null)
})

test('scanText flags a service_role key', () => {
  const hits = scanText(`const KEY="${SERVICE_JWT}";`)
  assert.equal(hits.length, 1)
  assert.equal(hits[0].type, 'jwt')
})

test('scanText NEVER flags the anon key (it is public by design)', () => {
  assert.deepEqual(scanText(`const supabase = createClient(url, "${ANON_JWT}")`), [])
})

test('scanText flags a new-format sb_secret key', () => {
  const hits = scanText('SUPABASE_SECRET=sb_secret_abcdEFGH1234 zzz')
  assert.equal(hits.length, 1)
  assert.equal(hits[0].type, 'secret_key')
})

test('scanText ignores the literal string "service_role" without a real key', () => {
  // e.g. an RLS policy shipped in a comment: auth.role() = 'service_role'
  assert.deepEqual(scanText(`if (auth.role() === 'service_role') allow()`), [])
})

test('findingFor builds a critical fail and never echoes the whole key', () => {
  const f = findingFor(scanText(SERVICE_JWT), 'https://app.example.com/main.js')
  assert.equal(f.kind, 'service_role_exposed')
  assert.equal(f.severity, 'fail')
  assert.equal(f.object, 'https://app.example.com/main.js')
  assert.match(f.detail, /bypasses ALL Row Level Security/)
  assert.ok(!f.detail.includes(SERVICE_JWT), 'must not print the full key')
})

test('findingFor returns null when there is nothing to report', () => {
  assert.equal(findingFor([], 'https://x.com'), null)
})

test('extractScriptUrls resolves relative and absolute srcs', () => {
  const html = `
    <script src="/_next/static/chunk.js"></script>
    <script src="https://cdn.example.com/vendor.js"></script>
    <script>inline()</script>
    <script src="data:text/js,skip"></script>`
  const urls = extractScriptUrls(html, 'https://app.example.com/')
  assert.ok(urls.includes('https://app.example.com/_next/static/chunk.js'))
  assert.ok(urls.includes('https://cdn.example.com/vendor.js'))
  assert.equal(urls.length, 2) // inline + data: are not fetchable srcs
})

test('scanSiteForServiceRole finds the key inside a JS bundle, names the file', async () => {
  const fetchImpl = async (url) => {
    if (url === 'https://app.example.com/') {
      return { text: async () => `<html><script src="/app.js"></script></html>` }
    }
    if (url === 'https://app.example.com/app.js') {
      // a real Supabase client init: anon key (safe) + a leaked service key (bad)
      return { text: async () => `createClient(u,"${ANON_JWT}"); const admin="${SERVICE_JWT}";` }
    }
    return { text: async () => '' }
  }
  const { findings, scanned } = await scanSiteForServiceRole({ siteUrl: 'https://app.example.com/', fetchImpl })
  assert.equal(scanned, 2) // page + 1 script
  assert.equal(findings.length, 1)
  assert.equal(findings[0].object, 'https://app.example.com/app.js')
  assert.equal(findings[0].severity, 'fail')
})

test('scanSiteForServiceRole is quiet on a clean site (only the anon key)', async () => {
  const fetchImpl = async (url) => {
    if (url.endsWith('/')) return { text: async () => `<script src="/ok.js"></script>` }
    return { text: async () => `createClient(u,"${ANON_JWT}")` }
  }
  const { findings } = await scanSiteForServiceRole({ siteUrl: 'https://safe.example.com/', fetchImpl })
  assert.deepEqual(findings, [])
})

// The site scanner follows `<script src>` from a page it was pointed at, so the
// PAGE decides what gets requested — an SSRF primitive if left unbounded. On the
// CLI the blast radius is a laptop; in the hosted Monitor, which the docs say
// shares this engine, it is the production network.
test('#ssrf the site scanner refuses private, loopback and metadata hosts', () => {
  for (const url of [
    'http://169.254.169.254/latest/meta-data/', 'http://[::ffff:169.254.169.254]/a.js',
    'http://127.0.0.1:8080/x.js', 'http://[::ffff:127.0.0.1]/x', 'http://localhost/x.js',
    'http://10.0.0.5/a.js', 'http://172.16.0.1/a.js', 'http://192.168.1.10/a.js',
    'http://[::1]/a.js', 'http://100.64.0.1/a.js', 'http://[fd00::1]/x', 'http://[fe80::1]/x',
    'file:///etc/passwd', 'http://0.0.0.0/x',
    // The v6 unspecified address reaches loopback on Linux; the parser folds
    // every spelling of it into "::".
    'http://[::]/x.js', 'http://[::0]/x', 'http://[0:0:0:0:0:0:0:0]/x',
    // Metadata services answer on a name, not only on 169.254.169.254.
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://metadata.goog/x', 'http://instance-data/latest/',
    'http://instance-data.ec2.internal/x',
  ]) assert.equal(isFetchableUrl(url), false, `${url} must be refused`)

  // …and the boundaries stay open: these are public addresses.
  for (const url of [
    'https://app.example.com/_next/static/chunk.js', 'http://cdn.jsdelivr.net/x.js',
    'https://172.32.0.1/a.js', 'https://192.169.0.1/a.js', 'https://8.8.8.8/x', 'https://[2606:4700::1]/x',
  ]) assert.equal(isFetchableUrl(url), true, `${url} must be allowed`)
})

// H1 (re-auditoria 20/07) — SSRF por REDIRECT. isFetchableUrl vetava a URL de
// entrada, mas o fetch seguia um 302 pra um endereço interno que nunca foi
// checado. Agora cada hop revalida o Location. Este teste também MATA a mutação
// que remove o .filter/revalidação — o filtro puro nunca era exercido pela fiação.
test('#ssrf a redirect to a private/metadata address is refused, not followed', async () => {
  let reachedInternal = false
  const fetchImpl = async (url, init) => {
    // sanity: precisamos estar dirigindo o redirect à mão
    assert.equal(init.redirect, 'manual', 'fetch must be driven with redirect:manual')
    if (url === 'https://public.example.com/') {
      return { status: 302, headers: { get: (h) => (h.toLowerCase() === 'location' ? 'http://169.254.169.254/latest/meta-data/' : null) }, text: async () => '' }
    }
    if (url.includes('169.254')) {
      reachedInternal = true
      return { status: 200, headers: { get: () => null }, text: async () => `admin="${SERVICE_JWT}"` }
    }
    return { status: 200, headers: { get: () => null }, text: async () => '' }
  }
  await assert.rejects(
    () => scanSiteForServiceRole({ siteUrl: 'https://public.example.com/', fetchImpl }),
    /only public|SSRF|Refusing to follow redirect/,
    'a redirect to the metadata IP must be refused'
  )
  assert.equal(reachedInternal, false, 'the internal address must never be fetched')
})

// H1b — a legitimate public→public redirect IS followed and scanned.
test('#ssrf a redirect between public hosts is followed and scanned', async () => {
  const fetchImpl = async (url) => {
    if (url === 'https://site.example.com/') {
      return { status: 301, headers: { get: (h) => (h.toLowerCase() === 'location' ? 'https://cdn.example.net/app.js' : null) }, text: async () => '' }
    }
    if (url === 'https://cdn.example.net/app.js') {
      return { status: 200, headers: { get: () => null }, text: async () => `const admin="${SERVICE_JWT}"` }
    }
    return { status: 200, headers: { get: () => null }, text: async () => '' }
  }
  const { findings } = await scanSiteForServiceRole({ siteUrl: 'https://site.example.com/', fetchImpl })
  assert.equal(findings.length, 1, 'the key on the redirected-to public host is found')
  assert.equal(findings[0].severity, 'fail')
})

// H2 (re-auditoria 20/07) — o scan lia no máximo 50 bundles e reportava limpo,
// indistinguível de "olhei tudo". Agora emite scan_truncated nomeando quantos
// ficaram de fora, e --max-scripts ajusta o teto.
test('#truncation scanning more scripts than the cap emits scan_truncated', async () => {
  const many = Array.from({ length: 80 }, (_, i) => `<script src="/a${i}.js"></script>`).join('')
  const fetchImpl = async (url) => ({
    status: 200, headers: { get: () => null },
    text: async () => (url === 'https://big.example.com/' ? `<html>${many}</html>` : ''),
  })
  const { findings, scanned } = await scanSiteForServiceRole({ siteUrl: 'https://big.example.com/', fetchImpl })
  const trunc = findings.find((f) => f.kind === 'scan_truncated')
  assert.ok(trunc, 'a scan_truncated finding must be emitted when scripts exceed the cap')
  assert.equal(trunc.severity, 'warn')
  assert.match(trunc.detail, /50 of 80/, 'it names how many were scanned vs total')
  assert.equal(scanned, 51, 'page + 50 bundles')

  // under the cap → no truncation finding, and --max-scripts raises the ceiling
  const few = Array.from({ length: 10 }, (_, i) => `<script src="/b${i}.js"></script>`).join('')
  const fetchImpl2 = async (url) => ({
    status: 200, headers: { get: () => null },
    text: async () => (url === 'https://small.example.com/' ? `<html>${few}</html>` : ''),
  })
  const r2 = await scanSiteForServiceRole({ siteUrl: 'https://small.example.com/', fetchImpl: fetchImpl2 })
  assert.ok(!r2.findings.some((f) => f.kind === 'scan_truncated'), '10 scripts under a 50 cap → no truncation')

  const r3 = await scanSiteForServiceRole({ siteUrl: 'https://big.example.com/', fetchImpl, maxScripts: 100 })
  assert.ok(!r3.findings.some((f) => f.kind === 'scan_truncated'), 'raising --max-scripts past the count clears the warning')
})
