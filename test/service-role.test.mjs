import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  decodeJwtRole,
  scanText,
  findingFor,
  extractScriptUrls,
  scanSiteForServiceRole,
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
