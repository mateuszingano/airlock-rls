// Exposed files (.env, .git, source maps) and the public-key hint of the
// --site scan. Every fake response here carries a status, because the probes
// only trust a 200 AND a body that is really the file (SPA hosts answer 200
// with index.html for any path).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  scanSiteForServiceRole,
  countEnvVars,
  isGitHead,
  isSourceMap,
  sourceMapUrlFor,
  hasPublicKey,
} from '../src/service-role.mjs'

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url')
const mkKey = (role) => `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ role, iss: 'supabase' })}.sig_not_verified`
const SERVICE_JWT = mkKey('service_role')
const ANON_JWT = mkKey('anon')

const ok = (body) => ({ status: 200, text: async () => body })
const notFound = () => ({ status: 404, text: async () => 'not found' })
const SPA = '<!doctype html><html><body><div id="root"></div></body></html>'

test('#exposed countEnvVars counts KEY=value lines and never counts an HTML fallback', () => {
  assert.equal(countEnvVars('SUPABASE_URL=https://x.supabase.co\n# c\nexport STRIPE_KEY=sk_live_x\n'), 2)
  assert.equal(countEnvVars(SPA), 0)
  assert.equal(countEnvVars(''), 0)
  assert.equal(countEnvVars('just some text'), 0)
})

test('#exposed isGitHead / isSourceMap / sourceMapUrlFor', () => {
  assert.equal(isGitHead('ref: refs/heads/main\n'), true)
  assert.equal(isGitHead('a'.repeat(40)), true)
  assert.equal(isGitHead(SPA), false)
  assert.equal(isSourceMap('{"version":3,"sources":["a.ts"],"mappings":"AAAA"}'), true)
  assert.equal(isSourceMap(SPA), false)
  assert.equal(isSourceMap('{"version":3}'), false)
  assert.equal(
    sourceMapUrlFor('x()\n//# sourceMappingURL=app.js.map', 'https://s.example.com/a/app.js'),
    'https://s.example.com/a/app.js.map'
  )
  assert.equal(sourceMapUrlFor('x()\n//# sourceMappingURL=data:application/json;base64,e30=', 'https://s.example.com/app.js'), null)
  assert.equal(sourceMapUrlFor('x()', 'https://s.example.com/app.js'), null)
})

test('#exposed an SPA that answers 200 + index.html for every path is NOT flagged', async () => {
  const page = SPA.replace('<body>', '<body><script src="/app.js"></script>')
  const fetchImpl = async (url) => (url.endsWith('/app.js') ? ok('x()') : ok(page))
  const { findings } = await scanSiteForServiceRole({ siteUrl: 'https://spa.example.com/', fetchImpl })
  assert.deepEqual(findings, [])
})

test('#exposed a real .env and .git are fails; no .env value is ever echoed', async () => {
  const fetchImpl = async (url) => {
    if (url === 'https://leaky.example.com/') return ok('<html></html>')
    if (url === 'https://leaky.example.com/.env') return ok('SUPABASE_SERVICE_KEY=supersecretvalue123\nDB_PASS=hunter2\n')
    if (url === 'https://leaky.example.com/.git/HEAD') return ok('ref: refs/heads/main\n')
    return notFound()
  }
  const { findings } = await scanSiteForServiceRole({ siteUrl: 'https://leaky.example.com/', fetchImpl })
  assert.deepEqual(findings.map((f) => f.kind).sort(), ['env_file_exposed', 'git_exposed'])
  assert.ok(findings.every((f) => f.severity === 'fail'))
  assert.match(findings.find((f) => f.kind === 'env_file_exposed').detail, /2 variable/)
  const all = JSON.stringify(findings)
  assert.ok(!all.includes('supersecretvalue123'))
  assert.ok(!all.includes('hunter2'))
})

test('#exposed public source maps are a warn, and a key inside sourcesContent is still a fail', async () => {
  const map = JSON.stringify({ version: 3, sources: ['src/admin.ts'], sourcesContent: [`const k="${SERVICE_JWT}"`], mappings: 'AAAA' })
  const fetchImpl = async (url) => {
    if (url === 'https://maps.example.com/') return ok('<script src="/app.js"></script>')
    if (url === 'https://maps.example.com/app.js') return ok('x()\n//# sourceMappingURL=app.js.map')
    if (url === 'https://maps.example.com/app.js.map') return ok(map)
    return notFound()
  }
  const { findings } = await scanSiteForServiceRole({ siteUrl: 'https://maps.example.com/', fetchImpl })
  const sm = findings.find((f) => f.kind === 'source_map_exposed')
  assert.equal(sm.severity, 'warn')
  assert.equal(sm.object, 'https://maps.example.com/app.js.map')
  assert.equal(findings.find((f) => f.kind === 'service_role_exposed').object, 'https://maps.example.com/app.js.map')
  assert.equal(findings[0].severity, 'fail') // fails sorted first
})

test('#exposed exposedFiles:false skips the extra probes entirely', async () => {
  const asked = []
  const fetchImpl = async (url) => {
    asked.push(url)
    return url.endsWith('/') ? ok('<script src="/app.js"></script>') : ok('x()\n//# sourceMappingURL=app.js.map')
  }
  await scanSiteForServiceRole({ siteUrl: 'https://off.example.com/', fetchImpl, exposedFiles: false })
  assert.deepEqual(asked, ['https://off.example.com/', 'https://off.example.com/app.js'])
})

test('#publickey publicKeyFound comes from an anon JWT or sb_publishable_, and is never a finding', async () => {
  assert.equal(hasPublicKey(`createClient(u,"${ANON_JWT}")`), true)
  assert.equal(hasPublicKey('createClient(u,"sb_publishable_abcDEF123456")'), true)
  assert.equal(hasPublicKey(`k="${SERVICE_JWT}"`), false)
  const fetchImpl = async (url) =>
    url.endsWith('/') ? ok('<script src="/c.js"></script>') : url.endsWith('/c.js') ? ok(`createClient(u,"${ANON_JWT}")`) : notFound()
  const r = await scanSiteForServiceRole({ siteUrl: 'https://pk.example.com/', fetchImpl })
  assert.equal(r.publicKeyFound, true)
  assert.deepEqual(r.findings, [])
  const r2 = await scanSiteForServiceRole({ siteUrl: 'https://nopk.example.com/', fetchImpl: async () => ok('<html></html>') })
  assert.equal(r2.publicKeyFound, false)
})
