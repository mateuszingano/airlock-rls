import { test } from 'node:test'
import assert from 'node:assert/strict'
import { classifyProbe, probeAnonReads } from '../src/dast.mjs'

test('rows returned = proven leak (fail)', () => {
  const f = classifyProbe('payments', 200, [{ id: 1, amount: 999, card_last4: '4242' }])
  assert.equal(f.kind, 'anon_read_leak')
  assert.equal(f.severity, 'fail')
  assert.match(f.detail, /amount/)
})

test('empty array = safe (RLS blocks or empty table)', () => {
  assert.equal(classifyProbe('waitlist', 200, []), null)
})

test('401/403 = safe (blocked)', () => {
  assert.equal(classifyProbe('secrets', 401, { message: 'permission denied' }), null)
  assert.equal(classifyProbe('secrets', 403, null), null)
})

test('probeAnonReads flags only the tables that actually return rows', async () => {
  const fetchImpl = async (url) => {
    if (url.includes('/leaky')) return { status: 200, json: async () => [{ id: 1, email: 'a@b.com' }] }
    if (url.includes('/locked')) return { status: 200, json: async () => [] }
    return { status: 401, json: async () => ({}) }
  }
  const { findings, probed } = await probeAnonReads({
    projectUrl: 'https://x.supabase.co',
    anonKey: 'anon',
    tables: ['leaky', 'locked', 'blocked'],
    fetchImpl,
  })
  assert.equal(probed, 3)
  assert.equal(findings.length, 1)
  assert.equal(findings[0].object, 'leaky')
})

test('discoverTables path is used when tables not provided', async () => {
  const calls = []
  const fetchImpl = async (url) => {
    calls.push(url)
    if (url.endsWith('/rest/v1/')) {
      return { ok: true, status: 200, json: async () => ({ paths: { '/': {}, '/users': {}, '/orders': {}, '/rpc/foo': {} } }) }
    }
    return { status: 200, json: async () => [] }
  }
  const { probed } = await probeAnonReads({ projectUrl: 'https://x.supabase.co', anonKey: 'k', fetchImpl })
  // /users and /orders discovered; '/' and '/rpc/foo' excluded
  assert.equal(probed, 2)
  assert.ok(calls.some((u) => u.includes('/users')))
})
