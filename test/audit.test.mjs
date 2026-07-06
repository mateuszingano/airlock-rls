import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildResult, permissiveLabel } from '../src/audit.mjs'

test('clean database passes', () => {
  const r = buildResult({ schema: 'public', noRls: [], permissiveRows: [] })
  assert.equal(r.passed, true)
  assert.equal(r.problems, 0)
})

test('table without RLS is a problem', () => {
  const r = buildResult({ schema: 'public', noRls: [{ tablename: 'profiles' }] })
  assert.equal(r.passed, false)
  assert.equal(r.problems, 1)
  assert.deepEqual(r.tablesWithoutRls, ['profiles'])
})

test('permissive USING(true) policy is a problem', () => {
  const r = buildResult({
    schema: 'public',
    permissiveRows: [{ tablename: 'notes', policyname: 'p_all', cmd: 'SELECT', qual: 'true', with_check: null }],
  })
  assert.equal(r.passed, false)
  assert.equal(r.permissive.length, 1)
  assert.equal(r.permissive[0].using, true)
  assert.equal(r.permissive[0].withCheck, false)
})

test('WITH CHECK(true) alone is a problem', () => {
  const r = buildResult({
    schema: 'public',
    permissiveRows: [{ tablename: 'notes', policyname: 'p_ins', cmd: 'INSERT', qual: null, with_check: 'true' }],
  })
  assert.equal(r.problems, 1)
  assert.equal(r.permissive[0].withCheck, true)
  assert.equal(r.permissive[0].using, false)
})

test('allow-list waves a permissive policy through', () => {
  const r = buildResult({
    schema: 'public',
    permissiveRows: [{ tablename: 'status', policyname: 'public_read', cmd: 'SELECT', qual: 'true', with_check: null }],
    allowSet: new Set(['public_read']),
  })
  assert.equal(r.passed, true)
  assert.equal(r.permissive.length, 0)
  assert.equal(r.allowed.length, 1)
})

test('allow-list accepts a plain array too', () => {
  const r = buildResult({
    schema: 'public',
    permissiveRows: [{ tablename: 'status', policyname: 'public_read', cmd: 'SELECT', qual: 'true', with_check: null }],
    allowSet: ['public_read'],
  })
  assert.equal(r.passed, true)
})

test('problems sum tables and policies', () => {
  const r = buildResult({
    schema: 'public',
    noRls: [{ tablename: 'a' }, { tablename: 'b' }],
    permissiveRows: [{ tablename: 'c', policyname: 'p', cmd: 'ALL', qual: 'true', with_check: 'true' }],
  })
  assert.equal(r.problems, 3)
})

test('permissiveLabel describes both clauses', () => {
  assert.equal(permissiveLabel({ using: true, withCheck: true }), 'USING(true) + WITH CHECK(true)')
  assert.equal(permissiveLabel({ using: true, withCheck: false }), 'USING(true)')
  assert.equal(permissiveLabel({ using: false, withCheck: true }), 'WITH CHECK(true)')
})
