import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildResult, classifyPolicy } from '../src/audit.mjs'

const policy = (over) => ({
  tablename: 't',
  policyname: 'p',
  cmd: 'SELECT',
  roles: ['authenticated'],
  qual: null,
  with_check: null,
  ...over,
})

function kinds(result) {
  return result.findings.map((f) => f.kind).sort()
}

test('clean database passes', () => {
  const r = buildResult({ schema: 'public', noRls: [], policies: [] })
  assert.equal(r.passed, true)
  assert.equal(r.problems, 0)
  assert.equal(r.findings.length, 0)
})

test('table without RLS is a fail', () => {
  const r = buildResult({ schema: 'public', noRls: [{ tablename: 'payments' }] })
  assert.equal(r.passed, false)
  assert.equal(r.findings[0].kind, 'rls_disabled')
  assert.equal(r.findings[0].severity, 'fail')
})

test('USING(true) is permissive_true (fail)', () => {
  const r = buildResult({ schema: 'public', policies: [policy({ roles: ['anon'], qual: 'true' })] })
  assert.deepEqual(kinds(r), ['permissive_true'])
  assert.equal(r.passed, false)
})

test('WITH CHECK(true) is permissive_true (fail)', () => {
  const r = buildResult({ schema: 'public', policies: [policy({ cmd: 'INSERT', qual: null, with_check: 'true' })] })
  assert.deepEqual(kinds(r), ['permissive_true'])
})

test('NEW: anon can read without user scoping → anon_unscoped (fail)', () => {
  // this is the subtle case the old engine missed: not literal true, but anon reads everything
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['anon'], cmd: 'SELECT', qual: "status = 'published'" })],
  })
  assert.deepEqual(kinds(r), ['anon_unscoped'])
  assert.equal(r.problems, 1)
})

test('NEW: role-only check for authenticated → authenticated_unscoped (warn, not fail)', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['authenticated'], cmd: 'SELECT', qual: "auth.role() = 'authenticated'" })],
  })
  assert.deepEqual(kinds(r), ['authenticated_unscoped'])
  assert.equal(r.warnings, 1)
  assert.equal(r.problems, 0)
  assert.equal(r.passed, true) // warnings alone don't fail the gate
})

test('a properly scoped policy (auth.uid()) is NOT flagged', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['public'], cmd: 'SELECT', qual: '(auth.uid() = user_id)' })],
  })
  assert.equal(r.findings.length, 0)
  assert.equal(r.passed, true)
})

test('scoping via a subquery on auth.uid() is NOT flagged (real Supabase pattern)', () => {
  const r = buildResult({
    schema: 'public',
    policies: [
      policy({
        roles: ['public'],
        cmd: 'SELECT',
        qual: '(email IN ( SELECT tickets.email FROM membros WHERE (membros.user_id = ( SELECT auth.uid()))))',
      }),
    ],
  })
  assert.equal(r.findings.length, 0)
})

test('NEW: write policy with no WITH CHECK → write_unchecked (warn)', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['authenticated'], cmd: 'INSERT', qual: null, with_check: null })],
  })
  assert.deepEqual(kinds(r), ['write_unchecked'])
  assert.equal(r.warnings, 1)
})

test('allow-list moves a finding out of findings into allowed', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ policyname: 'public_read', roles: ['anon'], qual: 'true' })],
    allow: ['public_read'],
  })
  assert.equal(r.passed, true)
  assert.equal(r.findings.length, 0)
  assert.equal(r.allowed.length, 1)
})

test('findings are ordered fail-before-warn', () => {
  const r = buildResult({
    schema: 'public',
    noRls: [{ tablename: 'x' }],
    policies: [policy({ roles: ['authenticated'], cmd: 'INSERT', with_check: null })], // warn
  })
  assert.equal(r.findings[0].severity, 'fail')
  assert.equal(r.findings[r.findings.length - 1].severity, 'warn')
})

test('classifyPolicy: ALL command counts as both read and write', () => {
  const f = classifyPolicy(policy({ roles: ['anon'], cmd: 'ALL', qual: "org = 'x'", with_check: null }))
  const ks = f.map((x) => x.kind).sort()
  assert.deepEqual(ks, ['anon_unscoped', 'write_unchecked'])
})

test('coverage: a public storage bucket is a warning', () => {
  const r = buildResult({ schema: 'public', publicBuckets: [{ id: 'avatars', name: 'avatars' }] })
  assert.deepEqual(kinds(r), ['public_bucket'])
  assert.equal(r.warnings, 1)
})

test('coverage: a SECURITY DEFINER function is a warning', () => {
  const r = buildResult({ schema: 'public', secDefFns: [{ proname: 'do_admin_thing' }] })
  assert.deepEqual(kinds(r), ['security_definer'])
})

test('result carries the full table list (for the DAST pass)', () => {
  const r = buildResult({ schema: 'public', allTables: [{ tablename: 'a' }, { tablename: 'b' }] })
  assert.deepEqual(r.tables, ['a', 'b'])
})
