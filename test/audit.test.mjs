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
  permissive: 'PERMISSIVE',
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

test('coverage: a view without security_invoker is a warning', () => {
  const r = buildResult({ schema: 'public', views: [{ viewname: 'user_emails', security_invoker: 'false' }] })
  assert.deepEqual(kinds(r), ['view_bypasses_rls'])
})

test('coverage: a security_invoker view is NOT flagged', () => {
  const r = buildResult({ schema: 'public', views: [{ viewname: 'safe_view', security_invoker: 'true' }] })
  assert.equal(r.findings.length, 0)
})

test('result carries the full table list (for the DAST pass)', () => {
  const r = buildResult({ schema: 'public', allTables: [{ tablename: 'a' }, { tablename: 'b' }] })
  assert.deepEqual(r.tables, ['a', 'b'])
})

// --- correctness: RESTRICTIVE policies + GRANTs ---

test('correctness: a RESTRICTIVE USING(true) never leaks (it only narrows)', () => {
  const r = buildResult({ schema: 'public', policies: [policy({ roles: ['anon'], qual: 'true', permissive: 'RESTRICTIVE' })] })
  assert.equal(r.findings.length, 0)
})

test('correctness: no GRANT to anon → a permissive USING(true) is NOT a leak', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['anon'], qual: 'true' })],
    grants: [], // grants were read; anon holds none on table "t"
  })
  assert.equal(r.problems, 0)
  assert.equal(r.findings.length, 0)
})

test('correctness: WITH the SELECT grant, the same policy IS a leak', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['anon'], qual: 'true' })],
    grants: [{ table_name: 't', grantee: 'anon', privilege_type: 'SELECT' }],
  })
  assert.deepEqual(kinds(r), ['permissive_true'])
  assert.equal(r.problems, 1)
})

test('correctness: a restrictive scoping policy downgrades a permissive leak to warn', () => {
  const r = buildResult({
    schema: 'public',
    policies: [
      policy({ policyname: 'open', roles: ['anon'], qual: 'true' }),
      policy({ policyname: 'scope', roles: ['anon'], qual: '(auth.uid() = owner)', permissive: 'RESTRICTIVE' }),
    ],
  })
  assert.equal(r.problems, 0) // the restrictive scope neutralises the open policy
  assert.equal(r.warnings, 1)
})

test('correctness: unknown grants (null) assume granted — no false negative', () => {
  const r = buildResult({ schema: 'public', policies: [policy({ roles: ['anon'], qual: 'true' })] })
  assert.equal(r.problems, 1) // grants not provided → still flagged
})

// --- item 3: completeness ---

test('a SECURITY DEFINER function anon can EXECUTE is a fail', () => {
  const r = buildResult({ schema: 'public', secDefFns: [{ proname: 'run_as_owner', anon_exec: true, auth_exec: true }] })
  assert.deepEqual(kinds(r), ['anon_executes_definer'])
  assert.equal(r.problems, 1)
})

test('a SECURITY DEFINER function only the owner can call is just a warning', () => {
  const r = buildResult({ schema: 'public', secDefFns: [{ proname: 'internal', anon_exec: false, auth_exec: false }] })
  assert.deepEqual(kinds(r), ['security_definer'])
  assert.equal(r.warnings, 1)
})

test('a permissive storage.objects policy is flagged (storage-prefixed)', () => {
  const r = buildResult({
    schema: 'public',
    storagePolicies: [{ tablename: 'objects', policyname: 'public_files', cmd: 'SELECT', roles: ['anon'], qual: 'true', with_check: null, permissive: 'PERMISSIVE' }],
  })
  assert.deepEqual(kinds(r), ['storage_permissive_true'])
})

test('a Realtime-published anon-readable table warns about change leakage', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ tablename: 'chat', roles: ['anon'], cmd: 'SELECT', qual: 'true' })],
    realtimeTables: [{ tablename: 'chat' }],
  })
  const ks = kinds(r)
  assert.ok(ks.includes('permissive_true'))
  assert.ok(ks.includes('realtime_exposure'))
})

test('a Realtime table that is NOT anon-readable does not warn', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ tablename: 'chat', roles: ['authenticated'], cmd: 'SELECT', qual: '(auth.uid() = owner)' })],
    realtimeTables: [{ tablename: 'chat' }],
  })
  assert.ok(!kinds(r).includes('realtime_exposure'))
})
