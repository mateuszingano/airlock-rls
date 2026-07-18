import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildResult, classifyPolicy, isScoped, isPermissiveTautology } from '../src/audit.mjs'

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

test('helper-scoped anon read is a warn (static scan cannot see inside the helper)', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['anon'], cmd: 'SELECT', qual: 'is_public(id)' })],
  })
  assert.deepEqual(kinds(r), ['helper_scoped'])
  assert.equal(r.problems, 0) // warn, not fail — it MIGHT restrict; DAST can prove it
  assert.match(r.findings[0].detail, /anon read is scoped only through is_public\(\)/)
})

test('helper-scoped AUTHENTICATED read is also a warn (any logged-in user could read all)', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['authenticated'], cmd: 'SELECT', qual: 'is_admin()' })],
  })
  assert.deepEqual(kinds(r), ['helper_scoped'])
  assert.match(r.findings[0].detail, /any authenticated user read is scoped only through is_admin\(\)/)
})

test('helper AND auth.uid() together → not flagged (a real scope is present)', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['anon'], cmd: 'SELECT', qual: 'is_x() and auth.uid() = owner' })],
  })
  assert.equal(r.findings.length, 0)
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

test('a SECURITY DEFINER function anon can EXECUTE is a warning (RLS helpers are legit)', () => {
  const r = buildResult({ schema: 'public', secDefFns: [{ proname: 'run_as_owner', anon_exec: true, auth_exec: true }] })
  assert.deepEqual(kinds(r), ['anon_executes_definer'])
  assert.equal(r.problems, 0)
  assert.equal(r.warnings, 1)
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

test('isScoped: recognises real Supabase scoping patterns (from the Zingui dogfood)', () => {
  assert.equal(isScoped('(auth.uid() = owner)'), true)
  assert.equal(isScoped("(familia_id = get_familia_id_do_user())"), true) // helper
  assert.equal(isScoped("(( SELECT auth.role() AS role) = 'service_role'::text)"), true) // backend-only
  assert.equal(isScoped("(auth.role() = 'authenticated')"), false) // role-only — still flagged
  assert.equal(isScoped("(status = 'published')"), false) // truly open
  assert.equal(isScoped(null), false)
})

test('an ALL policy with a scoped USING and no WITH CHECK is NOT write_unchecked (USING guards the write)', () => {
  // The Zingui pattern: [ALL] USING (familia_id = get_familia_id_do_user()), no WITH CHECK.
  // Postgres uses USING as the check, so the write IS scoped.
  const r = buildResult({
    schema: 'public',
    policies: [policy({ tablename: 'lancamentos', roles: ['authenticated'], cmd: 'ALL', qual: '(familia_id = get_familia_id_do_user())', with_check: null })],
  })
  assert.ok(!kinds(r).includes('write_unchecked'))
})

test('a service_role-only policy is NOT flagged as an anon leak', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ tablename: 'assinaturas', roles: ['public'], cmd: 'ALL', qual: "(auth.role() = 'service_role')" })],
  })
  assert.ok(!kinds(r).includes('anon_unscoped'))
})

test('a Realtime table that is NOT anon-readable does not warn', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ tablename: 'chat', roles: ['authenticated'], cmd: 'SELECT', qual: '(auth.uid() = owner)' })],
    realtimeTables: [{ tablename: 'chat' }],
  })
  assert.ok(!kinds(r).includes('realtime_exposure'))
})

// --- P0 fix #1: a scope token neutralised by `OR true` / tautology still fails ---

test('isPermissiveTautology: catches OR-true, OR 1=1, and bare tautologies', () => {
  assert.equal(isPermissiveTautology('auth.uid() = user_id OR true'), true)
  assert.equal(isPermissiveTautology('(auth.uid() = owner OR 1=1)'), true)
  assert.equal(isPermissiveTautology('true OR is_member(org)'), true)
  assert.equal(isPermissiveTautology('1 = 1'), true)
  assert.equal(isPermissiveTautology("'x' = 'x'"), true)
  assert.equal(isPermissiveTautology('(true)'), true)
  // real predicates must NOT be mistaken for tautologies
  assert.equal(isPermissiveTautology('published = true'), false)
  assert.equal(isPermissiveTautology('(auth.uid() = user_id)'), false)
  assert.equal(isPermissiveTautology("status = 'published'"), false)
  assert.equal(isPermissiveTautology('a = 1 OR b = 1'), false)
})

test('NEW #1: USING (auth.uid() = user_id OR true) for anon → permissive_true (FAIL)', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['anon'], cmd: 'SELECT', qual: 'auth.uid() = user_id OR true' })],
  })
  assert.deepEqual(kinds(r), ['permissive_true'])
  assert.equal(r.problems, 1)
})

test('NEW #1: a tautology-scoped read for authenticated is flagged (permissive_true warn)', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['authenticated'], cmd: 'SELECT', qual: 'auth.uid() = owner OR 1=1' })],
  })
  assert.deepEqual(kinds(r), ['permissive_true'])
  assert.equal(r.warnings, 1)
})

test('isScoped: a real scope neutralised by OR true is NOT scoped', () => {
  assert.equal(isScoped('auth.uid() = user_id OR true'), false)
  assert.equal(isScoped('(auth.uid() = user_id)'), true) // the honest scope still passes
})

// --- P0 fix #2: WITH CHECK present but not scoped ---

test('NEW #2: INSERT anon with WITH CHECK (status = ...) not scoped → write_unscoped (FAIL)', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['anon'], cmd: 'INSERT', qual: null, with_check: "status = 'pending'" })],
  })
  assert.deepEqual(kinds(r), ['write_unscoped'])
  assert.equal(r.problems, 1)
})

test('NEW #2: INSERT anon with WITH CHECK (1=1) → permissive_true (FAIL)', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['anon'], cmd: 'INSERT', qual: null, with_check: '1 = 1' })],
  })
  assert.deepEqual(kinds(r), ['permissive_true'])
  assert.equal(r.problems, 1)
})

test('NEW #2: authenticated-only unscoped WITH CHECK is a warn, not a fail', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['authenticated'], cmd: 'INSERT', qual: null, with_check: "kind = 'note'" })],
  })
  assert.deepEqual(kinds(r), ['write_unscoped'])
  assert.equal(r.problems, 0)
  assert.equal(r.warnings, 1)
})

test('correctness #2: a scoped WITH CHECK (auth.uid()) is NOT flagged', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['authenticated'], cmd: 'INSERT', qual: null, with_check: '(auth.uid() = user_id)' })],
  })
  assert.equal(r.findings.length, 0)
})

// --- P0 fix #3: any helper name routes to helper_scoped (no crying wolf) ---

test('NEW #3: authorize(...) (official Supabase RBAC) anon read → helper_scoped WARN, not fail', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['anon'], cmd: 'SELECT', qual: "authorize('posts.read')" })],
  })
  assert.deepEqual(kinds(r), ['helper_scoped'])
  assert.equal(r.problems, 0)
  assert.match(r.findings[0].detail, /through authorize\(\)/)
})

test('NEW #3: belongs_to_org() authenticated read → helper_scoped WARN', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['authenticated'], cmd: 'SELECT', qual: 'belongs_to_org(org_id)' })],
  })
  assert.deepEqual(kinds(r), ['helper_scoped'])
  assert.match(r.findings[0].detail, /through belongs_to_org\(\)/)
})

test('correctness #3: auth.role() = authenticated is still role-only (NOT a helper pass)', () => {
  // regression guard — auth.role() is a built-in, not a scoping helper
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['authenticated'], cmd: 'SELECT', qual: "auth.role() = 'authenticated'" })],
  })
  assert.deepEqual(kinds(r), ['authenticated_unscoped'])
})

// --- P0 fix #4: GRANT ... TO public is held by anon ---

test('NEW #4: GRANT SELECT TO public + USING(true) → permissive_true (FAIL)', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['anon'], qual: 'true' })],
    grants: [{ table_name: 't', grantee: 'PUBLIC', privilege_type: 'SELECT' }],
  })
  assert.deepEqual(kinds(r), ['permissive_true'])
  assert.equal(r.problems, 1)
})
