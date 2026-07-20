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

// --- FAIL-SAFE (re-audit → architecture, not form-hunting): an OR branch the
// engine can't prove restricts must WARN, never pass silently. Closes the class:
// even tautology forms the denylist doesn't recognize fall into the warn. ---
test('fail-safe: an unproven OR branch next to auth.uid() WARNs (never silent green)', () => {
  const widen = [
    "auth.uid() = user_id OR status = 'published'",
    'auth.uid() = user_id OR deleted_at is null OR deleted_at is not null',
    'auth.uid() = user_id OR is_public()',            // helper on an OR branch widens
  ]
  for (const qual of widen) {
    const r = buildResult({ schema: 'public', policies: [policy({ roles: ['authenticated'], cmd: 'SELECT', qual })] })
    assert.ok(kinds(r).includes('or_branch_unscoped'), `expected a warn for: ${qual}`)
    assert.equal(r.problems, 0) // it's a WARN, not a hard fail (could be intentional public sharing)
  }
})

// The parse-tree engine PROVES these branches are always-true, so they are no
// longer a soft "unproven branch" warn — they are the real thing: a tautology
// that opens the table. Stronger verdict than the old regex engine could give.
test('a provable tautology on an OR branch is a permissive_true FAIL, not just a warn', () => {
  for (const qual of [
    'auth.uid() = user_id OR (1=1 AND 2=2)',        // AND-group of constants
    'auth.uid() = user_id OR coalesce(true, false)', // coalesce to a constant true
    'auth.uid() = owner OR auth.uid() = auth.uid()', // reflexive on the token
    "auth.uid() = owner OR current_setting('x') = current_setting('x')",
    'auth.uid() = owner OR auth.uid() in (auth.uid())',
  ]) {
    const r = buildResult({ schema: 'public', policies: [policy({ roles: ['authenticated'], cmd: 'SELECT', qual })] })
    assert.ok(kinds(r).includes('permissive_true'), `expected permissive_true for: ${qual}`)
  }
})

test('fail-safe: a fully user-scoped OR does NOT warn (no false positive)', () => {
  const safe = [
    'auth.uid() = owner OR auth.uid() = shared_with', // both branches user-scoped
    '(auth.uid() = user_id)',                         // no OR at all
    'auth.uid() = user_id OR 1=2',                    // the OR branch is provably false → contributes nothing
    "auth.role() = 'service_role' OR auth.uid() = owner",
  ]
  for (const qual of safe) {
    const r = buildResult({ schema: 'public', policies: [policy({ roles: ['authenticated'], cmd: 'SELECT', qual })] })
    assert.ok(!kinds(r).includes('or_branch_unscoped'), `did NOT expect a warn for: ${qual}`)
  }
})

test('fail-safe: an anon-reachable widening OR branch still warns (verify, not silent)', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['anon'], cmd: 'SELECT', qual: "auth.uid() = user_id OR org = 'acme'" })],
  })
  assert.ok(kinds(r).includes('or_branch_unscoped'))
})

// BYPASS (re-audit → 7.5): realScope keyed on token PRESENCE, so a branch that
// CARRIES auth.uid() but doesn't restrict (`OR auth.uid() IS NOT NULL` = every
// logged-in user reads the whole table) passed green. realScope now requires the
// token to RESTRICT (be compared to a per-row value), not merely appear.
test('fail-safe: a token that is present but not restrictive still WARNs (not silent green)', () => {
  // These are NOT provably always-true (auth.uid() may be NULL for anon), so they
  // stay a soft warn. The reflexive ones moved to the tautology test above, where
  // the parse tree proves them always-true and the verdict is a hard fail.
  const widen = [
    'auth.uid() = owner OR auth.uid() is not null',   // any authenticated caller reads all
    'auth.uid() = owner OR auth.jwt() is not null',
    'auth.uid() = owner OR auth.uid() = ANY(ARRAY[auth.uid()])',
  ]
  for (const qual of widen) {
    const r = buildResult({ schema: 'public', policies: [policy({ roles: ['authenticated'], cmd: 'SELECT', qual })] })
    assert.ok(kinds(r).includes('or_branch_unscoped'), `expected a warn for: ${qual}`)
  }
})

test('fail-safe: a token compared to a per-row value is genuinely scoped (no false positive)', () => {
  const scoped = [
    'auth.uid() = owner OR is_admin(auth.uid())',
    'owner = (select auth.uid()) OR auth.uid() = shared_with',
    'auth.uid() = owner OR auth.uid() = ANY(collaborators)', // ANY over a column, not self
  ]
  for (const qual of scoped) {
    const r = buildResult({ schema: 'public', policies: [policy({ roles: ['authenticated'], cmd: 'SELECT', qual })] })
    assert.ok(!kinds(r).includes('or_branch_unscoped'), `did NOT expect a warn for: ${qual}`)
  }
})

// A clean database HAS tables whose RLS is in order. The fixture must say so:
// "no tables, no policies, nothing anywhere" is not a clean database, it is a
// database we never read — and that is now a hard fail (see below). Passing
// allTables here is what makes this a test of "clean" instead of a test of
// "empty", which is the exact ambiguity that let a typo'd --schema stay green.
test('clean database passes', () => {
  const r = buildResult({
    schema: 'public',
    allTables: [{ tablename: 'notes' }],
    noRls: [],
    policies: [{ tablename: 'notes', policyname: 'own notes', cmd: 'SELECT', roles: ['authenticated'], qual: 'owner_id = auth.uid()', with_check: null, permissive: 'PERMISSIVE' }],
  })
  assert.equal(r.passed, true)
  assert.equal(r.problems, 0)
  assert.equal(r.findings.length, 0)
})

// ONDA 0.1 — the invariant: "I audited nothing" must never render as "clean".
// A misspelled schema (`pubic`), or tables that moved to another schema while
// the workflow still points at the old one, empties every catalog query at once.
// That used to produce `passed: true` and print "✓ No RLS problems".
test('#nothing_audited an empty/misspelled schema fails instead of passing green', () => {
  const typo = buildResult({ schema: 'pubic_typo' })
  assert.equal(typo.passed, false, 'a schema with nothing in it must NOT pass')
  assert.equal(typo.problems, 1)
  assert.equal(typo.findings[0].kind, 'nothing_audited')
  assert.equal(typo.findings[0].severity, 'fail')
  // and reading ANY catalog row means we really did audit — no false alarm
  for (const seed of [
    { allTables: [{ tablename: 't' }] },
    { noRls: [{ tablename: 't' }] },
    { publicBuckets: [{ id: 'b', name: 'b' }] },
    { views: [{ viewname: 'v', reloptions: null }] },
  ]) {
    const r = buildResult({ schema: 'public', ...seed })
    assert.ok(!r.findings.some((f) => f.kind === 'nothing_audited'), `reading ${Object.keys(seed)[0]} must not report nothing_audited`)
  }
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

// FOR ALL is all FOUR verbs, so an unscoped USING exposes reads, writes AND
// deletes. The delete finding was missing before DELETE had a branch at all.
test('classifyPolicy: ALL command counts as read, write and delete', () => {
  const f = classifyPolicy(policy({ roles: ['anon'], cmd: 'ALL', qual: "org = 'x'", with_check: null }))
  const ks = f.map((x) => x.kind).sort()
  assert.deepEqual(ks, ['anon_unscoped', 'delete_unscoped', 'write_unchecked'])
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

test('isPermissiveTautology: GENERAL tautologies, not just the literal 1=1', () => {
  // the Critical the first fix missed: any self-equality / always-true constant
  assert.equal(isPermissiveTautology('auth.uid() = user_id OR 2=2'), true)
  assert.equal(isPermissiveTautology('auth.uid() = owner OR 5 = 5'), true)
  assert.equal(isPermissiveTautology('owner_id = owner_id'), true) // col=col never scopes
  assert.equal(isPermissiveTautology('x OR 0 = 0'), true)
  assert.equal(isPermissiveTautology('scope OR 1 < 2'), true)
  assert.equal(isPermissiveTautology('scope OR 5 >= 5'), true)
  assert.equal(isPermissiveTautology("scope OR 'a' <> 'b'"), true)
  assert.equal(isPermissiveTautology('(( auth.uid() = owner OR 42 = 42 ))'), true) // nested parens
  // NOT tautologies — must stay false
  assert.equal(isPermissiveTautology('a = 1 OR b = 2'), false)
  assert.equal(isPermissiveTautology('x OR 1 = 2'), false) // constant FALSE disjunct
  assert.equal(isPermissiveTautology('owner_id = tenant_id'), false) // different columns
  assert.equal(isPermissiveTautology('auth.uid() = owner AND 1=1'), false) // AND: scope survives
  assert.equal(isPermissiveTautology("org = 'x' OR org = 'y'"), false)
})

test('isPermissiveTautology: NESTED tautology inside a parenthesised OR group is caught', () => {
  assert.equal(isPermissiveTautology('auth.uid() = x OR (a OR 2=2)'), true)
  assert.equal(isPermissiveTautology('auth.uid() = x OR (foo AND bar OR 1=1)'), true)
  assert.equal(isPermissiveTautology('((auth.uid() = owner) OR (7 = 7))'), true)
  // nested but NOT a tautology — scope survives
  assert.equal(isPermissiveTautology('auth.uid() = x OR (a OR b = 1)'), false)
  assert.equal(isPermissiveTautology('auth.uid() = x OR (a AND 2=2)'), false) // AND inside → not always true
})

test('isPermissiveTautology: a constant IN a constant list is always-true', () => {
  // bare and OR-joined to a scope token — both neutralise the scope
  assert.equal(isPermissiveTautology('1 IN (1)'), true)
  assert.equal(isPermissiveTautology('auth.uid() = owner OR 1 IN (1)'), true)
  assert.equal(isPermissiveTautology('1 IN (1, 2)'), true)          // needle present in list
  assert.equal(isPermissiveTautology("'a' IN ('a','b')"), true)
  assert.equal(isPermissiveTautology('auth.uid() = x OR (a OR 1 IN (1))'), true) // nested
  // NOT tautologies — must stay false
  assert.equal(isPermissiveTautology('1 IN (2, 3)'), false)         // needle absent
  assert.equal(isPermissiveTautology('org_id IN (1, 2)'), false)    // left is a column
  assert.equal(isPermissiveTautology('auth.uid() = owner AND 1 IN (1)'), false) // AND: scope holds
  // a real subquery scope (email IN (select … where user_id = auth.uid())) must survive
  assert.equal(
    isScoped('email IN (SELECT email FROM membros WHERE membros.user_id = auth.uid())'),
    true
  )
})

test('isPermissiveTautology: a non-negative built-in >= 0 is always-true', () => {
  assert.equal(isPermissiveTautology('length(x) >= 0'), true)
  assert.equal(isPermissiveTautology('auth.uid() = owner OR length(secret) >= 0'), true)
  assert.equal(isPermissiveTautology('char_length(name) > -1'), true)
  assert.equal(isPermissiveTautology('octet_length(x) <> -1'), true)
  assert.equal(isPermissiveTautology('auth.uid() = x OR (a OR length(y) >= 0)'), true) // nested
  // real length FILTERS are NOT always-true — must stay false
  assert.equal(isPermissiveTautology('length(x) >= 5'), false)
  assert.equal(isPermissiveTautology('length(x) > 0'), false)       // empty string is length 0
  assert.equal(isPermissiveTautology('auth.uid() = owner AND length(x) >= 0'), false) // AND: scope holds
})

test('classifyPolicy: nested/IN/length tautologies for anon → permissive_true (FAIL)', () => {
  for (const qual of [
    'auth.uid() = user_id OR (a=b OR 2=2)', // nested OR
    'auth.uid() = user_id OR 1 IN (1)',     // constant IN
    'auth.uid() = user_id OR length(x) >= 0', // non-negative built-in
  ]) {
    const r = buildResult({
      schema: 'public',
      policies: [policy({ roles: ['anon'], cmd: 'SELECT', qual })],
    })
    assert.deepEqual(kinds(r), ['permissive_true'], `qual should FAIL: ${qual}`)
    assert.equal(r.problems, 1, `qual should be 1 problem: ${qual}`)
    assert.equal(r.passed, false)
  }
})

test('classifyPolicy: a legitimately scoped policy is NOT flagged (no false positive)', () => {
  // the fix must not regress real per-user / helper scopes
  for (const qual of [
    '(auth.uid() = user_id)',
    'belongs_to_org(org_id)',        // still a helper_scoped warn, never a false FAIL
    '(email IN ( SELECT tickets.email FROM membros WHERE (membros.user_id = ( SELECT auth.uid()))))',
  ]) {
    const r = buildResult({
      schema: 'public',
      policies: [policy({ roles: ['anon'], cmd: 'SELECT', qual })],
    })
    assert.equal(r.problems, 0, `qual must not FAIL: ${qual}`)
    assert.ok(
      !kinds(r).includes('permissive_true') && !kinds(r).includes('anon_unscoped'),
      `qual must not be flagged as exposed: ${qual}`
    )
  }
})

test('NEW Critical: OR 2=2 for anon is caught as permissive_true (FAIL)', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['anon'], cmd: 'SELECT', qual: 'auth.uid() = user_id OR 2=2' })],
  })
  assert.deepEqual(kinds(r), ['permissive_true'])
  assert.equal(r.problems, 1)
})

test('a tautology under AND does NOT get flagged (the scope still holds)', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['anon'], cmd: 'SELECT', qual: '(auth.uid() = user_id AND 1=1)' })],
  })
  assert.equal(r.findings.length, 0)
})

test('NEW #1: USING (auth.uid() = user_id OR true) for anon → permissive_true (FAIL)', () => {
  const r = buildResult({
    schema: 'public',
    policies: [policy({ roles: ['anon'], cmd: 'SELECT', qual: 'auth.uid() = user_id OR true' })],
  })
  assert.deepEqual(kinds(r), ['permissive_true'])
  assert.equal(r.problems, 1)
})

// Severity raised from warn to FAIL: a provable tautology for `authenticated`
// means every signed-up user reads every tenant's rows — the textbook IDOR. As a
// warn it could never break a build, so the gate went green on it. Deliberate
// openness (a shared feed, a public directory) is allow-listable.
test('NEW #1: a tautology-scoped read for authenticated is a FAIL, not a warn', () => {
  const r = buildResult({
    schema: 'public',
    allTables: [{ tablename: 't' }],
    policies: [policy({ roles: ['authenticated'], cmd: 'SELECT', qual: 'auth.uid() = owner OR 1=1' })],
  })
  assert.deepEqual(kinds(r), ['permissive_true'])
  assert.equal(r.problems, 1)
  assert.equal(r.passed, false)
})

// …but an unscoped-yet-unprovable qualifier stays a warn: there the scan really
// cannot tell whether the openness is intended.
test('NEW #1b: an unscoped (not provably true) read for authenticated stays a warn', () => {
  const r = buildResult({
    schema: 'public',
    allTables: [{ tablename: 't' }],
    policies: [policy({ roles: ['authenticated'], cmd: 'SELECT', qual: "org = 'acme'" })],
  })
  assert.deepEqual(kinds(r), ['authenticated_unscoped'])
  assert.equal(r.problems, 0)
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

// ---------------------------------------------------------------------------
// THE COMMAND × ROLE × QUALIFIER MATRIX
//
// This exists because the suite tested the PARSER exhaustively (34 hostile
// qualifiers, all caught) while barely testing the MATRIX — and the two
// Criticals lived in the matrix, not the parser: `FOR DELETE` was in no command
// set at all, and `FOR UPDATE` with no WITH CHECK excluded its own worst case.
// Both produced ZERO findings for months. Enumerating every cell would have
// caught them on day one, so the enumeration is now permanent.
// ---------------------------------------------------------------------------
const CMDS = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'ALL']
const ROLES = [['anon'], ['authenticated'], ['public'], ['service_role']]
// Qualifiers that expose everything, in the shapes real SQL takes.
const OPEN_QUALS = ['true', '1=1', '2 > 1', "'a' = 'a'", 'owner_id = owner_id', 'NOT false']
const SCOPED_QUAL = 'owner_id = auth.uid()'

const clientReachable = (roles) => roles.some((r) => r === 'anon' || r === 'authenticated' || r === 'public')

test('#matrix every wide-open policy on a client-reachable role is caught, in every command', () => {
  const misses = []
  for (const cmd of CMDS) {
    for (const roles of ROLES) {
      for (const qual of OPEN_QUALS) {
        // For write commands, omit WITH CHECK: Postgres then applies USING as
        // the check, which is exactly the shape that used to slip through.
        const r = buildResult({
          schema: 'public',
          allTables: [{ tablename: 't' }],
          policies: [{ tablename: 't', policyname: 'p', cmd, roles, qual, with_check: null, permissive: 'PERMISSIVE' }],
        })
        const caught = r.problems > 0
        const shouldCatch = clientReachable(roles)
        if (caught !== shouldCatch) {
          misses.push(`${cmd} TO ${roles.join(',')} USING (${qual}) → ${caught ? 'flagged' : 'MISSED'} (expected ${shouldCatch ? 'flagged' : 'clean'})`)
        }
      }
    }
  }
  assert.deepEqual(misses, [], `matrix gaps:\n  ${misses.join('\n  ')}`)
})

test('#matrix a properly scoped policy is never flagged, in any command or role', () => {
  const falseAlarms = []
  for (const cmd of CMDS) {
    for (const roles of ROLES) {
      const r = buildResult({
        schema: 'public',
        allTables: [{ tablename: 't' }],
        policies: [{ tablename: 't', policyname: 'p', cmd, roles, qual: SCOPED_QUAL, with_check: SCOPED_QUAL, permissive: 'PERMISSIVE' }],
      })
      if (r.problems > 0 || r.warnings > 0) {
        falseAlarms.push(`${cmd} TO ${roles.join(',')} USING (${SCOPED_QUAL}) → ${r.findings.map((f) => f.kind).join(',')}`)
      }
    }
  }
  assert.deepEqual(falseAlarms, [], `false alarms:\n  ${falseAlarms.join('\n  ')}`)
})

// The specific regressions, pinned by name so a future refactor can't quietly
// re-open them.
test('#matrix FOR DELETE USING(true) is a hard fail (the first Critical)', () => {
  for (const roles of [['anon'], ['authenticated'], ['public']]) {
    const r = buildResult({
      schema: 'public',
      allTables: [{ tablename: 'payments' }],
      policies: [{ tablename: 'payments', policyname: 'd', cmd: 'DELETE', roles, qual: 'true', with_check: null, permissive: 'PERMISSIVE' }],
    })
    assert.equal(r.problems, 1, `DELETE TO ${roles[0]} USING(true) must fail`)
    assert.equal(r.passed, false)
  }
})

test('#matrix FOR UPDATE USING(true) with no WITH CHECK is a hard fail (the second Critical)', () => {
  const r = buildResult({
    schema: 'public',
    allTables: [{ tablename: 'payments' }],
    policies: [{ tablename: 'payments', policyname: 'u', cmd: 'UPDATE', roles: ['anon'], qual: 'true', with_check: null, permissive: 'PERMISSIVE' }],
  })
  assert.equal(r.problems, 1, 'omitting WITH CHECK must not be safer than writing it')
  // and the explicit form stays caught too — the two must agree
  const explicit = buildResult({
    schema: 'public',
    allTables: [{ tablename: 'payments' }],
    policies: [{ tablename: 'payments', policyname: 'u', cmd: 'UPDATE', roles: ['anon'], qual: 'true', with_check: 'true', permissive: 'PERMISSIVE' }],
  })
  assert.ok(explicit.problems > 0, 'explicit WITH CHECK(true) must also fail')
})

// ---- Onda 1: the Mediums ----

// classifyPolicy/buildResult are exported and documented as reusable (the
// monitor consumes them). Rows from any source other than pg_policies came in
// with different casing and matched NOTHING — a wide-open policy classified as
// invisible. The author normalized `permissive` and stopped there.
test('#norm cmd and roles are normalized before classification', () => {
  const variants = [
    { cmd: 'select', roles: ['anon'] },
    { cmd: 'SELECT', roles: ['ANON'] },
    { cmd: ' Select ', roles: [' Anon '] },
    { cmd: 'SELECT', roles: ['"anon"'] },
    { cmd: 'delete', roles: ['ANON'] },
  ]
  for (const v of variants) {
    const r = buildResult({
      schema: 'public',
      allTables: [{ tablename: 't' }],
      policies: [{ tablename: 't', policyname: 'p', qual: 'true', with_check: null, permissive: 'PERMISSIVE', ...v }],
    })
    assert.equal(r.problems, 1, `${v.cmd} TO ${v.roles} must be caught regardless of casing`)
  }
  // and a non-client role stays clean whatever its casing
  const svc = buildResult({
    schema: 'public',
    allTables: [{ tablename: 't' }],
    policies: [{ tablename: 't', policyname: 'p', cmd: 'select', roles: ['SERVICE_ROLE'], qual: 'true', with_check: null, permissive: 'PERMISSIVE' }],
  })
  assert.equal(svc.problems, 0)
})

// RLS has no effect on a materialized view at all — there is no policy mechanism
// for them — so a client-role grant is a permanent full dump. pg_tables and the
// relkind='v' query both exclude matviews, so this was a total blind spot.
test('#matview a materialized view readable by a client role is a FAIL', () => {
  const anon = buildResult({
    schema: 'public',
    allTables: [{ tablename: 't' }],
    matviews: [{ matviewname: 'all_payments', anon_select: true, auth_select: true }],
  })
  assert.equal(anon.problems, 1)
  assert.equal(anon.findings[0].kind, 'matview_exposed')
  // authenticated-only is still a fail: there is no security_invoker escape hatch
  const auth = buildResult({
    schema: 'public',
    allTables: [{ tablename: 't' }],
    matviews: [{ matviewname: 'm', anon_select: false, auth_select: true }],
  })
  assert.equal(auth.problems, 1)
  // no client grant → nothing to say
  const none = buildResult({
    schema: 'public',
    allTables: [{ tablename: 't' }],
    matviews: [{ matviewname: 'm', anon_select: false, auth_select: false }],
  })
  assert.equal(none.findings.length, 0)
})

// "Could not read it" and "read it, it's fine" used to produce the same empty
// array. A CI running as a restricted role (good practice) got a green result
// while a public bucket stayed invisible forever.
test('#skipped a check that could not run is reported, not silently dropped', () => {
  const r = buildResult({
    schema: 'public',
    allTables: [{ tablename: 't' }],
    skipped: [{ check: 'storage.buckets', reason: '42501 permission denied for table buckets' }],
  })
  assert.equal(r.warnings, 1)
  assert.equal(r.findings[0].kind, 'check_skipped')
  assert.match(r.findings[0].detail, /UNKNOWN, not clean/)
  // a clean run reports nothing extra
  assert.equal(buildResult({ schema: 'public', allTables: [{ tablename: 't' }] }).warnings, 0)
})

// A generated (or hostile) policy with thousands of OR branches blew the JS
// stack with an uncaught RangeError, killing the entire audit: one bad policy
// took down every other table's result. It must degrade to "unproven" instead.
test('#deep a pathologically deep qualifier degrades to a finding, never a crash', () => {
  const deep = 'true' + ' OR true'.repeat(10000)
  const r = buildResult({
    schema: 'public',
    allTables: [{ tablename: 't' }],
    policies: [{ tablename: 't', policyname: 'p', cmd: 'SELECT', roles: ['anon'], qual: deep, with_check: null, permissive: 'PERMISSIVE' }],
  })
  assert.ok(r.problems >= 1, 'an unanalyzable qualifier must be reported, not skipped')
  assert.equal(r.passed, false)
})

// ── Onda 1 (2ª leva): the Mediums ──

// Policy names are unique PER TABLE in Postgres. Matching the bare name meant
// allow-listing an intentionally-public status page also muted a real finding on
// `payments`, and would keep muting every future table that reused the name.
test('#allow the allow-list can be qualified by table', () => {
  const pols = [
    { tablename: 'status_page', policyname: 'public_read', cmd: 'SELECT', roles: ['anon'], qual: 'true', with_check: null, permissive: 'PERMISSIVE' },
    { tablename: 'payments', policyname: 'public_read', cmd: 'SELECT', roles: ['anon'], qual: 'true', with_check: null, permissive: 'PERMISSIVE' },
  ]
  const base = { schema: 'public', allTables: [{ tablename: 'status_page' }, { tablename: 'payments' }], policies: pols }
  assert.equal(buildResult(base).problems, 2, 'both are open without an allow-list')
  assert.equal(buildResult({ ...base, allow: new Set(['status_page.public_read']) }).problems, 1, 'qualified silences only its own table')

  // The bare name is ambiguous here: two tables carry `public_read`. Honouring
  // it would waive the finding on `payments` too — the very leak the qualified
  // form exists to keep visible. It must not apply, and the author must be told
  // why, or they read a green build as "payments was reviewed".
  const bare = buildResult({ ...base, allow: new Set(['public_read']) })
  assert.equal(bare.problems, 2, 'an ambiguous bare name silences nothing')
  const amb = bare.findings.filter((f) => f.kind === 'allow_ambiguous')
  assert.equal(amb.length, 1, 'the author is told the --allow did not apply')
  assert.match(amb[0].detail, /payments\.public_read/, 'and is shown the qualified form to use')
})

// The bare form stays usable where it is unambiguous — one table, one name.
// Removing that would force qualification on every single-table project.
test('#allow a bare name still applies when only one table carries it', () => {
  const r = buildResult({
    schema: 'public',
    allTables: [{ tablename: 'status_page' }, { tablename: 'payments' }],
    policies: [
      { tablename: 'status_page', policyname: 'public_read', cmd: 'SELECT', roles: ['anon'], qual: 'true', with_check: null, permissive: 'PERMISSIVE' },
      { tablename: 'payments', policyname: 'owner_only', cmd: 'SELECT', roles: ['anon'], qual: 'true', with_check: null, permissive: 'PERMISSIVE' },
    ],
    allow: new Set(['public_read']),
  })
  assert.equal(r.problems, 1, 'the unique bare name applies; the other table is untouched')
  assert.equal(r.findings.filter((f) => f.kind === 'allow_ambiguous').length, 0)
})

// EXISTS is not opaque — its subquery is right there in the parse tree. Treated
// as a "helper we cannot see inside", `EXISTS (SELECT 1 FROM profiles)` — true
// for every row the moment that table has one record — was a soft warn.
test('#exists an uncorrelated EXISTS scopes nothing and is not a helper', () => {
  const R = (qual) => buildResult({
    schema: 'public',
    allTables: [{ tablename: 't' }],
    policies: [{ tablename: 't', policyname: 'p', cmd: 'SELECT', roles: ['anon'], qual, with_check: null, permissive: 'PERMISSIVE' }],
  })
  assert.equal(R('EXISTS (SELECT 1 FROM profiles)').problems, 1, 'no correlation → nothing is scoped → fail')
  // a correlated EXISTS is a legitimate scope and must stay clean
  assert.equal(R('EXISTS (SELECT 1 FROM members m WHERE m.user_id = auth.uid())').findings.length, 0)
  assert.equal(R('EXISTS (SELECT 1 FROM members WHERE user_id = auth.uid() AND org_id = t.org_id)').findings.length, 0)
  // a genuinely opaque helper is still a warn, not a fail
  assert.equal(R('is_public(id)').problems, 0)
  assert.ok(R('is_public(id)').findings.some((f) => f.kind === 'helper_scoped'))
})

// ── Onda 2: os dois Criticals que a re-auditoria encontrou ──

// `pg_policies.roles` is `name[]` (OID 1003) and node-pg has no parser for it,
// so a real database hands back the WIRE STRING `"{anon}"`, never a JS array.
// Every fixture in this file passed roles as an array, which is precisely why
// 101 tests stayed green while the product was a no-op against a real database:
// a payments table with `FOR SELECT TO anon USING (true)` audited clean while
// anon read the rows. Every role assertion must exist in BOTH spellings.
test('#wire roles arrive as a Postgres array literal, not a JS array', () => {
  const R = (roles) =>
    buildResult({
      schema: 'public',
      allTables: [{ tablename: 'payments' }],
      policies: [{ tablename: 'payments', policyname: 'leak', cmd: 'SELECT', roles, qual: 'true', with_check: null, permissive: 'PERMISSIVE' }],
    })
  for (const wire of ['{anon}', '{authenticated}', '{anon,authenticated}', '{public}', '{anon,service_role}'])
    assert.equal(R(wire).problems, 1, `wire form ${wire} must be classified`)
  for (const arr of [['anon'], ['authenticated'], ['anon', 'service_role']])
    assert.equal(R(arr).problems, 1, `array form ${JSON.stringify(arr)} must still work`)
  // and a server-only role stays clean in both spellings
  for (const safe of ['{service_role}', '{postgres}', '{authenticator}', ['service_role']])
    assert.equal(R(safe).problems, 0, `${JSON.stringify(safe)} must not be flagged`)
})

// USING and WITH CHECK answer different questions: USING decides WHICH ROWS may
// be updated, WITH CHECK decides what the new row may look like. The write
// branch only inspected USING when WITH CHECK was absent, so the combination
// `USING (true)` + a CORRECT `WITH CHECK` produced zero findings — and that is a
// full tenant takeover (proven on Postgres: an UPDATE with no WHERE rewrote
// another tenant's rows, each one passing the check because the attacker set
// himself as owner). Writing the correct WITH CHECK blinded the gate.
test('#update an open USING is caught even when WITH CHECK is properly scoped', () => {
  const R = (cmd, qual, wc) =>
    buildResult({
      schema: 'public',
      allTables: [{ tablename: 'notes' }],
      policies: [{ tablename: 'notes', policyname: 'p', cmd, roles: '{authenticated}', qual, with_check: wc, permissive: 'PERMISSIVE' }],
    })
  const SCOPED = 'auth.uid() = owner_id'
  for (const qual of ['true', '1=1', "status = 'published'"])
    assert.equal(R('UPDATE', qual, SCOPED).problems, 1, `UPDATE USING (${qual}) + scoped WITH CHECK must fail`)
  assert.ok(R('ALL', 'true', SCOPED).problems >= 1, 'FOR ALL carries the same exposure')
  // already-covered shapes must not gain a duplicate finding
  assert.equal(R('UPDATE', 'true', 'true').findings.length, 1)
  assert.equal(R('UPDATE', 'true', null).findings.length, 1)
  // and a genuinely scoped policy stays clean
  assert.equal(R('UPDATE', SCOPED, SCOPED).findings.length, 0)
})
