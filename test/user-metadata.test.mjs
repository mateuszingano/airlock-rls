// Rule policy_trusts_user_metadata: unit tests on the detector and the
// classifier (no database). The live-DB proof is in
// user-metadata.integration.test.mjs.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { trustsUserMetadata, bodyTrustsUserMetadata } from '../src/user-metadata.mjs'
import { buildResult, classifyUserMetadata } from '../src/audit.mjs'

// pg_policies deparses with casts; test both the raw and the deparsed spelling.
const ADMIN_JWT = "((auth.jwt() -> 'user_metadata'::text) ->> 'role'::text) = 'admin'::text"
const TENANT_JWT = "org_id = (((auth.jwt() -> 'user_metadata'::text) ->> 'org_id'::text))::uuid"
const PATH_JWT = "(auth.jwt() #>> '{user_metadata,role}'::text[]) = 'admin'::text"
const SETTING = "((current_setting('request.jwt.claims', true))::json -> 'user_metadata' ->> 'role') = 'admin'"
const SUBSELECT = "(EXISTS ( SELECT 1 FROM auth.users u WHERE ((u.id = auth.uid()) AND ((u.raw_user_meta_data ->> 'role'::text) = 'admin'::text))))"
const APP_META = "org_id = (((auth.jwt() -> 'app_metadata'::text) ->> 'org_id'::text))::uuid"
const RAW_APP = "(EXISTS ( SELECT 1 FROM auth.users u WHERE ((u.id = auth.uid()) AND ((u.raw_app_meta_data ->> 'role'::text) = 'admin'::text))))"
const STRING_ONLY = "((owner = auth.uid()) AND (note <> 'user_metadata'::text) AND (tag <> 'raw_user_meta_data'))"
const DATA_COL = "((owner = auth.uid()) AND ((data -> 'user_metadata'::text) IS NOT NULL))"

test('#user_metadata detector fires on every user_metadata shape', () => {
  for (const q of [ADMIN_JWT, TENANT_JWT, PATH_JWT, SETTING, SUBSELECT]) {
    assert.ok(trustsUserMetadata(q), `expected a hit on: ${q}`)
  }
  assert.equal(trustsUserMetadata(SUBSELECT), 'auth.users.raw_user_meta_data')
})

test('#user_metadata detector stays quiet on app_metadata, string literals and other JSON columns', () => {
  for (const q of [APP_META, RAW_APP, STRING_ONLY, DATA_COL, 'true', "user_id = auth.uid()", null, '']) {
    assert.equal(trustsUserMetadata(q), null, `false positive on: ${q}`)
  }
})

test('#user_metadata body match strips SQL comments', () => {
  assert.ok(bodyTrustsUserMetadata("select (raw_user_meta_data ->> 'role') = 'admin' from auth.users"))
  assert.ok(bodyTrustsUserMetadata("return auth.jwt() -> 'user_metadata' ->> 'role' = 'admin';"))
  assert.equal(bodyTrustsUserMetadata("-- never read raw_user_meta_data\nreturn auth.jwt() -> 'app_metadata' ->> 'role' = 'admin';"), null)
  assert.equal(bodyTrustsUserMetadata("/* user_metadata is user-editable: -> 'user_metadata' */ select 1"), null)
})

const pol = (over) => ({ tablename: 't', policyname: 'p', cmd: 'SELECT', roles: ['authenticated'], qual: null, with_check: null, permissive: 'PERMISSIVE', ...over })
const allGrants = { anon: new Set(['SELECT']), authenticated: new Set(['SELECT', 'INSERT', 'UPDATE', 'DELETE']) }

test('#user_metadata a permissive policy is a FAIL, including the tenant shape that looks scoped', () => {
  for (const qual of [ADMIN_JWT, TENANT_JWT, SUBSELECT]) {
    const [f] = classifyUserMetadata(pol({ qual }), { grants: allGrants })
    assert.equal(f.kind, 'policy_trusts_user_metadata')
    assert.equal(f.severity, 'fail')
    assert.equal(f.object, 't."p"')
  }
  // WITH CHECK alone is enough (an INSERT gated by a forged role).
  const [w] = classifyUserMetadata(pol({ cmd: 'INSERT', with_check: ADMIN_JWT }), { grants: allGrants })
  assert.equal(w.severity, 'fail')
})

test('#user_metadata the tenant shape used to pass green; now the audit fails', () => {
  const r = buildResult({ schema: 'public', policies: [pol({ qual: TENANT_JWT })], allTables: [{ tablename: 't' }] })
  assert.equal(r.passed, false)
  assert.deepEqual(r.findings.map((f) => f.kind), ['policy_trusts_user_metadata'])
})

test('#user_metadata restrictive policies: trusting one is a warn; only an honest restrictive downgrades', () => {
  const [r] = classifyUserMetadata(pol({ qual: ADMIN_JWT, permissive: 'RESTRICTIVE' }), { grants: allGrants })
  assert.equal(r.severity, 'warn')
  const honest = pol({ policyname: 'own', qual: 'user_id = auth.uid()', permissive: 'RESTRICTIVE' })
  const [d] = classifyUserMetadata(pol({ qual: ADMIN_JWT }), { grants: allGrants, restrictives: [honest] })
  assert.equal(d.severity, 'warn')
  // A restrictive that itself trusts user_metadata does NOT rescue the permissive one.
  const dishonest = pol({ policyname: 'tenant', qual: TENANT_JWT, permissive: 'RESTRICTIVE' })
  const [k] = classifyUserMetadata(pol({ qual: ADMIN_JWT }), { grants: allGrants, restrictives: [dishonest] })
  assert.equal(k.severity, 'fail')
})

test('#user_metadata quiet when authenticated cannot reach it: anon-only policy, or no grant', () => {
  assert.deepEqual(classifyUserMetadata(pol({ qual: ADMIN_JWT, roles: ['anon'] }), { grants: allGrants }), [])
  const noGrant = { anon: new Set(), authenticated: new Set() }
  assert.deepEqual(classifyUserMetadata(pol({ qual: ADMIN_JWT }), { grants: noGrant }), [])
  // PUBLIC includes authenticated.
  assert.equal(classifyUserMetadata(pol({ qual: ADMIN_JWT, roles: ['public'] }), { grants: allGrants }).length, 1)
})

test('#user_metadata respects --allow (qualified policy name)', () => {
  const r = buildResult({ schema: 'public', policies: [pol({ qual: TENANT_JWT })], allTables: [{ tablename: 't' }], allow: ['t.p'] })
  assert.equal(r.passed, true)
  assert.ok(r.allowed.some((f) => f.kind === 'policy_trusts_user_metadata'))
})

test('#user_metadata storage policies are prefixed like every other storage finding', () => {
  const r = buildResult({ schema: 'public', storagePolicies: [pol({ policyname: 'avatars admin', qual: ADMIN_JWT })] })
  assert.ok(r.findings.some((f) => f.kind === 'storage_policy_trusts_user_metadata' && f.severity === 'fail'), JSON.stringify(r.findings))
})

test('#user_metadata a client-callable definer body is a warn; uncallable or no prosrc stays quiet', () => {
  const body = "select coalesce((select (u.raw_user_meta_data ->> 'role') = 'admin' from auth.users u where u.id = auth.uid()), false)"
  const r = buildResult({ schema: 'public', secDefFns: [{ proname: 'is_admin', proconfig: ['search_path='], prosrc: body, anon_exec: false, auth_exec: true }] })
  const f = r.findings.find((x) => x.kind === 'policy_trusts_user_metadata')
  assert.equal(f.severity, 'warn')
  assert.equal(f.object, 'fn:is_admin')
  const quiet = buildResult({ schema: 'public', secDefFns: [{ proname: 'is_admin', proconfig: ['search_path='], prosrc: body, anon_exec: false, auth_exec: false }] })
  assert.ok(!quiet.findings.some((x) => x.kind === 'policy_trusts_user_metadata'))
  const old = buildResult({ schema: 'public', secDefFns: [{ proname: 'is_admin', proconfig: ['search_path='], anon_exec: false, auth_exec: true }] })
  assert.ok(!old.findings.some((x) => x.kind === 'policy_trusts_user_metadata'))
})
