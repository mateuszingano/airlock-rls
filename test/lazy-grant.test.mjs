// default_privileges_to_api_roles: the latent footprint of silencing the
// post-Oct-30 42501 errors with ALTER DEFAULT PRIVILEGES ... TO anon.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildResult } from '../src/audit.mjs'
import { fixPromptFor } from '../src/fix-prompts.mjs'

const T = [{ tablename: 'notes' }]
const acl = (owner, grantee, privilege_type, nspname = 'public') => ({ owner, nspname, grantee, privilege_type })
const kinds = (r) => r.findings.map((f) => f.kind)

test('#lazygrant postgres defaults to anon/authenticated are one warn per owner+schema, writes called out', () => {
  const r = buildResult({
    schema: 'public',
    allTables: T,
    defaultAcls: [
      acl('postgres', 'anon', 'SELECT'), acl('postgres', 'anon', 'INSERT'),
      acl('postgres', 'authenticated', 'SELECT'), acl('postgres', 'authenticated', 'DELETE'),
    ],
  })
  const f = r.findings.filter((x) => x.kind === 'default_privileges_to_api_roles')
  assert.equal(f.length, 1)
  assert.equal(f[0].severity, 'warn')
  assert.equal(f[0].object, 'defaults:postgres')
  assert.match(f[0].detail, /readable AND writable/)
  assert.match(f[0].detail, /anon: INSERT, SELECT/)
  assert.match(f[0].detail, /in schema "public"/)
  assert.equal(r.passed, true) // a warn: the gate stays green unless --fail-on warn
})

test('#lazygrant Supabase-managed owners (supabase_admin, supabase_*, pg_*) are never flagged', () => {
  const r = buildResult({
    schema: 'public',
    allTables: T,
    defaultAcls: [
      acl('supabase_admin', 'anon', 'SELECT'), acl('supabase_admin', 'authenticated', 'INSERT'),
      acl('supabase_storage_admin', 'anon', 'SELECT'), acl('pg_database_owner', 'anon', 'SELECT'),
      acl('service_role', 'anon', 'SELECT'),
    ],
  })
  assert.ok(!kinds(r).includes('default_privileges_to_api_roles'))
})

test('#lazygrant service_role or other grantees are ignored; PUBLIC counts', () => {
  const r1 = buildResult({ schema: 'public', allTables: T, defaultAcls: [acl('postgres', 'service_role', 'INSERT')] })
  assert.ok(!kinds(r1).includes('default_privileges_to_api_roles'))
  const r2 = buildResult({ schema: 'public', allTables: T, defaultAcls: [acl('app_owner', 'public', 'SELECT', null)] })
  const f = r2.findings.find((x) => x.kind === 'default_privileges_to_api_roles')
  assert.match(f.detail, /PUBLIC: SELECT/)
  assert.match(f.detail, /in every schema/)
  assert.match(f.detail, / readable by the API/)
  assert.doesNotMatch(f.detail, /writable/)
})

test('#lazygrant defaults:<owner> waives it, and is not reported as an unused waiver', () => {
  const r = buildResult({
    schema: 'public', allTables: T, allow: ['defaults:postgres'],
    defaultAcls: [acl('postgres', 'anon', 'SELECT')],
  })
  assert.ok(!kinds(r).includes('default_privileges_to_api_roles'))
  assert.ok(!kinds(r).includes('allow_unused'))
  assert.equal(r.allowed.filter((f) => f.kind === 'default_privileges_to_api_roles').length, 1)
})

test('#lazygrant has a fix prompt', () => {
  const p = fixPromptFor({ kind: 'default_privileges_to_api_roles', severity: 'warn', object: 'defaults:postgres', detail: 'x' })
  assert.match(p, /ALTER DEFAULT PRIVILEGES/)
  assert.match(p, /Do not fix this by disabling Row Level Security/)
})
