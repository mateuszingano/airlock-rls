// Integration test — runs the REAL audit() against a REAL Postgres.
//
// The unit tests exercise the pure classifier (buildResult) with hand-built
// rows. This test proves the other half: that the SQL in audit() actually reads
// pg_tables / pg_policies / grants from a live database and that the classifier
// then reaches the right verdict end-to-end.
//
// GATED: it only runs when a database URL is provided, so the offline
// `npm test` stays green with no database. Provide one of:
//   AIRLOCK_TEST_DB_URL   (preferred, explicit)
//   DATABASE_URL
// e.g. AIRLOCK_TEST_DB_URL=postgresql://postgres:postgres@127.0.0.1:5432/postgres
//
// In CI the `integration` job in .github/workflows/test.yml stands up a Postgres
// service container and sets AIRLOCK_TEST_DB_URL for this file.

import { test, before } from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { audit } from '../src/audit.mjs'

const DB_URL = process.env.AIRLOCK_TEST_DB_URL || process.env.DATABASE_URL
const gate = { skip: DB_URL ? false : 'no AIRLOCK_TEST_DB_URL / DATABASE_URL — skipping integration test' }

/** Swap the userinfo of a Postgres URL, keeping host/port/db/params intact. */
function withUser(url, user, password) {
  const u = new URL(url)
  u.username = user
  u.password = password
  return u.href
}

async function loadFixture(name) {
  const sql = await readFile(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)), 'utf8')
  const { default: pg } = await import('pg')
  const client = new pg.Client({ connectionString: DB_URL })
  await client.connect()
  try {
    await client.query(sql)
  } finally {
    await client.end()
  }
}

before(async () => {
  if (gate.skip) return
  await loadFixture('leaky.sql')
  await loadFixture('clean.sql')
})

test('leaky schema: audit() fails and classifies both leaks', gate, async () => {
  const result = await audit({ dbUrl: DB_URL, schema: 'app' })

  assert.equal(result.passed, false, 'leaky schema must not pass')
  assert.ok(result.problems >= 2, `expected >= 2 fails, got ${result.problems}`)

  const byKind = (k) => result.findings.filter((f) => f.severity === 'fail' && f.kind === k)

  // LEAK 1: payments has RLS off.
  const rlsOff = byKind('rls_disabled')
  assert.ok(
    rlsOff.some((f) => f.object === 'payments'),
    `expected an rls_disabled fail on "payments", got: ${JSON.stringify(rlsOff)}`
  )

  // LEAK 2: notes."read all" is USING(true), readable by anon (with the grant).
  const permissive = byKind('permissive_true')
  assert.ok(
    permissive.some((f) => f.object.startsWith('notes.')),
    `expected a permissive_true fail on "notes", got: ${JSON.stringify(permissive)}`
  )

  // CONTROL: profiles is scoped by auth.uid() → must NOT be a fail.
  const profilesFails = result.findings.filter((f) => f.severity === 'fail' && /(^|\W)profiles(\W|$)/.test(f.object))
  assert.equal(profilesFails.length, 0, `scoped "profiles" must not fail, got: ${JSON.stringify(profilesFails)}`)
})

test('clean schema: audit() passes (no fail-severity findings)', gate, async () => {
  const result = await audit({ dbUrl: DB_URL, schema: 'clean_app' })

  assert.equal(result.passed, true, `clean schema must pass, fails: ${JSON.stringify(result.findings.filter((f) => f.severity === 'fail'))}`)
  assert.equal(result.problems, 0)
})

// C1 (re-auditoria 20/07) — the whole gate went GREEN when the audit ran as a
// least-privilege role that is NOT a member of anon/authenticated, because
// information_schema.role_table_grants only returns rows the caller can "see".
// The README tells users to use exactly such a role. has_table_privilege()
// answers from the catalog regardless of the caller, so the leak must still be
// caught. This runs as `airlock_restricted`, created by restricted-role.sql.
test('C1: a leak is still caught when the audit runs as a restricted role', gate, async () => {
  await loadFixture('restricted-role.sql')

  // Re-point the connection at the restricted login, keeping host/port/db.
  const restrictedUrl = withUser(DB_URL, 'airlock_restricted', 'restricted')
  const result = await audit({ dbUrl: restrictedUrl, schema: 'app' })

  // The notes leak (permissive USING(true) readable by anon) is grant-dependent:
  // it is exactly what the old query hid. It MUST still be a fail here.
  const notesLeak = result.findings.filter(
    (f) => f.severity === 'fail' && f.kind === 'permissive_true' && f.object.startsWith('notes.')
  )
  assert.ok(
    notesLeak.length > 0,
    `the anon-readable notes leak must be caught even as a restricted role, got: ${JSON.stringify(
      result.findings.map((f) => ({ k: f.kind, o: f.object, s: f.severity }))
    )}`
  )
  assert.equal(result.passed, false, 'a restricted-role audit of a leaky schema must not pass')
})
