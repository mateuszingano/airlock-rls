// --fix-sql round-trip against a REAL Postgres: audit a schema full of hostile
// names, apply the generated draft migration, audit again. Every mechanical
// finding must be gone, the USING (true) policy must still be there (it is a
// TODO, never rewritten), and the migration must apply cleanly (bad quoting
// would make it fail). Gated like integration.test.mjs.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { audit } from '../src/audit.mjs'
import { buildFixSql } from '../src/fix-sql.mjs'

const DB_URL = process.env.AIRLOCK_TEST_DB_URL || process.env.DATABASE_URL
const gate = { skip: DB_URL ? false : 'no AIRLOCK_TEST_DB_URL / DATABASE_URL — skipping integration test' }

async function run(sql) {
  const { default: pg } = await import('pg')
  const client = new pg.Client({ connectionString: DB_URL })
  await client.connect()
  try {
    await client.query(sql)
  } finally {
    await client.end()
  }
}

test('fix-sql: the draft applies cleanly and clears every mechanical finding', gate, async () => {
  await run(await readFile(fileURLToPath(new URL('./fixtures/fixsql.sql', import.meta.url)), 'utf8'))
  const schema = 'Fix Me'
  const before = await audit({ dbUrl: DB_URL, schema })
  const kinds = (r) => new Set(r.findings.map((f) => f.kind))
  for (const k of ['rls_disabled', 'permissive_true', 'anon_executes_definer', 'definer_search_path_mutable',
    'view_bypasses_rls', 'matview_exposed', 'owner_bypasses_rls']) {
    assert.ok(kinds(before).has(k), `fixture should produce ${k}`)
  }

  const { sql, statements } = buildFixSql(before, { version: 'test' })
  assert.ok(statements >= 6, `expected >= 6 statements, got ${statements}`)
  await run(sql) // throws if any identifier is quoted wrong

  const after = await audit({ dbUrl: DB_URL, schema })
  for (const k of ['rls_disabled', 'anon_executes_definer', 'definer_search_path_mutable',
    'view_bypasses_rls', 'matview_exposed', 'owner_bypasses_rls']) {
    assert.ok(!kinds(after).has(k), `${k} should be gone after applying the draft`)
  }
  // The policy is a decision, never rewritten: still there.
  assert.ok(kinds(after).has('permissive_true'), 'USING (true) policy must survive (TODO only)')
})
