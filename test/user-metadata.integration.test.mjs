// Integration test for policy_trusts_user_metadata — the REAL audit() against a
// REAL Postgres, so the deparsed pg_policies text (casts and all) and the
// prosrc query are what the rule actually sees. Gated like integration.test.mjs.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { audit } from '../src/audit.mjs'

const DB_URL = process.env.AIRLOCK_TEST_DB_URL || process.env.DATABASE_URL
const gate = { skip: DB_URL ? false : 'no AIRLOCK_TEST_DB_URL / DATABASE_URL — skipping integration test' }

test('user_metadata: forged-role and forged-tenant policies fail; app_metadata and literals stay quiet', gate, async () => {
  const sql = await readFile(fileURLToPath(new URL('./fixtures/user-metadata.sql', import.meta.url)), 'utf8')
  const { default: pg } = await import('pg')
  const client = new pg.Client({ connectionString: DB_URL })
  await client.connect()
  try {
    await client.query(sql)
  } finally {
    await client.end()
  }

  const result = await audit({ dbUrl: DB_URL, schema: 'usermeta' })
  const um = result.findings.filter((f) => f.kind === 'policy_trusts_user_metadata')
  const by = (obj) => um.find((f) => f.object === obj)

  assert.equal(by('admin_notes."admins read"')?.severity, 'fail', JSON.stringify(um))
  assert.equal(by('tenant_docs."tenant read"')?.severity, 'fail', JSON.stringify(um))
  assert.equal(by('reports."admin via users"')?.severity, 'fail', JSON.stringify(um))
  assert.equal(by('billing."paid only"')?.severity, 'warn', JSON.stringify(um))
  assert.equal(by('fn:is_admin')?.severity, 'warn', JSON.stringify(um))

  for (const quiet of ['app_docs."tenant via app_metadata"', 'notes."own notes"', 'anon_only."anon meta"', 'fn:is_admin_safe']) {
    assert.equal(by(quiet), undefined, `false positive on ${quiet}: ${JSON.stringify(um)}`)
  }
  assert.equal(um.length, 5, JSON.stringify(um))
  assert.equal(result.passed, false)
})
