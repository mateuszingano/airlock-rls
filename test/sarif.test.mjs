// SARIF 2.1.0 + GitHub annotations (`--sarif`, `--format github`).
// The SARIF log is validated against the official OASIS schema (vendored in
// test/fixtures, draft-04) with ajv — devDependencies only, nothing at runtime.
import { test, before } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, mkdtempSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'
import { toSarif, toGithubAnnotations, ruleFor, levelFor, emitGithubOutputs } from '../src/sarif.mjs'

const require = createRequire(import.meta.url)
const Ajv = require('ajv-draft-04')
const addFormats = require('ajv-formats')
const ajv = new Ajv({ allErrors: true, strict: false })
addFormats(ajv)
const SCHEMA = JSON.parse(readFileSync(fileURLToPath(new URL('./fixtures/sarif-schema-2.1.0.json', import.meta.url)), 'utf8'))
const validate = ajv.compile(SCHEMA)
function assertValidSarif(log) {
  const ok = validate(log)
  assert.ok(ok, 'SARIF does not match the official 2.1.0 schema: ' + JSON.stringify(validate.errors, null, 2))
}

const DB_RESULT = {
  schema: 'public',
  findings: [
    { kind: 'rls_disabled', severity: 'fail', object: 'payments', detail: 'table in "public" has RLS DISABLED', fixPrompt: 'Enable RLS...' },
    { kind: 'permissive_true', severity: 'fail', object: 'notes."read all"', detail: '[SELECT] USING(true) — anon reads every row' },
    { kind: 'permissive_true', severity: 'fail', object: 'docs."open"', detail: '[SELECT] USING(true)' },
    { kind: 'storage_permissive_true', severity: 'fail', object: 'storage.objects."open"', detail: 'x' },
    { kind: 'bypassrls_role', severity: 'warn', object: 'role:hardening_bypass', detail: 'role has BYPASSRLS' },
    { kind: 'some_future_kind', severity: 'info', object: 'thing', detail: 'y' },
  ],
}

test('#sarif a DB-mode result is valid SARIF 2.1.0 (official schema)', () => {
  const log = toSarif(DB_RESULT, { version: '9.9.9' })
  assertValidSarif(log)
  assert.equal(log.version, '2.1.0')
  const run = log.runs[0]
  assert.equal(run.tool.driver.name, 'airlock-rls')
  assert.equal(run.tool.driver.version, '9.9.9')
  assert.equal(run.results.length, DB_RESULT.findings.length)
})

test('#sarif the schema check is real: a broken log is rejected', () => {
  const log = toSarif(DB_RESULT)
  delete log.runs[0].tool.driver.name
  log.runs[0].results[0].level = 'critical'
  assert.equal(validate(log), false)
})

test('#sarif one rule per kind, results point at it by ruleId + ruleIndex', () => {
  const run = toSarif(DB_RESULT).runs[0]
  const ids = run.tool.driver.rules.map((r) => r.id)
  assert.deepEqual(ids, ['rls_disabled', 'permissive_true', 'storage_permissive_true', 'bypassrls_role', 'some_future_kind'])
  for (const r of run.results) assert.equal(run.tool.driver.rules[r.ruleIndex].id, r.ruleId)
  for (const rule of run.tool.driver.rules) {
    assert.ok(rule.shortDescription.text && rule.fullDescription.text && rule.helpUri)
  }
})

test('#sarif levels: fail → error, warn → warning, other → note', () => {
  assert.equal(levelFor('fail'), 'error')
  assert.equal(levelFor('warn'), 'warning')
  assert.equal(levelFor('info'), 'note')
  const levels = toSarif(DB_RESULT).runs[0].results.map((r) => r.level)
  assert.deepEqual(levels, ['error', 'error', 'error', 'error', 'warning', 'note'])
})

test('#sarif DB findings get a logicalLocation (schema-qualified), never a fake file', () => {
  const [payments, notes, , , role] = toSarif(DB_RESULT).runs[0].results
  assert.equal(payments.locations[0].physicalLocation, undefined)
  assert.equal(payments.locations[0].logicalLocations[0].fullyQualifiedName, 'public.payments')
  assert.equal(notes.locations[0].logicalLocations[0].fullyQualifiedName, 'notes."read all"')
  assert.equal(role.locations[0].logicalLocations[0].fullyQualifiedName, 'role:hardening_bypass')
  assert.equal(payments.message.text, 'payments: table in "public" has RLS DISABLED')
})

test('#sarif a finding with file/line becomes a physicalLocation (forward slashes, line >= 1)', () => {
  const log = toSarif({
    schema: 'public',
    findings: [
      { kind: 'rls_disabled', severity: 'fail', object: 'orders', detail: 'RLS off', file: 'supabase\\migrations\\20260101_init.sql', line: 12 },
      { kind: 'permissive_true', severity: 'fail', object: 'notes."all"', detail: 'x', file: './supabase/migrations/a.sql' },
    ],
  })
  assertValidSarif(log)
  const [a, b] = log.runs[0].results
  assert.deepEqual(a.locations[0].physicalLocation, { artifactLocation: { uri: 'supabase/migrations/20260101_init.sql' }, region: { startLine: 12 } })
  assert.equal(b.locations[0].physicalLocation.artifactLocation.uri, 'supabase/migrations/a.sql')
  assert.equal(b.locations[0].physicalLocation.region.startLine, 1)
})

test('#sarif stable fingerprints and the fix prompt travel as properties', () => {
  const r1 = toSarif(DB_RESULT).runs[0].results
  const r2 = toSarif(DB_RESULT).runs[0].results
  assert.equal(r1[0].partialFingerprints['airlockFinding/v1'], r2[0].partialFingerprints['airlockFinding/v1'])
  assert.notEqual(r1[1].partialFingerprints['airlockFinding/v1'], r1[2].partialFingerprints['airlockFinding/v1'])
  assert.equal(r1[0].properties.fixPrompt, 'Enable RLS...')
  assert.equal(r1[1].properties, undefined)
})

test('#sarif an empty / passing result is still a valid log with zero results', () => {
  const log = toSarif({ schema: 'public', findings: [] })
  assertValidSarif(log)
  assert.deepEqual(log.runs[0].results, [])
  assert.deepEqual(log.runs[0].tool.driver.rules, [])
})

test('#sarif storage_ rules say they are Storage policies; site kinds link to the site-scan docs', () => {
  assert.match(ruleFor('storage_permissive_true').shortDescription.text, /Storage policy/)
  assert.match(ruleFor('env_file_exposed').helpUri, /scan-a-deployed-site/)
  assert.match(ruleFor('rls_disabled').helpUri, /#what-it-checks$/)
})

test('#github annotations: one workflow command per finding, escaped, file/line when present', () => {
  const lines = toGithubAnnotations({
    findings: [
      { kind: 'rls_disabled', severity: 'fail', object: 'orders', detail: 'RLS off, 100% exposed\nsecond line', file: 'supabase/migrations/a,b.sql', line: 3 },
      { kind: 'bypassrls_role', severity: 'warn', object: 'role:x', detail: 'has BYPASSRLS' },
      { kind: 'odd', severity: 'info', object: 'o', detail: 'd' },
    ],
  })
  assert.equal(lines[0], '::error file=supabase/migrations/a%2Cb.sql,line=3,title=airlock%3A rls_disabled::orders: RLS off, 100%25 exposed%0Asecond line')
  assert.equal(lines[1], '::warning title=airlock%3A bypassrls_role::role:x: has BYPASSRLS')
  assert.match(lines[2], /^::notice /)
})

test('#github emitGithubOutputs skips annotations under --json and writes the SARIF file', () => {
  const out = []
  const dir = mkdtempSync(join(tmpdir(), 'airlock-sarif-'))
  const file = join(dir, 'nested', 'airlock.sarif')
  emitGithubOutputs(DB_RESULT, { sarif: file, format: 'github', json: true, log: (s) => out.push(s) })
  assert.deepEqual(out, [])
  assert.ok(existsSync(file))
  assertValidSarif(JSON.parse(readFileSync(file, 'utf8')))
  emitGithubOutputs(DB_RESULT, { format: 'github', log: (s) => out.push(s) })
  assert.equal(out.length, DB_RESULT.findings.length)
})

// ---------------------------------------------------------------------------
// CLI, end to end. Usage errors run offline; the real-DB run is gated.
// ---------------------------------------------------------------------------
const BIN = fileURLToPath(new URL('../bin/airlock.mjs', import.meta.url))
const cli = (args, env = {}) =>
  spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', env: { ...process.env, SUPABASE_DB_URL: '', SUPABASE_SITE_URL: '', ...env } })

test('#cli --format with a bad value and --sarif without a path are usage errors (exit 2)', () => {
  const a = cli(['--format', 'xml'])
  assert.equal(a.status, 2)
  assert.match(a.stderr, /Invalid --format "xml"/)
  const b = cli(['--sarif'])
  assert.equal(b.status, 2)
  assert.match(b.stderr, /--sarif needs a file path/)
})

const DB_URL = process.env.AIRLOCK_TEST_DB_URL || process.env.DATABASE_URL
const gate = { skip: DB_URL ? false : 'no AIRLOCK_TEST_DB_URL / DATABASE_URL — skipping SARIF CLI integration test' }

// Own schema, so it can't race the fixtures other test files load in parallel.
const SQL = `
do $$ begin create role anon nologin; exception when duplicate_object then null; end $$;
do $$ begin create role authenticated nologin; exception when duplicate_object then null; end $$;
drop schema if exists sarif_app cascade;
create schema sarif_app;
grant usage on schema sarif_app to anon, authenticated;
create table sarif_app.ledger (id int primary key, amount int);
create table sarif_app.notes (id int primary key, body text);
alter table sarif_app.notes enable row level security;
create policy "read all" on sarif_app.notes for select using (true);
grant select on sarif_app.ledger, sarif_app.notes to anon, authenticated;
`

before(async () => {
  if (gate.skip) return
  const { default: pg } = await import('pg')
  const c = new pg.Client({ connectionString: DB_URL })
  await c.connect()
  try {
    await c.query(SQL)
  } finally {
    await c.end()
  }
})

test('#cli real DB: --sarif + --format github keep the report and exit code, write a valid log', gate, () => {
  const dir = mkdtempSync(join(tmpdir(), 'airlock-sarif-cli-'))
  const file = join(dir, 'airlock.sarif')
  const plain = cli([DB_URL, '--schema', 'sarif_app'])
  const r = cli([DB_URL, '--schema', 'sarif_app', '--sarif', file, '--format', 'github'])
  assert.equal(plain.status, 1)
  assert.equal(r.status, 1, 'exit code must not change')
  assert.match(r.stdout, /^::error title=airlock%3A rls_disabled::ledger: /m)
  assert.match(r.stdout, /^::error title=airlock%3A permissive_true::notes\."read all": /m)
  assert.match(r.stdout, /RLS audit failed/, 'the human report still prints')
  const log = JSON.parse(readFileSync(file, 'utf8'))
  assertValidSarif(log)
  const kinds = log.runs[0].results.map((x) => x.ruleId)
  assert.ok(kinds.includes('rls_disabled') && kinds.includes('permissive_true'))
  const ledger = log.runs[0].results.find((x) => x.ruleId === 'rls_disabled')
  assert.equal(ledger.locations[0].logicalLocations[0].fullyQualifiedName, 'sarif_app.ledger')
  // --json stays parseable with --format github.
  const j = cli([DB_URL, '--schema', 'sarif_app', '--json', '--format', 'github'])
  assert.equal(j.status, 1)
  assert.doesNotThrow(() => JSON.parse(j.stdout))
})
