// No-database mode: `airlock migrations`. Pure parts (SQL splitting, statement
// classification, file:line lookup) plus end-to-end runs on the embedded
// Postgres (PGlite) — no external database needed, so these always run.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import {
  splitSql,
  classifyStatement,
  extensionName,
  locatorFor,
  attachLocations,
  auditMigrations,
  MigrationsUsageError,
} from '../src/migrations.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const FIX = (name) => path.join(here, 'fixtures', name)
const CLI = path.join(here, '..', 'bin', 'airlock.mjs')

// ---------------------------------------------------------------- splitSql

test('#migrations splitSql splits on top-level ; and keeps the start line', () => {
  const sql = [
    '-- header comment',
    '/* block',
    '   comment; with a semicolon */',
    "create table a (x text default 'a;b');",
    '',
    'create function f() returns int as $$ begin return 1; end $$ language plpgsql;',
    'select "odd;name" from a;',
  ].join('\n')
  const st = splitSql(sql)
  assert.deepEqual(st.map((s) => s.line), [4, 6, 7])
  assert.equal(st[0].sql, "create table a (x text default 'a;b')") // leading comments dropped
  assert.match(st[1].sql, /return 1; end \$\$ language plpgsql$/)
  assert.equal(st[2].sql, 'select "odd;name" from a')
})

test('#migrations splitSql handles tagged dollar quotes, nested comments, E-strings and $1', () => {
  const sql =
    "do $body$ begin perform 'x;y'; raise notice $$a;b$$; end $body$;\n" +
    '/* outer /* inner; */ still comment; */ select 1;\n' +
    "select E'it\\'s; fine', 'it''s; fine';\n" +
    'prepare p as select $1;\n'
  const st = splitSql(sql)
  assert.equal(st.length, 4)
  assert.match(st[0].sql, /^do \$body\$/)
  assert.equal(st[1].sql, 'select 1')
  assert.equal(st[2].line, 3)
  assert.equal(st[3].sql, 'prepare p as select $1')
})

test('#migrations splitSql counts lines inside multi-line strings and bodies', () => {
  const st = splitSql("create function g() returns text as $$\nselect 'a\nb'\n$$ language sql;\n\ncreate table t (id int);")
  assert.equal(st[1].line, 6)
  assert.deepEqual(splitSql('   \n -- only a comment\n'), [])
})

// ---------------------------------------------------------- classification

test('#migrations classifyStatement / extensionName', () => {
  assert.equal(classifyStatement('BEGIN'), 'txn')
  assert.equal(classifyStatement('commit'), 'txn')
  assert.equal(classifyStatement('start transaction'), 'txn')
  assert.equal(classifyStatement('\\connect postgres'), 'meta')
  assert.equal(classifyStatement('create extension if not exists "uuid-ossp" with schema extensions'), 'extension')
  assert.equal(classifyStatement('create table begin_log (id int)'), 'sql')
  assert.equal(extensionName('create extension if not exists "uuid-ossp" with schema extensions'), 'uuid-ossp')
  assert.equal(extensionName('CREATE EXTENSION pg_net'), 'pg_net')
})

// ----------------------------------------------------------- file:line map

test('#migrations locatorFor + attachLocations map each object kind to its statement', () => {
  const applied = [
    { file: 'm/1.sql', line: 3, sql: 'create table if not exists public."profiles" (id uuid)' },
    { file: 'm/1.sql', line: 9, sql: 'create policy "read all" on public.notes for select using (true)' },
    { file: 'm/2.sql', line: 1, sql: 'create policy "read all" on public.notes for select using (owner = auth.uid())' },
    { file: 'm/2.sql', line: 5, sql: 'create or replace function public.grant_credits(a int) returns void language sql as $$ select 1 $$' },
    { file: 'm/2.sql', line: 9, sql: 'create view public.member_directory as select email from auth.users' },
    { file: 'm/2.sql', line: 12, sql: "insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true)" },
    { file: 'm/2.sql', line: 14, sql: 'alter publication supabase_realtime add table public.notes' },
    { file: 'm/2.sql', line: 16, sql: 'create role sneaky login bypassrls' },
    { file: 'm/2.sql', line: 18, sql: 'create policy "up" on storage.objects for insert with check (true)' },
  ]
  const findings = [
    { object: 'profiles' },
    { object: 'notes."read all"' },
    { object: 'fn:grant_credits' },
    { object: 'view:member_directory' },
    { object: 'storage:avatars' },
    { object: 'realtime:notes' },
    { object: 'role:sneaky' },
    { object: 'storage.objects."up"' },
    { object: 'table:profiles' },
    { object: 'nowhere' },
    { object: 'public' },
  ]
  attachLocations(findings, applied)
  const where = findings.map((f) => (f.file ? `${f.file}:${f.line}` : null))
  assert.deepEqual(where, [
    'm/1.sql:3',
    'm/2.sql:1', // latest definition of a re-created policy wins
    'm/2.sql:5',
    'm/2.sql:9',
    'm/2.sql:12',
    'm/2.sql:14',
    'm/2.sql:16',
    'm/2.sql:18',
    'm/1.sql:3',
    null,
    null,
  ])
  assert.equal(locatorFor('allow:foo bar'), null)
})

test('#migrations a table name never matches a longer name', () => {
  const findings = [{ object: 'notes' }]
  attachLocations(findings, [{ file: 'a.sql', line: 1, sql: 'create table public.notes_archive (id int)' }])
  assert.equal(findings[0].file, undefined)
})

// ---------------------------------------------------------- end-to-end

test('#migrations audits a leaky migrations folder with the real engine, with file:line', async () => {
  const r = await auditMigrations({ paths: [FIX('migrations-leaky')] })
  const by = (k) => r.findings.find((f) => f.kind === k)
  assert.equal(by('rls_disabled').object, 'profiles')
  assert.match(by('rls_disabled').file, /20260101000000_init\.sql$/)
  assert.equal(by('rls_disabled').line, 9)
  assert.equal(by('permissive_true').object, 'notes."read all"')
  assert.equal(by('permissive_true').line, 22)
  assert.equal(by('public_bucket').object, 'storage:avatars')
  assert.equal(by('anon_executes_definer').object, 'fn:grant_credits')
  assert.equal(by('definer_search_path_mutable').line, 5)
  assert.equal(by('realtime_exposure').object, 'realtime:notes')
  // the clean, owner-scoped table produced nothing
  assert.ok(!r.findings.some((f) => String(f.object).startsWith('todos')))
  assert.equal(r.passed, false)

  // honesty: the failed statement is reported, the extension skip is counted
  const inc = by('migrations_incomplete')
  assert.equal(inc.severity, 'warn')
  assert.equal(inc.line, 26)
  assert.equal(r.migrations.failed.length, 1)
  assert.match(r.migrations.failed[0].error, /does_not_exist/)
  assert.deepEqual(r.migrations.extensionsSkipped, ['pg_net'])
  assert.deepEqual(r.migrations.extensionsLoaded, ['uuid-ossp'])
  assert.equal(r.migrations.skipped.transaction, 2)
})

test('#migrations a clean folder passes (only the engine generic definer review note)', async () => {
  const r = await auditMigrations({ paths: [FIX('migrations-clean')] })
  // The engine always notes a SECURITY DEFINER function for review; closed to
  // anon/authenticated it is the generic warn, not anon_executes_definer.
  assert.deepEqual(r.findings.map((f) => `${f.kind} ${f.object}`), ['security_definer fn:handle_new_user'])
  assert.match(r.findings[0].detail, /review who can call it/)
  assert.equal(r.findings[0].line, 14)
  assert.equal(r.passed, true)
  assert.equal(r.migrations.failed.length, 0)
})

test('#migrations --no-default-grants: an ungranted USING(true) is not an exposure, RLS off still is', async () => {
  const r = await auditMigrations({ paths: [FIX('migrations-leaky')], defaultGrants: false })
  const kinds = r.findings.map((f) => f.kind)
  assert.ok(kinds.includes('rls_disabled'))
  assert.ok(!kinds.includes('permissive_true'))
  assert.equal(r.migrations.defaultGrants, false)
})

test('#migrations nothing loadable is a usage error, never a clean report', async () => {
  await assert.rejects(() => auditMigrations({ paths: [FIX('migrations-broken')] }), (e) => {
    assert.ok(e instanceof MigrationsUsageError)
    assert.match(e.message, /Nothing could be loaded/)
    assert.match(e.message, /001_all_broken\.sql:2/)
    return true
  })
  await assert.rejects(() => auditMigrations({ paths: [FIX('does-not-exist')] }), MigrationsUsageError)
  await assert.rejects(() => auditMigrations({ paths: [here] }), /No \.sql files/) // test/ has no .sql at top level
})

// ---------------------------------------------------------- CLI

const run = (...args) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } })

test('#migrations CLI: exit 1 with file:line in the report, exit 0 on clean, exit 2 on misuse', () => {
  const leaky = run('migrations', FIX('migrations-leaky'))
  assert.equal(leaky.status, 1, leaky.stderr)
  assert.match(leaky.stdout, /migrations: 2 file\(s\), 12 of 16 statement\(s\) loaded/)
  assert.match(leaky.stdout, /20260101000000_init\.sql:9/)
  assert.match(leaky.stdout, /1 extension\(s\) skipped \(pg_net\)/)

  const clean = run('migrations', FIX('migrations-clean'))
  assert.equal(clean.status, 0, clean.stdout + clean.stderr)

  const json = JSON.parse(run('migrations', FIX('migrations-leaky'), '--json').stdout)
  assert.equal(json.migrations.applied, 12)
  assert.ok(json.findings.find((f) => f.kind === 'rls_disabled').file)

  assert.equal(run('migrations', FIX('migrations-broken')).status, 2)
  const misuse = run('migrations', FIX('migrations-leaky'), '--url', 'https://x.supabase.co')
  assert.equal(misuse.status, 2)
  assert.match(misuse.stderr, /can't be used with "migrations"/)
  assert.equal(run('postgresql://localhost:1/x', '--no-default-grants').status, 2)
})
