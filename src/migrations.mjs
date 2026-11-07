// Airlock — no-database mode: audit your SQL migrations, no credentials.
//
//   npx airlock-rls migrations              # reads ./supabase/migrations
//   npx airlock-rls migrations db/schema.sql other/dir
//
// It replays the migration files (sorted by name, like the Supabase CLI) into an
// embedded Postgres (PGlite, in memory, nothing leaves the machine), after a
// bootstrap that recreates what a hosted Supabase project already has (the API
// roles, auth.uid()/auth.users, storage.buckets/objects, the extensions schema,
// the supabase_realtime publication, the default grants on `public`). Then it
// serves that database over a local socket and runs the SAME audit engine as the
// live mode (src/audit.mjs, unchanged): every rule, the grant-aware logic, the
// allow-list. Findings it can trace to the migration that created the object get
// `file` and `line`.
//
// Honesty rules, same as the rest of Airlock:
//  - A statement that fails to load is reported (file, line, error), and the run
//    adds a `migrations_incomplete` warning: whatever it would have created was
//    NOT audited. Never a silent pass.
//  - Nothing loaded at all is exit 2 (usage), not a clean report.
//  - CREATE EXTENSION that the embedded Postgres can't load is skipped and
//    counted, not treated as a failure; statements that then depend on it fail
//    loudly as above.

import { readdir, readFile, stat } from 'node:fs/promises'
import path from 'node:path'

// ---------------------------------------------------------------------------
// SQL splitting (pure). Splits on top-level `;`, respecting '...' strings
// (with '' escapes), E'...' strings (backslash escapes), "identifiers",
// $tag$ dollar quotes, -- line comments and nested /* */ comments. Each
// statement keeps the 1-based line where its first real token starts.
// ---------------------------------------------------------------------------

/**
 * @param {string} text
 * @returns {{sql:string, line:number}[]}
 */
export function splitSql(text) {
  const s = String(text || '').replace(/\r\n?/g, '\n')
  const out = []
  let i = 0
  let line = 1
  let start = 0
  let startLine = null // line of the first non-space, non-comment char of the statement
  const n = s.length

  // `start` is moved to the first real token, so leading comments never end
  // up in front of the statement text (classification and file:line lookups
  // match on how the statement begins).
  const mark = () => {
    if (startLine === null) {
      startLine = line
      start = i
    }
  }
  const flush = (end) => {
    const sql = startLine === null ? '' : s.slice(start, end).trim()
    if (sql) out.push({ sql, line: startLine })
    start = end + 1
    startLine = null
  }

  while (i < n) {
    const c = s[i]
    const d = s[i + 1]
    if (c === '\n') { line++; i++; continue }
    if (c === '-' && d === '-') { // line comment
      while (i < n && s[i] !== '\n') i++
      continue
    }
    if (c === '/' && d === '*') { // block comment, nestable in Postgres
      let depth = 1
      i += 2
      while (i < n && depth > 0) {
        if (s[i] === '\n') line++
        if (s[i] === '/' && s[i + 1] === '*') { depth++; i += 2; continue }
        if (s[i] === '*' && s[i + 1] === '/') { depth--; i += 2; continue }
        i++
      }
      continue
    }
    if (/\s/.test(c)) { i++; continue }
    if (c === ';') { flush(i); i++; continue }
    mark()
    if (c === "'") {
      // E'...' allows backslash escapes; a plain string only ''.
      const escaped = i > 0 && /[eE]/.test(s[i - 1]) && (i < 2 || !/[\w$]/.test(s[i - 2]))
      i++
      while (i < n) {
        if (s[i] === '\n') line++
        if (escaped && s[i] === '\\') { i += 2; continue }
        if (s[i] === "'") {
          if (s[i + 1] === "'") { i += 2; continue }
          break
        }
        i++
      }
      i++
      continue
    }
    if (c === '"') {
      i++
      while (i < n) {
        if (s[i] === '\n') line++
        if (s[i] === '"') {
          if (s[i + 1] === '"') { i += 2; continue }
          break
        }
        i++
      }
      i++
      continue
    }
    if (c === '$') {
      const m = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(s.slice(i, i + 64))
      // `$1` (a parameter) is not a dollar quote; only $$ or $tag$.
      if (m && !(i > 0 && /[\w$]/.test(s[i - 1]))) {
        const tag = m[0]
        const close = s.indexOf(tag, i + tag.length)
        const end = close === -1 ? n : close + tag.length
        for (let k = i; k < end; k++) if (s[k] === '\n') line++
        i = end
        continue
      }
    }
    i++
  }
  flush(n)
  return out
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/**
 * Resolve the given paths (files or directories) to the .sql files to load,
 * in the order the Supabase CLI applies them: by file name within each
 * directory (timestamps sort correctly), directories in the order given.
 * @param {string[]} paths
 * @returns {Promise<string[]>}
 */
export async function listMigrationFiles(paths) {
  const files = []
  for (const p of paths) {
    let st
    try {
      st = await stat(p)
    } catch {
      throw new MigrationsUsageError(`No such file or directory: ${p}`)
    }
    if (st.isDirectory()) {
      const names = (await readdir(p)).filter((f) => f.toLowerCase().endsWith('.sql')).sort()
      for (const f of names) files.push(path.join(p, f))
    } else {
      files.push(p)
    }
  }
  return files
}

export class MigrationsUsageError extends Error {}

// ---------------------------------------------------------------------------
// Bootstrap: what a hosted Supabase project has before your first migration.
// ---------------------------------------------------------------------------

/** Extensions the embedded Postgres can load, by SQL name → PGlite contrib module. */
const CONTRIB = {
  'uuid-ossp': 'uuid_ossp',
  pgcrypto: 'pgcrypto',
  pg_trgm: 'pg_trgm',
  citext: 'citext',
  hstore: 'hstore',
  ltree: 'ltree',
  moddatetime: 'moddatetime',
  unaccent: 'unaccent',
  fuzzystrmatch: 'fuzzystrmatch',
  btree_gist: 'btree_gist',
  btree_gin: 'btree_gin',
}

export const BOOTSTRAP_SQL = `
-- API and platform roles (names match a hosted project, so the audit's
-- "Supabase-managed" allow-set treats them exactly as it does in production).
create role anon nologin noinherit;
create role authenticated nologin noinherit;
create role service_role nologin noinherit bypassrls;
create role authenticator noinherit login;
grant anon, authenticated, service_role to authenticator;
create role supabase_admin nologin;
create role supabase_auth_admin nologin;
create role supabase_storage_admin nologin;
create role supabase_realtime_admin nologin;
create role dashboard_user nologin;
create role pgbouncer nologin;

create schema if not exists extensions;
grant usage on schema extensions to anon, authenticated, service_role;
grant usage on schema public to anon, authenticated, service_role;

-- auth: the helpers policies call, and the users table triggers hang off.
create schema auth;
grant usage on schema auth to anon, authenticated, service_role;
create table auth.users (
  instance_id uuid, id uuid primary key, aud varchar(255), role varchar(255),
  email varchar(255), encrypted_password varchar(255), email_confirmed_at timestamptz,
  invited_at timestamptz, confirmation_token varchar(255), confirmation_sent_at timestamptz,
  recovery_token varchar(255), recovery_sent_at timestamptz, last_sign_in_at timestamptz,
  raw_app_meta_data jsonb, raw_user_meta_data jsonb, is_super_admin boolean,
  created_at timestamptz default now(), updated_at timestamptz default now(),
  phone text, phone_confirmed_at timestamptz, confirmed_at timestamptz,
  banned_until timestamptz, deleted_at timestamptz, is_anonymous boolean default false
);
create function auth.uid() returns uuid language sql stable as
  $$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
create function auth.role() returns text language sql stable as
  $$ select nullif(current_setting('request.jwt.claim.role', true), '')::text $$;
create function auth.email() returns text language sql stable as
  $$ select nullif(current_setting('request.jwt.claim.email', true), '')::text $$;
create function auth.jwt() returns jsonb language sql stable as
  $$ select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb $$;

-- storage: buckets/objects with the columns migrations insert into and the
-- path helpers policies use. objects has RLS on, as on a hosted project.
create schema storage;
grant usage on schema storage to anon, authenticated, service_role;
create table storage.buckets (
  id text primary key, name text not null, owner uuid, owner_id text,
  created_at timestamptz default now(), updated_at timestamptz default now(),
  public boolean default false, avif_autodetection boolean default false,
  file_size_limit bigint, allowed_mime_types text[], type text default 'STANDARD'
);
create table storage.objects (
  id uuid primary key default gen_random_uuid(), bucket_id text references storage.buckets(id),
  name text, owner uuid, owner_id text, created_at timestamptz default now(),
  updated_at timestamptz default now(), last_accessed_at timestamptz default now(),
  metadata jsonb, path_tokens text[] generated always as (string_to_array(name, '/')) stored,
  version text, user_metadata jsonb
);
alter table storage.objects enable row level security;
grant all on storage.buckets, storage.objects to anon, authenticated, service_role;
create function storage.foldername(name text) returns text[] language sql immutable as
  $$ select (string_to_array(name, '/'))[1:array_length(string_to_array(name, '/'), 1) - 1] $$;
create function storage.filename(name text) returns text language sql immutable as
  $$ select (string_to_array(name, '/'))[array_length(string_to_array(name, '/'), 1)] $$;
create function storage.extension(name text) returns text language sql immutable as
  $$ select reverse(split_part(reverse(name), '.', 1)) $$;

-- realtime publication that migrations add tables to.
create publication supabase_realtime;

-- Schemas of platform extensions the embedded Postgres can't run, so a
-- migration that only references them (grants, cron.schedule) still loads.
create schema if not exists cron;
create function cron.schedule(job_name text, schedule text, command text) returns bigint
  language sql as $$ select 1::bigint $$;
create function cron.schedule(schedule text, command text) returns bigint
  language sql as $$ select 1::bigint $$;
create function cron.unschedule(job_name text) returns boolean language sql as $$ select true $$;
create schema if not exists net;
create schema if not exists vault;
create schema if not exists graphql;
create schema if not exists graphql_public;
`

// Hosted projects created before Oct 30, 2026 auto-grant new objects in
// `public` to the API roles. Most migrations rely on it (they never GRANT),
// so without this every table would look unreachable and the audit would miss
// real leaks. Emulated by default — a security tool should assume the grant —
// and turned off with --no-default-grants to model a post-Oct-30 project.
export const DEFAULT_GRANTS_SQL = `
alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;
alter default privileges in schema public grant all on functions to anon, authenticated, service_role;
`

// ---------------------------------------------------------------------------
// Statement classification (pure)
// ---------------------------------------------------------------------------

const TXN_RE = /^(begin|commit|rollback|end|abort|start\s+transaction|savepoint|release(\s+savepoint)?|rollback\s+to)\b/i

/** @returns {'txn'|'meta'|'extension'|'sql'} */
export function classifyStatement(sql) {
  const s = sql.trim()
  if (s.startsWith('\\')) return 'meta'
  if (TXN_RE.test(s)) return 'txn'
  if (/^create\s+extension\b/i.test(s)) return 'extension'
  return 'sql'
}

/** The extension name in a CREATE EXTENSION statement, unquoted. */
export function extensionName(sql) {
  const m = /^create\s+extension\s+(?:if\s+not\s+exists\s+)?("([^"]+)"|[\w-]+)/i.exec(sql.trim())
  if (!m) return null
  return (m[2] || m[1]).toLowerCase()
}

// ---------------------------------------------------------------------------
// Finding → file:line (pure)
// ---------------------------------------------------------------------------

const esc = (x) => String(x).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
/**
 * An identifier, optionally schema-qualified, optionally quoted, matching
 * `name`. The trailing look-aheads stop a name from matching a longer one and
 * a schema name from matching as the object (`public` in `public.profiles`).
 */
const ident = (name) => `(?:"?[\\w$]+"?\\s*\\.\\s*)?"?${esc(name)}"?(?![\\w$])(?!\\s*\\.)`

/**
 * Build the regex that finds the statement which created a finding's object,
 * and whether the FIRST (creation) or LAST (latest definition) match wins.
 * @returns {{re:RegExp, pick:'first'|'last'}|null}
 */
export function locatorFor(object) {
  const o = String(object || '')
  let m
  if ((m = /^(.+?)\."(.+)"$/.exec(o))) {
    const table = m[1].replace(/^storage\./, '')
    return { re: new RegExp(`^create\\s+policy\\s+"?${esc(m[2])}"?\\s+on\\s+${ident(table)}`, 'i'), pick: 'last' }
  }
  if ((m = /^fn:(.+)$/.exec(o))) {
    return { re: new RegExp(`^create\\s+(?:or\\s+replace\\s+)?function\\s+${ident(m[1])}\\s*\\(`, 'i'), pick: 'last' }
  }
  if ((m = /^view:(.+)$/.exec(o))) {
    return { re: new RegExp(`^create\\s+(?:or\\s+replace\\s+)?(?:temp\\w*\\s+)?(?:recursive\\s+)?view\\s+${ident(m[1])}`, 'i'), pick: 'last' }
  }
  if ((m = /^matview:(.+)$/.exec(o))) {
    return { re: new RegExp(`^create\\s+materialized\\s+view\\s+(?:if\\s+not\\s+exists\\s+)?${ident(m[1])}`, 'i'), pick: 'last' }
  }
  if ((m = /^role:(.+)$/.exec(o))) {
    return { re: new RegExp(`^(?:create|alter)\\s+(?:role|user)\\s+"?${esc(m[1])}"?(?![\\w$])[\\s\\S]*\\b(?:bypassrls|superuser)\\b`, 'i'), pick: 'last' }
  }
  if ((m = /^realtime:(.+)$/.exec(o))) {
    return { re: new RegExp(`^alter\\s+publication\\s+supabase_realtime\\s+add\\s+table[\\s\\S]*${ident(m[1])}`, 'i'), pick: 'last' }
  }
  if ((m = /^storage:(.+)$/.exec(o))) {
    return { re: new RegExp(`^insert\\s+into\\s+storage\\.buckets[\\s\\S]*'${esc(m[1])}'`, 'i'), pick: 'last' }
  }
  if ((m = /^table:(.+)$/.exec(o)) || (m = /^([\w$]+)$/.exec(o))) {
    return { re: new RegExp(`^create\\s+(?:unlogged\\s+)?table\\s+(?:if\\s+not\\s+exists\\s+)?${ident(m[1])}`, 'i'), pick: 'first' }
  }
  return null
}

/**
 * Add `file`/`line` to each finding traceable to an applied statement.
 * Mutates and returns the findings. Findings without a match are untouched.
 * @param {{object:string}[]} findings
 * @param {{file:string, line:number, sql:string}[]} applied
 */
export function attachLocations(findings, applied) {
  for (const f of findings || []) {
    if (f.file) continue
    const loc = locatorFor(f.object)
    if (!loc) continue
    let hit = null
    for (const st of applied) {
      if (loc.re.test(st.sql)) {
        hit = st
        if (loc.pick === 'first') break
      }
    }
    if (hit) {
      f.file = hit.file
      f.line = hit.line
    }
  }
  return findings
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

const rel = (p) => path.relative(process.cwd(), p).split(path.sep).join('/') || p

async function loadPglite() {
  try {
    const [{ PGlite }, { PGLiteSocketServer }] = await Promise.all([
      import('@electric-sql/pglite'),
      import('@electric-sql/pglite-socket'),
    ])
    const extensions = {}
    for (const [sqlName, mod] of Object.entries(CONTRIB)) {
      try {
        const m = await import(`@electric-sql/pglite/contrib/${mod}`)
        extensions[mod] = m[mod] || Object.values(m)[0]
      } catch {
        // not available in this PGlite build: CREATE EXTENSION will be skipped
        delete CONTRIB[sqlName]
      }
    }
    try {
      const { vector } = await import('@electric-sql/pglite/vector')
      extensions.vector = vector
    } catch {
      // pgvector not bundled: `create extension vector` is skipped and counted
    }
    return { PGlite, PGLiteSocketServer, extensions }
  } catch (err) {
    throw new MigrationsUsageError(
      `The migrations mode needs the embedded Postgres (@electric-sql/pglite), which failed to load: ${err.message}`
    )
  }
}

/**
 * Replay migrations into an embedded Postgres and run the standard audit.
 * @param {{paths?:string[], schema?:string, allow?:string[], defaultGrants?:boolean,
 *          auditImpl?:Function}} opts
 * @returns {Promise<object>} the audit result plus `migrations` (what was loaded)
 */
export async function auditMigrations({ paths = ['supabase/migrations'], schema = 'public', allow = [], defaultGrants = true, auditImpl } = {}) {
  const files = await listMigrationFiles(paths)
  if (!files.length) {
    throw new MigrationsUsageError(`No .sql files found in ${paths.join(', ')}. Point it at your migrations folder or a schema dump.`)
  }

  const { PGlite, PGLiteSocketServer, extensions } = await loadPglite()
  const db = await PGlite.create({ extensions })
  const info = {
    files: files.map(rel),
    statements: 0,
    applied: 0,
    skipped: { transaction: 0, meta: 0 },
    extensionsSkipped: [],
    extensionsLoaded: [],
    failed: [],
    defaultGrants,
  }
  const applied = []
  let server
  try {
    await db.exec(BOOTSTRAP_SQL)
    if (defaultGrants) await db.exec(DEFAULT_GRANTS_SQL)

    for (const file of files) {
      const text = await readFile(file, 'utf8')
      for (const st of splitSql(text)) {
        info.statements++
        const kind = classifyStatement(st.sql)
        if (kind === 'meta') { info.skipped.meta++; continue }
        // Each statement runs on its own. A BEGIN would make the first failure
        // abort every statement after it until COMMIT, hiding them all.
        if (kind === 'txn') { info.skipped.transaction++; continue }
        try {
          await db.exec(st.sql)
          if (kind === 'extension') info.extensionsLoaded.push(extensionName(st.sql))
          info.applied++
          applied.push({ file: rel(file), line: st.line, sql: st.sql })
        } catch (err) {
          if (kind === 'extension') {
            info.extensionsSkipped.push(extensionName(st.sql) || st.sql.slice(0, 60))
            continue
          }
          info.failed.push({
            file: rel(file),
            line: st.line,
            statement: st.sql.replace(/\s+/g, ' ').slice(0, 120),
            error: String(err && err.message ? err.message : err).split('\n')[0],
          })
        }
      }
      // A dump's `set search_path = ''` or a `set role` must not leak into the
      // next file.
      try { await db.exec('reset all; reset role;') } catch { /* best effort */ }
    }

    if (info.applied === 0) {
      const why = info.failed[0] ? ` First error: ${info.failed[0].file}:${info.failed[0].line}: ${info.failed[0].error}` : ''
      throw new MigrationsUsageError(`Nothing could be loaded from ${info.files.length} file(s), so nothing was audited.${why}`)
    }

    server = new PGLiteSocketServer({ db, port: 0, host: '127.0.0.1', maxConnections: 4 })
    await server.start()
    const run = auditImpl || (await import('./audit.mjs')).audit
    const result = await run({ dbUrl: `postgresql://postgres@${server.getServerConn()}/postgres`, schema, allow })

    attachLocations(result.findings, applied)
    attachLocations(result.allowed, applied)

    if (info.failed.length) {
      const first = info.failed.slice(0, 3).map((f) => `${f.file}:${f.line} (${f.error})`).join('; ')
      result.findings.push({
        kind: 'migrations_incomplete',
        severity: 'warn',
        object: `${info.failed.length} statement(s)`,
        detail:
          `${info.failed.length} of ${info.statements} migration statement(s) failed to load in the embedded Postgres, so ` +
          `whatever they create or change was NOT audited: ${first}${info.failed.length > 3 ? '; …' : ''}. ` +
          `Run against the live database for a complete audit.`,
        file: info.failed[0].file,
        line: info.failed[0].line,
      })
      result.warnings = result.findings.filter((f) => f.severity === 'warn').length
    }
    result.migrations = info
    return result
  } finally {
    if (server) await server.stop().catch(() => {})
    await db.close().catch(() => {})
  }
}
