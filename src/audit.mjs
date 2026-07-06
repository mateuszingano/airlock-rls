// Airlock — the CI gate for Supabase RLS.
//
// Core audit logic, framework-free so the CLI, the GitHub Action, the DAST
// probe and the monitor all share one source of truth.
//
// It audits the *logic* of Row Level Security, not just its presence:
//   - rls_disabled          table with RLS off (every row exposed)            [fail]
//   - permissive_true       policy USING(true) / WITH CHECK(true)             [fail]
//   - anon_unscoped         anon can read rows without scoping to a user      [fail]
//   - authenticated_unscoped any logged-in user reads all rows (no auth.uid) [warn]
//   - write_unchecked       INSERT/UPDATE/ALL with no WITH CHECK guard        [warn]
//
// audit() returns a structured result; it never prints or exits — callers
// decide how to report. `pg` is loaded lazily so the pure classifier
// (buildResult) can be imported and tested without the driver installed.

/**
 * @typedef {object} Finding
 * @property {string} kind
 * @property {'fail'|'warn'} severity
 * @property {string} object     e.g. `payments` or `notes."read all"`
 * @property {string} detail     human-readable explanation
 *
 * @typedef {object} AuditResult
 * @property {string} schema
 * @property {Finding[]} findings   all findings (fail + warn), ordered fail-first
 * @property {Finding[]} allowed    permissive findings waved through by `allow`
 * @property {number} problems      count of severity==='fail'
 * @property {number} warnings      count of severity==='warn'
 * @property {boolean} passed       problems === 0
 */

const SCOPED_RE = /auth\.uid\(\)|current_setting/i

/** Roles that include the anonymous (public API) caller. */
function includesAnon(roles = []) {
  return roles.includes('anon') || roles.includes('public')
}
function includesAuthenticated(roles = []) {
  return roles.includes('authenticated') || roles.includes('public')
}

/**
 * Classify a single policy row into zero or more findings. Pure.
 * @param {{tablename:string, policyname:string, cmd:string, roles:string[], qual:string|null, with_check:string|null}} p
 * @returns {Finding[]}
 */
export function classifyPolicy(p) {
  const object = `${p.tablename}."${p.policyname}"`
  const out = []

  // 1) Literal always-true — dominant, don't double-flag.
  if (p.qual === 'true' || p.with_check === 'true') {
    const how = [p.qual === 'true' ? 'USING(true)' : null, p.with_check === 'true' ? 'WITH CHECK(true)' : null]
      .filter(Boolean)
      .join(' + ')
    out.push({ kind: 'permissive_true', severity: 'fail', object, detail: `[${p.cmd}] ${how}` })
    return out
  }

  const readish = p.cmd === 'SELECT' || p.cmd === 'ALL'
  const writeish = p.cmd === 'INSERT' || p.cmd === 'UPDATE' || p.cmd === 'ALL'
  const scoped = p.qual != null && SCOPED_RE.test(p.qual)

  // 2) A read policy that doesn't scope to the current user (no auth.uid()).
  if (readish && p.qual != null && !scoped) {
    if (includesAnon(p.roles)) {
      out.push({
        kind: 'anon_unscoped',
        severity: 'fail',
        object,
        detail: `[${p.cmd}] anon can read rows without scoping to a user — USING (${short(p.qual)})`,
      })
    } else if (includesAuthenticated(p.roles)) {
      out.push({
        kind: 'authenticated_unscoped',
        severity: 'warn',
        object,
        detail: `[${p.cmd}] any authenticated user reads all rows (no auth.uid()) — USING (${short(p.qual)})`,
      })
    }
  }

  // 3) A write policy with no WITH CHECK guard.
  if (writeish && (p.with_check == null || p.with_check === '')) {
    out.push({
      kind: 'write_unchecked',
      severity: 'warn',
      object,
      detail: `[${p.cmd}] no WITH CHECK — writes are not guarded (a row can be created/moved across the tenant line)`,
    })
  }

  return out
}

function short(s, n = 60) {
  s = String(s).replace(/\s+/g, ' ').trim()
  return s.length > n ? s.slice(0, n - 1) + '…' : s
}

/**
 * Build the structured result from raw catalog rows. Pure — no I/O — so it's
 * unit-testable without a database and reusable by the monitor.
 *
 * @param {object} args
 * @param {string} args.schema
 * @param {{tablename:string}[]} args.noRls
 * @param {object[]} args.policies      rows from pg_policies (tablename, policyname, cmd, roles[], qual, with_check)
 * @param {Set<string>|string[]} [args.allow]  policy names to treat as intentional (removed from findings → allowed)
 * @returns {AuditResult}
 */
export function buildResult({
  schema,
  noRls = [],
  policies = [],
  allTables = [],
  publicBuckets = [],
  secDefFns = [],
  allow = new Set(),
} = {}) {
  const allowSet = allow instanceof Set ? allow : new Set(allow)

  const findings = []
  for (const t of noRls) {
    findings.push({
      kind: 'rls_disabled',
      severity: 'fail',
      object: t.tablename,
      detail: `table in "${schema}" has RLS DISABLED — every row is exposed to the API roles`,
    })
  }

  const allowed = []
  for (const p of policies) {
    for (const f of classifyPolicy(p)) {
      if (allowSet.has(p.policyname)) allowed.push(f)
      else findings.push(f)
    }
  }

  // Coverage beyond RLS policies.
  for (const b of publicBuckets) {
    const f = {
      kind: 'public_bucket',
      severity: 'warn',
      object: `storage:${b.id || b.name}`,
      detail: 'storage bucket is public — anyone with the URL can read its files',
    }
    if (allowSet.has(b.id) || allowSet.has(b.name)) allowed.push(f)
    else findings.push(f)
  }
  for (const fn of secDefFns) {
    const f = {
      kind: 'security_definer',
      severity: 'warn',
      object: `fn:${fn.proname}`,
      detail: 'SECURITY DEFINER function runs as its owner and can bypass RLS — review who can call it',
    }
    if (allowSet.has(fn.proname)) allowed.push(f)
    else findings.push(f)
  }

  // fail before warn, stable otherwise
  findings.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'fail' ? -1 : 1))

  const problems = findings.filter((f) => f.severity === 'fail').length
  const warnings = findings.filter((f) => f.severity === 'warn').length

  return {
    schema,
    findings,
    allowed,
    problems,
    warnings,
    passed: problems === 0,
    tables: allTables.map((t) => t.tablename || t),
  }
}

/**
 * Run the RLS audit against a Postgres/Supabase database.
 * @param {{dbUrl:string, schema?:string, allow?:string[]|Set<string>}} opts
 * @returns {Promise<AuditResult>}
 */
export async function audit({ dbUrl, schema = 'public', allow = [] } = {}) {
  if (!dbUrl) throw new Error('Missing database URL. Set SUPABASE_DB_URL or pass one in.')

  const { default: pg } = await import('pg')
  const client = new pg.Client({ connectionString: dbUrl })
  await client.connect()
  try {
    const { rows: noRls } = await client.query(
      `select tablename from pg_catalog.pg_tables
        where schemaname = $1 and rowsecurity = false
        order by tablename`,
      [schema]
    )
    const { rows: policies } = await client.query(
      `select tablename, policyname, cmd, roles, qual, with_check
         from pg_policies where schemaname = $1
        order by tablename, policyname`,
      [schema]
    )
    const { rows: allTables } = await client.query(
      `select tablename from pg_catalog.pg_tables where schemaname = $1 order by tablename`,
      [schema]
    )
    // SECURITY DEFINER functions in the schema — run as owner, can bypass RLS.
    const { rows: secDefFns } = await client.query(
      `select p.proname
         from pg_proc p join pg_namespace n on n.oid = p.pronamespace
        where n.nspname = $1 and p.prosecdef = true
        order by p.proname`,
      [schema]
    )
    // Public storage buckets (Supabase only — guarded for plain Postgres).
    let publicBuckets = []
    try {
      const { rows } = await client.query(
        `select id, name from storage.buckets where public = true order by id`
      )
      publicBuckets = rows
    } catch {
      publicBuckets = [] // no storage schema (not a Supabase DB) — skip
    }
    return buildResult({ schema, noRls, policies, allTables, publicBuckets, secDefFns, allow })
  } finally {
    await client.end()
  }
}
