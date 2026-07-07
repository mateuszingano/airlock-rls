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

/**
 * Does this policy qualifier scope access (so it's not an open anon read)?
 * Recognises the real Supabase patterns:
 *  - per-user: auth.uid() / current_setting / auth.jwt()
 *  - restricted to a backend role: auth.role() = 'service_role' (NOT
 *    'authenticated'/'anon' — those stay flagged as role-only)
 *  - scoping through a SECURITY DEFINER helper: get_/is_/has_/current_*()
 */
export function isScoped(qual) {
  if (qual == null) return false
  if (/auth\.uid\(\)|current_setting|auth\.jwt\(\)/i.test(qual)) return true
  if (/'service_role'/i.test(qual)) return true // restricted to the backend role
  if (/\b(get|is|has|current)_\w+\(/i.test(qual)) return true // scoping via a helper
  return false
}

/** Roles that include the anonymous (public API) caller. */
function includesAnon(roles = []) {
  return roles.includes('anon') || roles.includes('public')
}
function includesAuthenticated(roles = []) {
  return roles.includes('authenticated') || roles.includes('public')
}

const READ_CMDS = new Set(['SELECT', 'ALL'])
const WRITE_CMDS = new Set(['INSERT', 'UPDATE', 'ALL'])

function isRestrictive(p) {
  return String(p.permissive).toUpperCase() === 'RESTRICTIVE'
}

/**
 * Does `role` actually hold `priv` on this table? grants is
 * { anon: Set<priv>, authenticated: Set<priv> } or null (unknown → assume yes,
 * to avoid false negatives when we couldn't read grants).
 */
function hasGrant(grants, role, priv) {
  if (!grants) return true
  const set = grants[role]
  return set ? set.has(priv) : false
}

/**
 * Is there a RESTRICTIVE policy on this table that scopes the same command for
 * this role to the current user? A restrictive scope neutralises a permissive
 * leak (Postgres ANDs restrictive policies in), so we downgrade fail → warn.
 */
function restrictiveScopes(restrictives, cmd, role) {
  return restrictives.some(
    (r) =>
      (r.cmd === cmd || r.cmd === 'ALL' || cmd === 'ALL') &&
      (r.roles.includes(role) || r.roles.includes('public')) &&
      isScoped(r.qual)
  )
}

/**
 * Classify one PERMISSIVE policy into zero or more findings, aware of table
 * GRANTs and any RESTRICTIVE policies on the same table.
 *
 * @param {object} p     policy row (tablename, policyname, cmd, roles[], qual, with_check, permissive)
 * @param {object} [ctx] { grants: {anon,authenticated}|null, restrictives: policy[] }
 * @returns {Finding[]}
 */
export function classifyPolicy(p, ctx = {}) {
  const { grants = null, restrictives = [] } = ctx
  // A RESTRICTIVE policy only narrows access — it can never be the cause of a leak.
  if (isRestrictive(p)) return []

  const object = `${p.tablename}."${p.policyname}"`
  const out = []
  const scoped = isScoped(p.qual)
  const readish = READ_CMDS.has(p.cmd)
  const writeish = WRITE_CMDS.has(p.cmd)

  // Which roles this policy actually exposes for reads/writes (role applies AND
  // the role holds the matching table GRANT — no grant means no exposure).
  const anonRead = includesAnon(p.roles) && hasGrant(grants, 'anon', 'SELECT')
  const authRead = includesAuthenticated(p.roles) && hasGrant(grants, 'authenticated', 'SELECT')
  const writePriv = p.cmd === 'UPDATE' ? 'UPDATE' : 'INSERT'
  const anonWrite = includesAnon(p.roles) && hasGrant(grants, 'anon', writePriv)
  const authWrite = includesAuthenticated(p.roles) && hasGrant(grants, 'authenticated', writePriv)

  // 1) Read side.
  if (readish && (p.qual === 'true' || (p.qual != null && !scoped))) {
    const literal = p.qual === 'true'
    if (anonRead) {
      const saved = restrictiveScopes(restrictives, p.cmd, 'anon')
      out.push({
        kind: literal ? 'permissive_true' : 'anon_unscoped',
        severity: saved ? 'warn' : 'fail',
        object,
        detail: literal
          ? `[${p.cmd}] USING(true) — anon reads every row${saved ? ' (a restrictive policy narrows it — verify)' : ''}`
          : `[${p.cmd}] anon reads without scoping to a user — USING (${short(p.qual)})${saved ? ' (restrictive-narrowed — verify)' : ''}`,
      })
    } else if (authRead) {
      out.push({
        kind: literal ? 'permissive_true' : 'authenticated_unscoped',
        severity: 'warn',
        object,
        detail: `[${p.cmd}] any authenticated user reads all rows${literal ? ' — USING(true)' : ` (no auth.uid()) — USING (${short(p.qual)})`}`,
      })
    }
  }

  // 2) Write side — WITH CHECK(true) or missing check, but only if a role can write.
  if (writeish && (anonWrite || authWrite)) {
    if (p.with_check === 'true') {
      const saved = restrictiveScopes(restrictives, p.cmd, anonWrite ? 'anon' : 'authenticated')
      out.push({
        kind: 'permissive_true',
        severity: saved ? 'warn' : 'fail',
        object,
        detail: `[${p.cmd}] WITH CHECK(true) — writes are not tied to the caller (a row can be forged as anyone)${saved ? ' (restrictive-narrowed — verify)' : ''}`,
      })
    } else if (p.with_check == null || p.with_check === '') {
      out.push({
        kind: 'write_unchecked',
        severity: 'warn',
        object,
        detail: `[${p.cmd}] no WITH CHECK — writes are not guarded (a row can be created/moved across the tenant line)`,
      })
    }
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
  views = [],
  storagePolicies = [],
  realtimeTables = [],
  grants = null,
  allow = new Set(),
} = {}) {
  const allowSet = allow instanceof Set ? allow : new Set(allow)

  // Grants map (only if grant data was provided). Absent → classifyPolicy assumes
  // granted, to avoid false negatives when we couldn't read privileges.
  let grantsByTable = null
  if (grants) {
    grantsByTable = {}
    for (const g of grants) {
      const t = grantsByTable[g.table_name] || (grantsByTable[g.table_name] = { anon: new Set(), authenticated: new Set() })
      if (t[g.grantee]) t[g.grantee].add(g.privilege_type)
    }
  }
  const grantsFor = (table) =>
    grantsByTable ? grantsByTable[table] || { anon: new Set(), authenticated: new Set() } : null

  // Restrictive policies per table (context for neutralising permissive leaks).
  const restrictivesByTable = {}
  for (const p of policies) {
    if (String(p.permissive).toUpperCase() === 'RESTRICTIVE') {
      ;(restrictivesByTable[p.tablename] = restrictivesByTable[p.tablename] || []).push(p)
    }
  }

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
    const ctx = { grants: grantsFor(p.tablename), restrictives: restrictivesByTable[p.tablename] || [] }
    for (const f of classifyPolicy(p, ctx)) {
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
    // A SECURITY DEFINER function runs as its owner (bypassing RLS). The real
    // danger is when the anon/authenticated role can EXECUTE it.
    const anonExec = fn.anon_exec === true || fn.anon_exec === 'true'
    const authExec = fn.auth_exec === true || fn.auth_exec === 'true'
    let f
    if (anonExec) {
      // WARN, not fail: in Supabase, SECURITY DEFINER helper functions used
      // inside RLS policies (and auth triggers) legitimately need anon EXECUTE.
      // It's "review whether this one mutates/leaks", not a certain leak.
      f = { kind: 'anon_executes_definer', severity: 'warn', object: `fn:${fn.proname}`,
        detail: 'anon can EXECUTE this SECURITY DEFINER function (runs as owner, bypasses RLS) — fine for RLS helpers/triggers, but review any that read or mutate data' }
    } else if (authExec) {
      f = { kind: 'security_definer', severity: 'warn', object: `fn:${fn.proname}`,
        detail: 'any authenticated user can EXECUTE this SECURITY DEFINER function (runs as owner, bypasses RLS) — review' }
    } else {
      f = { kind: 'security_definer', severity: 'warn', object: `fn:${fn.proname}`,
        detail: 'SECURITY DEFINER function runs as its owner and can bypass RLS — review who can call it' }
    }
    if (allowSet.has(fn.proname)) allowed.push(f)
    else findings.push(f)
  }
  // Storage object-level policies (storage.objects) — same logic, prefixed.
  for (const p of storagePolicies) {
    for (const f of classifyPolicy({ ...p, tablename: 'storage.objects' }, { grants: null, restrictives: [] })) {
      if (allowSet.has(p.policyname)) allowed.push(f)
      else findings.push({ ...f, kind: 'storage_' + f.kind })
    }
  }
  // Realtime: a published table whose rows are anon-readable also streams its
  // changes to anonymous websocket subscribers.
  const anonReadableTables = new Set(
    findings.filter((f) => f.kind === 'rls_disabled' || f.kind === 'anon_unscoped' || (f.kind === 'permissive_true' && /\[(SELECT|ALL)\]/.test(f.detail)))
      .map((f) => (f.kind === 'rls_disabled' ? f.object : (f.object.match(/^(.+?)\."/) || [])[1]))
  )
  for (const t of realtimeTables) {
    const name = t.tablename || t
    if (anonReadableTables.has(name)) {
      const f = { kind: 'realtime_exposure', severity: 'warn', object: `realtime:${name}`,
        detail: `table "${name}" streams changes via Realtime and is anon-readable — its row changes leak to anonymous subscribers` }
      if (allowSet.has(name)) allowed.push(f)
      else findings.push(f)
    }
  }
  for (const v of views) {
    // A view without security_invoker runs as its owner and reads underlying
    // tables *bypassing the caller's RLS* — a classic way to leak past a policy.
    if (String(v.security_invoker) !== 'true') {
      const f = {
        kind: 'view_bypasses_rls',
        severity: 'warn',
        object: `view:${v.viewname}`,
        detail: 'view runs as its owner (security_invoker off) — it can bypass RLS on the tables it reads',
      }
      if (allowSet.has(v.viewname)) allowed.push(f)
      else findings.push(f)
    }
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
      `select tablename, policyname, cmd, roles, qual, with_check, permissive
         from pg_policies where schemaname = $1
        order by tablename, policyname`,
      [schema]
    )
    // Table GRANTs for anon/authenticated — RLS only matters where a grant exists.
    const { rows: grants } = await client.query(
      `select table_name, grantee, privilege_type
         from information_schema.role_table_grants
        where table_schema = $1 and grantee in ('anon','authenticated')`,
      [schema]
    )
    const { rows: allTables } = await client.query(
      `select tablename from pg_catalog.pg_tables where schemaname = $1 order by tablename`,
      [schema]
    )
    // SECURITY DEFINER functions + who can EXECUTE them (anon running owner-priv
    // code is the real danger).
    const { rows: secDefFns } = await client.query(
      `select p.proname,
              has_function_privilege('anon', p.oid, 'EXECUTE') as anon_exec,
              has_function_privilege('authenticated', p.oid, 'EXECUTE') as auth_exec
         from pg_proc p join pg_namespace n on n.oid = p.pronamespace
        where n.nspname = $1 and p.prosecdef = true
        order by p.proname`,
      [schema]
    )
    // Storage object-level RLS (policies on storage.objects).
    let storagePolicies = []
    try {
      const { rows } = await client.query(
        `select tablename, policyname, cmd, roles, qual, with_check, permissive
           from pg_policies where schemaname = 'storage' and tablename = 'objects'`
      )
      storagePolicies = rows
    } catch {
      storagePolicies = []
    }
    // Realtime: tables published to the supabase_realtime publication.
    let realtimeTables = []
    try {
      const { rows } = await client.query(
        `select tablename from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = $1`,
        [schema]
      )
      realtimeTables = rows
    } catch {
      realtimeTables = []
    }
    // Views that bypass RLS (security_invoker off = runs as owner).
    const { rows: views } = await client.query(
      `select c.relname as viewname,
              coalesce((select option_value from pg_options_to_table(c.reloptions)
                         where option_name = 'security_invoker'), 'false') as security_invoker
         from pg_class c join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = $1 and c.relkind = 'v'
        order by c.relname`,
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
    return buildResult({ schema, noRls, policies, allTables, publicBuckets, secDefFns, views, storagePolicies, realtimeTables, grants, allow })
  } finally {
    await client.end()
  }
}
