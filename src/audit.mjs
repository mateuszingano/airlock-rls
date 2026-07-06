// Airlock — the CI gate for Supabase RLS.
//
// Core audit logic, kept framework-free so the CLI, the GitHub Action, and the
// (future) continuous monitor can all share one source of truth.
//
// It answers the two questions that leak a Supabase database:
//   1. Which tables in the target schema have Row Level Security DISABLED?
//   2. Which policies are permissive (USING (true) / WITH CHECK (true)) — i.e.
//      always-true rules that let every API role through and defeat isolation?
//
// The module exports a single `audit()` that returns a structured result. It
// never calls process.exit and never prints — callers decide how to report.
//
// `pg` is loaded lazily inside audit() so the pure helpers (buildResult,
// permissiveLabel) can be imported and tested without the driver installed.

/**
 * Run the RLS audit against a Postgres/Supabase database.
 *
 * @param {object} opts
 * @param {string} opts.dbUrl        Postgres connection string (required).
 * @param {string} [opts.schema]     Schema to audit. Default: 'public'.
 * @param {Set<string>|string[]} [opts.allow]  Policy names to treat as
 *        intentionally permissive (e.g. a public status page). These are
 *        reported as `allowed` instead of counting as problems.
 * @returns {Promise<AuditResult>}
 *
 * @typedef {object} AuditResult
 * @property {string} schema
 * @property {string[]} tablesWithoutRls      Table names with RLS disabled.
 * @property {PermissivePolicy[]} permissive  Always-true policies that count as problems.
 * @property {PermissivePolicy[]} allowed      Always-true policies waved through by `allow`.
 * @property {number} problems                 tablesWithoutRls.length + permissive.length.
 * @property {boolean} passed                  true when problems === 0.
 *
 * @typedef {object} PermissivePolicy
 * @property {string} table
 * @property {string} policy
 * @property {string} cmd        SELECT / INSERT / UPDATE / DELETE / ALL.
 * @property {boolean} using     qual === 'true'.
 * @property {boolean} withCheck with_check === 'true'.
 */
export async function audit({ dbUrl, schema = 'public', allow = [] } = {}) {
  if (!dbUrl) {
    throw new Error('Missing database URL. Set SUPABASE_DB_URL or pass one in.')
  }

  const allowSet = allow instanceof Set ? allow : new Set(allow)
  const { default: pg } = await import('pg')
  const client = new pg.Client({ connectionString: dbUrl })
  await client.connect()

  try {
    // 1) Tables with RLS turned off — every row is exposed to the API roles.
    const { rows: noRls } = await client.query(
      `select tablename
         from pg_catalog.pg_tables
        where schemaname = $1 and rowsecurity = false
        order by tablename`,
      [schema]
    )

    // 2) Permissive policies — USING (true) / WITH CHECK (true) bypass isolation.
    const { rows: permissiveRows } = await client.query(
      `select tablename, policyname, cmd, qual, with_check
         from pg_policies
        where schemaname = $1
          and (qual = 'true' or with_check = 'true')
        order by tablename, policyname`,
      [schema]
    )

    return buildResult({ schema, noRls, permissiveRows, allowSet })
  } finally {
    await client.end()
  }
}

/**
 * Turn raw catalog rows into the structured AuditResult. Pure — no I/O — so it
 * can be unit-tested without a database and reused by the monitor later.
 *
 * @param {object} args
 * @param {string} args.schema
 * @param {{tablename: string}[]} args.noRls           Rows from pg_tables (rowsecurity = false).
 * @param {{tablename: string, policyname: string, cmd: string, qual: string, with_check: string}[]} args.permissiveRows
 * @param {Set<string>} [args.allowSet]                Policy names to wave through.
 * @returns {AuditResult}
 */
export function buildResult({ schema, noRls = [], permissiveRows = [], allowSet = new Set() } = {}) {
  const allow = allowSet instanceof Set ? allowSet : new Set(allowSet)
  const permissive = []
  const allowed = []
  for (const p of permissiveRows) {
    const entry = {
      table: p.tablename,
      policy: p.policyname,
      cmd: p.cmd,
      using: p.qual === 'true',
      withCheck: p.with_check === 'true',
    }
    ;(allow.has(p.policyname) ? allowed : permissive).push(entry)
  }

  const tablesWithoutRls = noRls.map((r) => r.tablename)
  const problems = tablesWithoutRls.length + permissive.length

  return {
    schema,
    tablesWithoutRls,
    permissive,
    allowed,
    problems,
    passed: problems === 0,
  }
}

/**
 * Human-readable label for how a policy is permissive, e.g. "USING(true) + WITH CHECK(true)".
 * @param {PermissivePolicy} p
 * @returns {string}
 */
export function permissiveLabel(p) {
  return [p.using ? 'USING(true)' : null, p.withCheck ? 'WITH CHECK(true)' : null]
    .filter(Boolean)
    .join(' + ')
}
