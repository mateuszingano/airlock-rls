// Airlock — draft fix migration (`--fix-sql <file>`).
//
// Turns the findings of one audit into a DRAFT SQL migration. Two kinds of
// output, kept visibly apart:
//
//   1. Mechanical fixes — statements whose effect is fully determined by the
//      finding (enable RLS, revoke a grant, pin a search_path, flip a view to
//      security_invoker...). Emitted as real SQL, each with a one-line note on
//      what it can break.
//   2. Decisions — anything where the right answer depends on the app (who owns
//      a row, whether a table is meant to be public). Emitted ONLY as commented
//      templates marked TODO. A policy is never rewritten automatically: a
//      wrong guess at the owner column is a new leak or a broken app.
//
// Allowed/waived findings never reach this module (they live in
// result.allowed, not result.findings). Pure: no I/O, no database.

/** Quote an identifier exactly like Postgres' quote_ident would need it:
 *  always double-quoted, inner quotes doubled. Always quoting is never wrong
 *  for a name read back from the catalog (it is the exact stored spelling). */
export function quoteIdent(name) {
  return '"' + String(name).replace(/"/g, '""') + '"'
}

/** Quote a string literal (single quotes doubled). */
export function quoteLiteral(s) {
  return "'" + String(s).replace(/'/g, "''") + "'"
}

/** schema.name, both quoted. A name that already carries its schema
 *  (storage.objects) is split on the FIRST dot only when asked. */
function qualified(schema, name) {
  return `${quoteIdent(schema)}.${quoteIdent(name)}`
}

/** Split a policy finding's object `table."policy"` into its parts. The policy
 *  name is everything between the first `."` and the final quote, so a policy
 *  name that itself contains quotes survives. */
export function splitPolicyObject(object) {
  const s = String(object || '')
  const i = s.indexOf('."')
  if (i < 0 || !s.endsWith('"')) return null
  return { table: s.slice(0, i), policy: s.slice(i + 2, -1) }
}

/** `[SELECT]` / `[ALL]` ... at the start of a policy finding's detail. */
function commandOf(detail) {
  const m = /^\[(SELECT|INSERT|UPDATE|DELETE|ALL)\]/.exec(String(detail || ''))
  return m ? m[1] : 'ALL'
}

const POLICY_KINDS = new Set([
  'permissive_true', 'anon_unscoped', 'authenticated_unscoped', 'or_branch_unscoped',
  'write_unscoped', 'write_unchecked', 'update_using_unscoped', 'delete_unscoped',
])

const NOT_SQL = new Set(['service_role_exposed', 'env_file_exposed', 'git_exposed', 'source_map_exposed'])

/** Prefix every line of a block with `-- `. */
const comment = (text) => String(text).split('\n').map((l) => (l ? `-- ${l}` : '--')).join('\n')

/** The policy template a human fills in: same name, same command, scoped to
 *  an owner column they must pick. */
function policyTemplate(tableSql, policy, cmd) {
  const p = quoteIdent(policy)
  const using = cmd === 'INSERT' ? '' : '\n  using ((select auth.uid()) = <owner_column>)'
  const check = cmd === 'SELECT' || cmd === 'DELETE' ? '' : '\n  with check ((select auth.uid()) = <owner_column>)'
  return [
    `drop policy ${p} on ${tableSql};`,
    `create policy ${p} on ${tableSql}`,
    `  for ${cmd.toLowerCase()} to authenticated${using}${check};`,
  ].join('\n')
}

/**
 * Build the draft migration.
 * @param {{schema?:string, findings:Array<{kind:string,severity:string,object:string,detail:string}>}} result
 * @param {{version?:string, now?:Date}} [opts]
 * @returns {{sql:string, statements:number, todos:number}}
 */
export function buildFixSql(result, { version = '0.0.0', now = new Date() } = {}) {
  const schema = (result && result.schema) || 'public'
  const findings = (result && result.findings) || []
  const fixes = [] // {note, sql}
  const todos = [] // {note, sql}
  const seen = new Set()
  const addFix = (note, sql) => {
    if (seen.has(sql)) return
    seen.add(sql)
    fixes.push({ note, sql })
  }
  const addTodo = (note, sql) => {
    const key = 'todo:' + note + sql
    if (seen.has(key)) return
    seen.add(key)
    todos.push({ note, sql })
  }
  const strip = (obj, prefix) => String(obj).slice(prefix.length)

  for (const f of findings) {
    const kind = f.kind || ''
    if (kind === 'rls_disabled') {
      const t = qualified(schema, f.object)
      addFix(
        `${f.object}: RLS is off. Enabling it with no policy LOCKS the table for the API (anon and authenticated read and write nothing) until you add a policy — see the TODO below.`,
        `alter table ${t} enable row level security;`
      )
      addTodo(
        `${f.object}: add the policy that says who may read and write each row (pick the owner column).`,
        `create policy "owner can read" on ${t}\n  for select to authenticated using ((select auth.uid()) = <owner_column>);\n` +
          `create policy "owner can write" on ${t}\n  for all to authenticated using ((select auth.uid()) = <owner_column>)\n  with check ((select auth.uid()) = <owner_column>);`
      )
    } else if (kind === 'anon_executes_definer') {
      const fn = qualified(schema, strip(f.object, 'fn:'))
      addFix(
        `${f.object}: anon can call this SECURITY DEFINER function. If an RLS policy or auth trigger that anon hits calls it, keep EXECUTE for anon and remove this line. (Fails if the name is overloaded: add the argument types.)`,
        `revoke execute on function ${fn} from public, anon;`
      )
    } else if (kind === 'security_definer') {
      const fn = qualified(schema, strip(f.object, 'fn:'))
      addTodo(
        `${f.object}: SECURITY DEFINER function — decide who should call it. If only your server does, revoke it from the client roles.`,
        `revoke execute on function ${fn} from public, anon, authenticated;`
      )
    } else if (kind === 'definer_search_path_mutable') {
      const fn = qualified(schema, strip(f.object, 'fn:'))
      addFix(
        `${f.object}: pin the search_path. After this the body must schema-qualify every table and function it uses (public.x, not x), or it errors at runtime.`,
        `alter function ${fn} set search_path = '';`
      )
    } else if (kind === 'view_bypasses_rls') {
      const v = qualified(schema, strip(f.object, 'view:'))
      addFix(
        `${f.object}: run the view as the caller, so the RLS of the tables underneath applies. Callers then also need SELECT and a policy on those tables.`,
        `alter view ${v} set (security_invoker = true);`
      )
    } else if (kind === 'matview_exposed') {
      const mv = qualified(schema, strip(f.object, 'matview:'))
      addFix(
        `${f.object}: RLS never applies to a materialized view. Revoke the client roles; serve it through a scoped function if the app needs it.`,
        `revoke select on ${mv} from anon, authenticated;`
      )
    } else if (kind === 'public_bucket') {
      const id = strip(f.object, 'storage:')
      addFix(
        `${f.object}: make the bucket private. Existing public URLs stop working; serve files with signed URLs. Remove this line if every file in it is meant to be public.`,
        `update storage.buckets set public = false where id = ${quoteLiteral(id)};`
      )
    } else if (kind === 'owner_bypasses_rls') {
      const t = qualified(schema, strip(f.object, 'table:'))
      addFix(
        `${f.object}: the owner is a role the API can reach and bypasses RLS. FORCE makes the policies apply to the owner too.`,
        `alter table ${t} force row level security;`
      )
    } else if (POLICY_KINDS.has(kind) || (kind.startsWith('storage_') && POLICY_KINDS.has(kind.slice(8)))) {
      const parts = splitPolicyObject(f.object)
      if (!parts) continue
      const tableSql = kind.startsWith('storage_') ? 'storage.objects' : qualified(schema, parts.table)
      addTodo(
        `${f.object}: ${f.detail}\nRewrite the policy with a real owner check. Never "fix" it with USING (true) or by disabling RLS.`,
        policyTemplate(tableSql, parts.policy, commandOf(f.detail))
      )
    } else if (kind === 'realtime_exposure') {
      const t = qualified(schema, strip(f.object, 'realtime:'))
      addTodo(
        `${f.object}: fix the table's read policy first; or stop streaming it if nothing needs live updates.`,
        `alter publication supabase_realtime drop table ${t};`
      )
    } else if (kind === 'bypassrls_role') {
      const r = quoteIdent(strip(f.object, 'role:'))
      addTodo(`${f.object}: confirm this role really needs to bypass RLS. If not:`, `alter role ${r} nobypassrls;`)
    } else if (kind === 'anon_read_leak') {
      const t = qualified(schema, f.object)
      addTodo(
        `${f.object}: a live request with the anon key read rows. Fix the policy above; if anonymous visitors should see nothing at all:`,
        `revoke select on ${t} from anon;`
      )
    } else if (kind === 'anon_write_leak') {
      const t = qualified(schema, f.object)
      addTodo(
        `${f.object}: a live request with the anon key wrote to this table. Unless anonymous writes are a feature:`,
        `revoke insert, update, delete on ${t} from anon;`
      )
    } else if (NOT_SQL.has(kind)) {
      addTodo(`${f.object}: not a database fix — see the report (rotate the secret / fix the deploy).`, '')
    }
    // Everything else (allow_*, scan_truncated, nothing_audited, check_skipped,
    // helper_scoped...) is bookkeeping with nothing to change in the schema.
  }

  const lines = [
    `-- Draft fix migration generated by airlock-rls v${version} on ${now.toISOString().slice(0, 10)}`,
    `-- for schema ${quoteIdent(schema)}.`,
    '--',
    '-- REVIEW BEFORE APPLYING. The statements below are the mechanical fixes;',
    '-- each note says what it can break. Everything that needs a decision about',
    '-- your app (who owns a row, what is public) is a commented TODO at the end.',
    '-- Re-run `npx airlock-rls` after applying to confirm the findings are gone.',
    '',
    'begin;',
    '',
  ]
  if (fixes.length) {
    for (const x of fixes) lines.push(comment(x.note), x.sql, '')
  } else {
    lines.push('-- No mechanical fixes for this audit.', '')
  }
  lines.push('commit;', '')
  if (todos.length) {
    lines.push('-- ===================================================================', '-- TODO: needs a human decision (commented out on purpose)', '-- ===================================================================', '')
    for (const x of todos) {
      lines.push(comment('TODO ' + x.note))
      if (x.sql) lines.push(comment(x.sql))
      lines.push('')
    }
  }
  return { sql: lines.join('\n'), statements: fixes.length, todos: todos.length }
}
