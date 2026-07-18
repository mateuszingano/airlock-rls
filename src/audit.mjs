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

/** Strip one or more fully-enclosing paren pairs: "((x))" → "x". */
function stripOuterParens(s) {
  s = s.trim()
  while (s.startsWith('(') && s.endsWith(')')) {
    let depth = 0
    let matches = true
    for (let i = 0; i < s.length; i++) {
      if (s[i] === '(') depth++
      else if (s[i] === ')') {
        depth--
        if (depth === 0 && i < s.length - 1) { matches = false; break }
      }
    }
    if (matches) s = s.slice(1, -1).trim()
    else break
  }
  return s
}

/**
 * Is this single boolean term ALWAYS true, so it can't scope anything?
 *  - the literal `true`
 *  - a reflexive equality — both sides the identical literal OR column:
 *    `1=1`, `2=2`, `'a'='a'`, `owner_id = owner_id`
 *  - a constant comparison that holds: `1<2`, `5>=5`, `'a'<>'b'`
 *  - a constant IN a constant list: `1 in (1)`, `'a' in ('a','b')`
 *  - a non-negative built-in the comparison can't falsify: `length(x) >= 0`,
 *    `char_length(x) > -1` (these functions return an int >= 0)
 * (`1=2` and `a=b` are NOT tautologies and stay false.)
 */
function isAlwaysTrueTerm(term) {
  const s = stripOuterParens(term)
  if (s === 'true') return true
  // A sub-expression that itself has a top-level OR is always-true if ANY of its
  // disjuncts is — recurse, so a NESTED tautology like `(a OR 2=2)` is caught.
  const disj = splitTopLevelOr(s)
  if (disj.length > 1) return disj.some(isAlwaysTrueTerm)
  const OPERAND = "'[^']*'|[\\w.]+"
  // reflexive: same operand on both sides of `=` (covers lit=lit AND col=col)
  const refl = new RegExp(`^(${OPERAND})\\s*=\\s*(${OPERAND})$`).exec(s)
  if (refl && refl[1] === refl[2]) return true
  // constant OP constant → evaluate (both sides number, or both string)
  const cmp = new RegExp(`^(-?\\d+(?:\\.\\d+)?|'[^']*')\\s*(=|<>|!=|<=|>=|<|>)\\s*(-?\\d+(?:\\.\\d+)?|'[^']*')$`).exec(s)
  if (cmp) {
    const [, a, op, b] = cmp
    const aStr = a.startsWith("'"), bStr = b.startsWith("'")
    if (aStr !== bStr) return false // mixed types — don't guess
    const va = aStr ? a : parseFloat(a)
    const vb = bStr ? b : parseFloat(b)
    switch (op) {
      case '=': return va === vb
      case '<>': case '!=': return va !== vb
      case '<': return va < vb
      case '>': return va > vb
      case '<=': return va <= vb
      case '>=': return va >= vb
    }
  }
  // constant IN a constant list → always-true iff the constant is in the list:
  //   `1 in (1)`, `1 in (1, 2)`, `'a' in ('a','b')`. A column or subquery
  //   (`email in (select ...)`) is NOT constant, so it stays scoped/unevaluated.
  const inm = new RegExp(`^(${OPERAND})\\s+in\\s*\\((.+)\\)$`).exec(s)
  if (inm) {
    const needle = inm[1]
    const CONST = /^(-?\d+(?:\.\d+)?|'[^']*')$/
    if (!CONST.test(needle)) return false // left side is a column — can't decide
    const list = splitTopLevelCommas(inm[2]).map((x) => x.trim())
    if (list.length && list.every((x) => CONST.test(x))) return list.includes(needle)
    return false
  }
  // a non-negative built-in compared so the result ALWAYS satisfies it:
  //   `length(x) >= 0`, `char_length(x) > -1`, `octet_length(x) <> -1`.
  // These functions return an integer >= 0, so the predicate can never be false.
  const NONNEG = 'length|char_length|character_length|octet_length|bit_length|cardinality'
  const nn = new RegExp(`^(?:${NONNEG})\\s*\\(.*\\)\\s*(>=|>|<>|!=)\\s*(-?\\d+(?:\\.\\d+)?)$`).exec(s)
  if (nn) {
    const op = nn[1], n = parseFloat(nn[2])
    if (op === '>=') return n <= 0          // r >= n holds for all r >= 0 when n <= 0
    if (op === '>') return n < 0            // r >  n holds for all r >= 0 when n <  0
    if (op === '<>' || op === '!=') return n < 0 // r is never negative
  }
  return false
}

/** Split on commas at paren-depth 0 (for an `IN (a, b, c)` list). */
function splitTopLevelCommas(q) {
  const parts = []
  let depth = 0
  let last = 0
  for (let i = 0; i < q.length; i++) {
    if (q[i] === '(') depth++
    else if (q[i] === ')') depth--
    else if (depth === 0 && q[i] === ',') { parts.push(q.slice(last, i)); last = i + 1 }
  }
  parts.push(q.slice(last))
  return parts
}

/** Split a boolean expression on `OR` at paren-depth 0. */
function splitTopLevelOr(q) {
  const parts = []
  let depth = 0
  let last = 0
  for (let i = 0; i < q.length; i++) {
    if (q[i] === '(') depth++
    else if (q[i] === ')') depth--
    else if (depth === 0 && q.startsWith(' or ', i)) { parts.push(q.slice(last, i)); i += 3; last = i + 1 }
  }
  parts.push(q.slice(last))
  return parts.map((p) => p.trim())
}

/**
 * Does this qualifier always evaluate true, so it can't scope anything? A scope
 * token is neutralised when a tautology is OR-joined to it (`auth.uid() = owner
 * OR 2=2`) or IS the whole qualifier (`1=1`, `(true)`, `owner_id = owner_id`).
 * A tautology joined only by AND does NOT neutralise the scope, so we only look
 * at top-level OR disjuncts (and the whole expression).
 */
export function isPermissiveTautology(qual) {
  if (qual == null) return false
  // isAlwaysTrueTerm handles the parens, the top-level OR split, AND the recursion
  // into nested OR groups — one entry point covers `2=2`, `x OR 2=2`, `x OR (a OR 2=2)`.
  return isAlwaysTrueTerm(String(qual).toLowerCase().replace(/\s+/g, ' ').trim())
}

/** Is this single term provably ALWAYS FALSE (`false`, `1=2`, `'a'='b'`)? Such a
 *  term contributes nothing to an OR, so it doesn't widen access. */
function isAlwaysFalseTerm(term) {
  const s = stripOuterParens(term)
  if (s === 'false') return true
  const cmp = /^(-?\d+(?:\.\d+)?|'[^']*')\s*(=|<>|!=|<=|>=|<|>)\s*(-?\d+(?:\.\d+)?|'[^']*')$/.exec(s)
  if (!cmp) return false
  const [, a, op, b] = cmp
  const aStr = a.startsWith("'"), bStr = b.startsWith("'")
  if (aStr !== bStr) return false
  const va = aStr ? a : parseFloat(a)
  const vb = bStr ? b : parseFloat(b)
  switch (op) {
    case '=': return va !== vb
    case '<>': case '!=': return va === vb
    case '<': return !(va < vb)
    case '>': return !(va > vb)
    case '<=': return !(va <= vb)
    case '>=': return !(va >= vb)
    default: return false
  }
}

/**
 * FAIL-SAFE for the tautology hydra: a policy is "safely scoped" only if EVERY
 * top-level OR disjunct itself restricts to the caller (realScope) or is provably
 * false. If ANY OR branch is something the engine can't prove restricts —
 * `auth.uid()=x OR status='published'`, `OR (1=1 AND 2=2)`, `OR deleted_at IS
 * NULL`, `OR coalesce(true,false)` — the OR WIDENS access, so we must NOT pass it
 * silently. Returns true → caller emits a WARN (not a silent green). This closes
 * the whole class instead of enumerating tautology forms one by one.
 */
export function hasUnprovenOrBranch(qual) {
  if (qual == null) return false
  const disj = splitTopLevelOr(String(qual).toLowerCase().replace(/\s+/g, ' ').trim())
  if (disj.length <= 1) return false
  return !disj.every((d) => realScope(d) || isAlwaysFalseTerm(d))
}

/** The auth/session built-ins we understand precisely (a real, visible scope). */
function realScope(qual) {
  if (/auth\.uid\(\)|current_setting|auth\.jwt\(\)/i.test(qual)) return true
  if (/'service_role'/i.test(qual)) return true // restricted to the backend role
  return false
}

/**
 * First user-defined function call that could be a scoping helper — a static
 * scan can't see inside it, so it warrants a soft warn, not a pass or a hard
 * fail. Recognises ANY helper name (authorize(), belongs_to_org(), can_read(),
 * get_/is_/has_*), not just a fixed prefix. Ignores the built-ins we handle
 * precisely (auth.uid/jwt/role, current_setting) and the SQL keywords that take
 * parens (select/exists in subqueries). Returns null if none.
 */
function helperCall(qual) {
  const re = /\b((?:\w+\.)?\w+)\s*\(/g
  // Ignore the built-ins we handle precisely, the SQL keywords that take parens
  // (select/exists subqueries, the `in (…)` operator), and non-negative scalar
  // built-ins that only appear inside constant/tautological predicates — none of
  // these scope a row to the caller, so they must not read as a "real" helper.
  const skip = new Set([
    'auth.uid', 'auth.jwt', 'auth.role', 'current_setting', 'select', 'exists', 'in',
    'length', 'char_length', 'character_length', 'octet_length', 'bit_length', 'cardinality',
  ])
  let m
  while ((m = re.exec(qual)) !== null) {
    if (!skip.has(m[1].toLowerCase())) return m[1]
  }
  return null
}

/**
 * Does this policy qualifier scope access (so it's not an open anon read)?
 * Recognises the real Supabase patterns:
 *  - per-user: auth.uid() / current_setting / auth.jwt()
 *  - restricted to a backend role: auth.role() = 'service_role' (NOT
 *    'authenticated'/'anon' — those stay flagged as role-only)
 *  - scoping through a helper function of ANY name (see helperCall)
 * A tautology (`... OR true`, `1=1`) never counts as scoped, even when a scope
 * token is also present.
 */
export function isScoped(qual) {
  if (qual == null) return false
  if (isPermissiveTautology(qual)) return false
  if (realScope(qual)) return true
  if (helperCall(qual)) return true
  return false
}

/**
 * If a policy is scoped ONLY through a helper function (no auth.uid()/service_role
 * we can see), return the helper name — a static scan can't tell whether the
 * helper actually restricts (is_public() would leak). Used to emit a soft warn.
 */
export function helperScope(qual) {
  if (qual == null) return null
  if (isPermissiveTautology(qual)) return null
  if (realScope(qual)) return null
  return helperCall(qual)
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
  const taut = isPermissiveTautology(p.qual)
  const scoped = isScoped(p.qual) // false when taut (isScoped short-circuits on tautology)
  const readish = READ_CMDS.has(p.cmd)
  const writeish = WRITE_CMDS.has(p.cmd)

  // Which roles this policy actually exposes for reads/writes (role applies AND
  // the role holds the matching table GRANT — no grant means no exposure).
  const anonRead = includesAnon(p.roles) && hasGrant(grants, 'anon', 'SELECT')
  const authRead = includesAuthenticated(p.roles) && hasGrant(grants, 'authenticated', 'SELECT')
  const writePriv = p.cmd === 'UPDATE' ? 'UPDATE' : 'INSERT'
  const anonWrite = includesAnon(p.roles) && hasGrant(grants, 'anon', writePriv)
  const authWrite = includesAuthenticated(p.roles) && hasGrant(grants, 'authenticated', writePriv)

  // 1) Read side. A literal `true`, a tautology (`... OR true`, `1=1`), or any
  // non-scoping qualifier all expose rows.
  if (readish && (p.qual === 'true' || taut || (p.qual != null && !scoped))) {
    const literal = p.qual === 'true' || taut
    const how = p.qual === 'true' ? 'USING(true)' : `USING (${short(p.qual)}) always evaluates true`
    if (anonRead) {
      const saved = restrictiveScopes(restrictives, p.cmd, 'anon')
      out.push({
        kind: literal ? 'permissive_true' : 'anon_unscoped',
        severity: saved ? 'warn' : 'fail',
        object,
        detail: literal
          ? `[${p.cmd}] ${how} — anon reads every row${saved ? ' (a restrictive policy narrows it — verify)' : ''}`
          : `[${p.cmd}] anon reads without scoping to a user — USING (${short(p.qual)})${saved ? ' (restrictive-narrowed — verify)' : ''}`,
      })
    } else if (authRead) {
      out.push({
        kind: literal ? 'permissive_true' : 'authenticated_unscoped',
        severity: 'warn',
        object,
        detail: `[${p.cmd}] any authenticated user reads all rows${literal ? ` — ${how}` : ` (no auth.uid()) — USING (${short(p.qual)})`}`,
      })
    }
  }

  // 1b) Helper-scoped and client-reachable: static analysis can't see inside the
  // helper, so warn (a helper that returns true for everyone would leak). Covers
  // anon AND authenticated — an authed-only helper that doesn't restrict lets any
  // logged-in user read every row, same failure mode a notch less exposed.
  if (readish && (anonRead || authRead)) {
    const helper = helperScope(p.qual)
    if (helper) {
      const who = anonRead ? 'anon' : 'any authenticated user'
      const prove = anonRead
        ? ' (add --url/--anon-key to prove it, or allow-list if intentional)'
        : ' (allow-list it if intentional)'
      out.push({
        kind: 'helper_scoped',
        severity: 'warn',
        object,
        detail: `[${p.cmd}] ${who} read is scoped only through ${helper}() — a static scan can't see inside it; verify it restricts the caller${prove}`,
      })
    }
  }

  // 1c) FAIL-SAFE. A real scope (auth.uid()) is present, but a top-level OR branch
  // widens access in a way the engine can't PROVE restricts — `... OR status =
  // 'published'`, `... OR (1=1 AND 2=2)`, `... OR deleted_at IS NULL`. This is the
  // architecture, not another form in the denylist: any OR branch we can't prove
  // restricts → WARN, never a silent green. (`taut` is already a fail above; a
  // fully user-scoped OR like `auth.uid()=a OR auth.uid()=b` proves out and is quiet.)
  if (readish && (anonRead || authRead) && !taut && scoped && hasUnprovenOrBranch(p.qual)) {
    const who = anonRead ? 'anon' : 'any authenticated user'
    out.push({
      kind: 'or_branch_unscoped',
      severity: 'warn',
      object,
      detail: `[${p.cmd}] scoped by auth.uid() but an OR branch widens it — ${who} may read rows outside the caller: USING (${short(p.qual)}). Prove the branch restricts (add --url/--anon-key) or allow-list if it's intentional public sharing.`,
    })
  }

  // 2) Write side — WITH CHECK literal-true, tautology, present-but-unscoped, or
  // missing, but only if a role can actually write.
  if (writeish && (anonWrite || authWrite)) {
    const wc = p.with_check
    const wcTaut = wc === 'true' || isPermissiveTautology(wc)
    const saved = restrictiveScopes(restrictives, p.cmd, anonWrite ? 'anon' : 'authenticated')
    if (wcTaut) {
      out.push({
        kind: 'permissive_true',
        severity: saved ? 'warn' : 'fail',
        object,
        detail: `[${p.cmd}] WITH CHECK(${wc === 'true' ? 'true' : short(wc)}) always passes — writes are not tied to the caller (a row can be forged as anyone)${saved ? ' (restrictive-narrowed — verify)' : ''}`,
      })
    } else if (wc != null && wc !== '' && !isScoped(wc)) {
      // A WITH CHECK is present but doesn't scope the new row to the caller, so
      // anon (or any authenticated user) can INSERT rows attributed to another
      // tenant. anon → fail; authenticated-only → warn (a notch less exposed).
      out.push({
        kind: 'write_unscoped',
        severity: anonWrite && !saved ? 'fail' : 'warn',
        object,
        detail: `[${p.cmd}] WITH CHECK (${short(wc)}) doesn't tie the row to the caller — ${anonWrite ? 'anon' : 'any authenticated user'} can forge rows as another tenant${saved ? ' (restrictive-narrowed — verify)' : ''}`,
      })
    } else if ((wc == null || wc === '') && !scoped && p.qual !== 'true' && !taut) {
      // When WITH CHECK is omitted, Postgres uses the USING expression as the
      // check for new/updated rows. So this is only an unguarded write when
      // USING doesn't scope (and isn't a literal-true/tautology case, already flagged).
      out.push({
        kind: 'write_unchecked',
        severity: 'warn',
        object,
        detail: `[${p.cmd}] no WITH CHECK and USING doesn't scope to the caller — writes aren't tied to the tenant`,
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
      const grantee = String(g.grantee).toLowerCase()
      // A grant to PUBLIC is held by every role — including anon and authenticated.
      if (grantee === 'public') {
        t.anon.add(g.privilege_type)
        t.authenticated.add(g.privilege_type)
      } else if (t[grantee]) {
        t[grantee].add(g.privilege_type)
      }
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
  // Supabase connections use TLS with a cert that isn't in the system CA bundle
  // (and its default `sslmode=require` is now treated as verify-full by pg,
  // which fails with "self-signed certificate in certificate chain"). Detect an
  // SSL/Supabase connection and connect encrypted without cert pinning. Local
  // plaintext connections (no sslmode, localhost) keep working untouched.
  const usesSsl = /sslmode=(require|verify|prefer)|\.supabase\.(co|com)/i.test(dbUrl)
  // Honesty: if the caller explicitly asked for cert verification, say out loud
  // (on stderr — never stdout, so --json stays clean) that we're overriding it.
  if (usesSsl && /sslmode=verify-(full|ca)/i.test(dbUrl)) {
    console.warn(
      "airlock: overriding sslmode=verify-* — connecting over TLS but WITHOUT certificate verification " +
        "(Supabase's cert isn't in the system CA bundle). Encrypted, not MitM-proof. See SECURITY.md."
    )
  }
  // Strip sslmode from the URL (pg would parse `require` as verify-full and fail
  // on Supabase's cert chain) and set our own ssl config instead.
  const cleanUrl = usesSsl
    ? dbUrl
        .replace(/([?&])sslmode=[^&]*/gi, '$1')
        .replace(/\?&/g, '?')
        .replace(/&&/g, '&')
        .replace(/[?&]$/g, '')
    : dbUrl
  const client = new pg.Client({
    connectionString: cleanUrl,
    ...(usesSsl ? { ssl: { rejectUnauthorized: false } } : {}),
  })
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
        where table_schema = $1 and grantee in ('anon','authenticated','PUBLIC')`,
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
