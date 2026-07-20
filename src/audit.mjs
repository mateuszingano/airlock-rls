// Airlock — the CI gate for Supabase RLS.
//
// Core audit logic, framework-free so the CLI, the GitHub Action and the DAST
// probe in THIS package all share one source of truth. (The hosted Monitor does
// NOT import this file — it carries its own vendored copy; see the ⚠️ note below.)
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

import {
  isTautology as coreIsTautology,
  restrictsToCallerQual,
  helperCallQual,
  hasUnprovenOrBranch as coreHasUnprovenOrBranch,
} from './scope.mjs'

// ── Qualifier predicates ────────────────────────────────────────────────────
// These used to reason about the qualifier with regexes (paren counting, `or`
// splitting on raw text). That is fundamentally unsafe: a string literal holding
// a parenthesis (`note = '('`) unbalances the count and hides a top-level
// `OR 1=1`, so a policy that leaks every row passed green. They now delegate to
// `./scope.mjs`, which decides on a REAL SQL parse tree, where a string literal
// is just a leaf and can never change the structure.
//
// ⚠️ The Monitor does NOT share this engine. It carries its own vendored copy at
// `airlock-monitor/src/lib/monitor/scope.ts`. A fix here does NOT land there —
// apply it in both. (A shared `airlock-core` package was tried and rejected: a
// `file:../` dep breaks the Monitor's Vercel deploy, since the sibling folder
// does not exist in the cloned repo.)

/**
 * Does this qualifier always evaluate true, so it can't scope anything?
 * Covers `true`, `1=1`, `owner_id = owner_id`, `NOT FALSE`, `NULL IS NULL`,
 * `TRUE::bool`, `coalesce(true, …)`, `1 in (1)`, `length(x) >= 0`, and the same
 * shapes nested inside any OR group.
 */
export function isPermissiveTautology(qual) {
  return coreIsTautology(qual)
}

/**
 * FAIL-SAFE for the tautology hydra: a policy is "safely scoped" only if EVERY
 * top-level OR disjunct itself restricts to the caller or is provably false. If
 * ANY branch can't be proven to restrict — `auth.uid()=x OR status='published'`,
 * `OR is_public`, `OR coalesce(true,false)` — the OR WIDENS access, so the caller
 * emits a WARN rather than a silent green. An unparseable qualifier counts as
 * unproven, never as safe.
 */
export function hasUnprovenOrBranch(qual) {
  return coreHasUnprovenOrBranch(qual)
}

/**
 * A real, visible scope: the caller identity (auth.uid()/auth.jwt()/
 * current_setting) COMPARED to a per-row value, or the backend-role restriction
 * `auth.role() = 'service_role'`. Being merely PRESENT is not enough —
 * `auth.uid() IS NOT NULL`, `auth.uid() = auth.uid()` and friends scope nothing.
 * A data column compared to the string 'service_role' is NOT a backend
 * restriction (that was a real false-negative in the regex engine).
 */
function realScope(qual) {
  return restrictsToCallerQual(qual)
}

/**
 * First user-defined function call that could be a scoping helper — a static
 * scan can't see inside it, so it warrants a soft warn, not a pass or a hard
 * fail. Built-ins we understand precisely (auth.*, current_setting, coalesce,
 * length, …) are ignored. Returns null if none.
 */
function helperCall(qual) {
  return helperCallQual(qual)
}

/**
 * Does this policy qualifier scope access (so it's not an open anon read)?
 *  - per-user: the caller token compared to a row value
 *  - restricted to the backend role: auth.role() = 'service_role'
 *  - scoping through a helper function of any name (see helperCall)
 * A tautology never counts as scoped, even when a scope token is also present.
 */
export function isScoped(qual) {
  if (qual == null) return false
  if (isPermissiveTautology(qual)) return false
  if (realScope(qual)) return true
  if (helperCall(qual)) return true
  return false
}

/**
 * If a policy is scoped ONLY through a helper function (no auth.uid()/
 * service_role we can see), return the helper name — a static scan can't tell
 * whether the helper actually restricts (is_public() would leak). Used to emit
 * a soft warn.
 */
export function helperScope(qual) {
  if (qual == null) return null
  if (isPermissiveTautology(qual)) return null
  if (realScope(qual)) return null
  return helperCall(qual)
}


/**
 * Normalize a role list to lowercase, trimmed, quote-free strings.
 *
 * `pg_policies.roles` comes back lowercase from a live database, so the raw
 * comparisons below worked for the `audit()` path — but `classifyPolicy` and
 * `buildResult` are exported and documented as reusable (the monitor consumes
 * them, and so could a migration parser or a .sql dump reader). Any caller
 * feeding rows from another source hit silent misses: `['ANON']` matched
 * nothing, so a wide-open policy classified as invisible. Note the author DID
 * normalize `permissive` (isRestrictive upper-cases it) and simply didn't carry
 * that through to cmd/roles — asymmetry, not intent.
 */
function normRoles(roles = []) {
  // `pg_policies.roles` is `name[]` (OID 1003), and node-pg has NO parser
  // registered for that type — it hands back the raw wire string `"{anon}"`,
  // never a JS array.
  //
  // The original code was `roles.includes('anon')`, which worked by ACCIDENT:
  // String.prototype.includes did a substring match on `"{anon}"`. Wrapping a
  // non-array in `[roles]` turned that accident into exact equality against the
  // literal `"{anon}"`, and every role check silently returned false — which
  // made EVERY policy rule a no-op against a real database. Proven end to end:
  // a payments table with `FOR SELECT TO anon USING (true)` audited clean while
  // anon read the card numbers.
  //
  // So parse the wire form explicitly instead of relying on either accident.
  const list = Array.isArray(roles)
    ? roles
    : String(roles ?? '')
        .replace(/^\{|\}$/g, '') // {anon,authenticated} → anon,authenticated
        .split(',')
  return list.map((r) => String(r ?? '').replace(/"/g, '').trim().toLowerCase()).filter(Boolean)
}

/** Normalize a policy command to the upper-case form the command sets use. */
function normCmd(cmd) {
  return String(cmd ?? '').trim().toUpperCase()
}

/**
 * Roles that include the anonymous (public API) caller. `reachable` is the set
 * of roles a client connecting as anon actually holds (itself + every role
 * granted to it, computed by audit() via pg_has_role); when present it catches
 * a policy `TO custom_role` where custom_role was granted to anon. Absent (unit
 * tests, non-DB callers) → literal matching only, the original behaviour.
 */
function includesAnon(roles = [], reachable = null) {
  const r = normRoles(roles)
  if (r.includes('anon') || r.includes('public')) return true
  if (reachable) return r.some((x) => reachable.has(x))
  return false
}
function includesAuthenticated(roles = [], reachable = null) {
  const r = normRoles(roles)
  if (r.includes('authenticated') || r.includes('public')) return true
  if (reachable) return r.some((x) => reachable.has(x))
  return false
}

// `ALL` is not a fifth command — it is the SET of the four. Expanding it in one
// place, and asking every downstream question per CONCRETE command, is the fix
// for a whole family of findings: `writePriv` collapsed ALL to INSERT alone (so
// `FOR ALL` + a UPDATE-only grant produced no finding), and the restrictive
// rescue asked "does a restrictive cover ALL?" instead of "does one cover the
// SELECT slice / the DELETE slice / …", so a legitimate per-command restrictive
// set never narrowed a FOR ALL policy. Both are the same mistake: treating the
// set as an atom.
const ALL_COMMANDS = ['SELECT', 'INSERT', 'UPDATE', 'DELETE']
function commandsOf(cmd) {
  const c = normCmd(cmd)
  return c === 'ALL' ? ALL_COMMANDS : [c]
}

const READ_CMDS = new Set(['SELECT', 'ALL'])
const WRITE_CMDS = new Set(['INSERT', 'UPDATE', 'ALL'])
// DELETE was in NEITHER set, so `FOR DELETE` fell through every branch and
// produced zero findings: `CREATE POLICY d ON payments FOR DELETE TO anon
// USING (true)` passed the gate green while letting anyone with the anon key
// empty the table. It needs its own set because it is neither a read nor a
// write in the WITH CHECK sense — DELETE has no WITH CHECK at all; the USING
// expression alone decides which rows may be destroyed.
const DELETE_CMDS = new Set(['DELETE', 'ALL'])

function isRestrictive(p) {
  return String(p.permissive).toUpperCase() === 'RESTRICTIVE'
}

/**
 * Is this policy waved through by the allow-list?
 *
 * Policy names are unique PER TABLE in Postgres, not per schema — `public_read`
 * on a status page and `public_read` on `payments` are different objects that
 * happen to share a name. Matching on the bare name silenced both: allow-listing
 * the intentionally-public status page also muted a real finding on payments,
 * and would keep muting it as new tables reused the name.
 *
 * Accepts `table.policy` (qualified, always unambiguous) and the bare `policy`
 * (kept for compatibility, and correct whenever the name is used once).
 */
function policyAllowed(allowSet, p, tablesByPolicyName) {
  const qualified = `${p.tablename}.${p.policyname}`
  if (allowSet.has(qualified)) return qualified
  // A bare policy name is only unambiguous when exactly one table carries it.
  // "public_read" is a name people reuse on every table; honouring it bare
  // would silence tables the author never looked at. When it is ambiguous we
  // refuse to apply it and say so (see `allow_ambiguous`), rather than
  // silently waiving findings across the schema.
  if (!allowSet.has(p.policyname)) return null
  const tables = tablesByPolicyName.get(p.policyname)
  return tables && tables.size === 1 ? p.policyname : null
}

/**
 * The allow-list is ONE flat namespace, but it silences SIX different kinds of
 * object: policies, storage buckets, SECURITY DEFINER functions, realtime
 * tables, views and materialized views. A bucket, a view and a policy all named
 * `reports` are different objects; `--allow reports` used to mute all of them at
 * once, including a `matview_exposed` FAIL the author never saw and never
 * intended to waive.
 *
 * So everything that is not a policy must be qualified with its namespace —
 * the same prefix already printed in the finding's `object` field
 * (`storage:`, `fn:`, `realtime:`, `view:`, `matview:`). A bare name that would
 * have matched here no longer silences anything; it raises `allow_needs_namespace`
 * telling the author the exact spelling to use.
 */
function nsAllowed(allowSet, used, ns, ...names) {
  for (const n of names) {
    if (n == null || n === '') continue
    const entry = `${ns}:${n}`
    if (allowSet.has(entry)) {
      used.add(entry)
      return entry
    }
  }
  return null
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
 * Does this RESTRICTIVE policy apply to the command the finding is about?
 *
 * A restrictive FOR SELECT narrows only reads. The old check accepted
 * `cmd === 'ALL'` on the PERMISSIVE side, which meant a restrictive on ONE
 * command was taken as narrowing all four: `FOR ALL TO anon USING (true)` was
 * downgraded to a warn by a restrictive that only guarded SELECT, while anon
 * still deleted every row.
 */
function restrictiveCovers(r, cmd) {
  const rc = normCmd(r.cmd)
  if (rc === 'ALL') return true
  // A permissive FOR ALL exposes every command — only a restrictive FOR ALL
  // narrows every command.
  if (cmd === 'ALL') return false
  return rc === cmd
}

/**
 * Is there a RESTRICTIVE policy on this table that scopes the same command for
 * this role to the current user? A restrictive scope neutralises a permissive
 * leak (Postgres ANDs restrictive policies in), so we downgrade fail → warn.
 *
 * `side` picks WHICH EXPRESSION actually runs, because USING and WITH CHECK
 * answer different questions and a restrictive policy can scope one while
 * leaving the other wide open:
 *
 *   - 'using' — which EXISTING rows are reachable (SELECT, DELETE, UPDATE
 *     targeting). Decided by the restrictive's USING.
 *   - 'check' — what a NEW/updated row may look like (INSERT, UPDATE value).
 *     Decided by the restrictive's WITH CHECK, and Postgres falls back to
 *     USING only when WITH CHECK is omitted.
 *
 * This used to read `isScoped(r.qual)` for every case, so
 * `RESTRICTIVE ... USING (owner = auth.uid()) WITH CHECK (true)` was taken as
 * narrowing INSERT — it narrows nothing there. A permissive policy that lets
 * anon forge rows as another tenant was reported as a warn ("restrictive-
 * narrowed — verify") instead of the fail it is.
 */
function restrictiveScopes(restrictives, cmd, role, side = 'using') {
  return restrictives.some((r) => {
    if (!restrictiveCovers(r, cmd)) return false
    const roles = normRoles(r.roles)
    if (!roles.includes(role) && !roles.includes('public')) return false
    const wc = r.with_check
    const expr = side === 'check' && wc != null && wc !== '' ? wc : r.qual
    return isScoped(expr)
  })
}

/**
 * A finding that spans MORE than one concrete command (the write side of a
 * `FOR ALL` policy exposes both INSERT and UPDATE) is only rescued when a
 * restrictive narrows EVERY command in the set. A restrictive that scopes only
 * INSERT does not make the UPDATE-forge safe — requiring all-of prevents the
 * per-command restrictive fix from re-opening the very leak it was meant to
 * close, one abstraction level up.
 */
function restrictiveScopesEvery(restrictives, cmds, role, side = 'using') {
  return cmds.length > 0 && cmds.every((c) => restrictiveScopes(restrictives, c, role, side))
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
  const { grants = null, restrictives = [], clientRoles = null } = ctx
  const anonRoles = clientRoles?.anon || null
  const authRoles = clientRoles?.authenticated || null
  // A RESTRICTIVE policy only narrows access — it can never be the cause of a leak.
  if (isRestrictive(p)) return []

  // Normalize the command ONCE, up front, and use it everywhere below — the raw
  // `cmd` was compared against upper-case sets, so a lower-case 'select' from
  // any non-pg_policies source silently matched no branch at all.
  const cmd = normCmd(p.cmd)
  const object = `${p.tablename}."${p.policyname}"`
  const out = []
  const taut = isPermissiveTautology(p.qual)
  const scoped = isScoped(p.qual) // false when taut (isScoped short-circuits on tautology)
  const readish = READ_CMDS.has(cmd)
  const writeish = WRITE_CMDS.has(cmd)
  const deleteish = DELETE_CMDS.has(cmd)
  // Set by the write branch when it judged the USING expression IN ITS ROLE AS
  // THE CHECK (WITH CHECK omitted). That is the only case where the UPDATE
  // row-targeting section below would repeat what was already said. See the
  // note there — this used to be inferred from the finding text.
  let usingJudgedAsCheck = false

  // Which roles this policy actually exposes for reads/writes (role applies AND
  // the role holds the matching table GRANT — no grant means no exposure).
  const anonRead = includesAnon(p.roles, anonRoles) && hasGrant(grants, 'anon', 'SELECT')
  const authRead = includesAuthenticated(p.roles, authRoles) && hasGrant(grants, 'authenticated', 'SELECT')
  // The write privileges this policy's command actually implies. For a plain
  // INSERT/UPDATE it is that one; for `FOR ALL` it is BOTH — and a role that
  // holds EITHER can write. The old `cmd === 'UPDATE' ? 'UPDATE' : 'INSERT'`
  // checked only INSERT for `FOR ALL`, so `FOR ALL USING (true)` + a
  // grant of UPDATE-but-not-INSERT produced zero findings while anon rewrote
  // every row (proven on Postgres). Ask for the whole set the command implies.
  const writeCmds = commandsOf(cmd).filter((c) => c === 'INSERT' || c === 'UPDATE')
  const hasAnonWrite = writeCmds.some((c) => hasGrant(grants, 'anon', c))
  const hasAuthWrite = writeCmds.some((c) => hasGrant(grants, 'authenticated', c))
  const anonWrite = includesAnon(p.roles, anonRoles) && hasAnonWrite
  const authWrite = includesAuthenticated(p.roles, authRoles) && hasAuthWrite
  const anonDelete = includesAnon(p.roles, anonRoles) && hasGrant(grants, 'anon', 'DELETE')
  const authDelete = includesAuthenticated(p.roles, authRoles) && hasGrant(grants, 'authenticated', 'DELETE')

  // 1) Read side. A literal `true`, a tautology (`... OR true`, `1=1`), or any
  // non-scoping qualifier all expose rows.
  if (readish && (p.qual === 'true' || taut || (p.qual != null && !scoped))) {
    const literal = p.qual === 'true' || taut
    const how = p.qual === 'true' ? 'USING(true)' : `USING (${short(p.qual)}) always evaluates true`
    if (anonRead) {
      // Reads are narrowed by a restrictive on the SELECT slice (its USING),
      // never by one on some other command of a FOR ALL policy.
      const saved = restrictiveScopes(restrictives, 'SELECT', 'anon')
      out.push({
        kind: literal ? 'permissive_true' : 'anon_unscoped',
        severity: saved ? 'warn' : 'fail',
        object,
        detail: literal
          ? `[${cmd}] ${how} — anon reads every row${saved ? ' (a restrictive policy narrows it — verify)' : ''}`
          : `[${cmd}] anon reads without scoping to a user — USING (${short(p.qual)})${saved ? ' (restrictive-narrowed — verify)' : ''}`,
      })
    } else if (authRead) {
      const saved = restrictiveScopes(restrictives, 'SELECT', 'authenticated')
      out.push({
        kind: literal ? 'permissive_true' : 'authenticated_unscoped',
        // A LITERAL always-true for `authenticated` is a fail, not a nudge: in
        // any multi-tenant app it means every signed-up user reads every other
        // tenant's rows, which is the textbook IDOR. It used to be a warn, and
        // since warns never broke the build, the gate went green on it.
        // A merely UNSCOPED (not provably always-true) qualifier stays a warn —
        // there the scan genuinely can't tell intent. Both are allow-listable
        // when the openness is deliberate (a shared feed, a public directory).
        severity: literal && !saved ? 'fail' : 'warn',
        object,
        detail: `[${cmd}] any authenticated user reads all rows${literal ? ` — ${how}` : ` (no auth.uid()) — USING (${short(p.qual)})`}${saved ? ' (restrictive-narrowed — verify)' : ''}`,
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
        detail: `[${cmd}] ${who} read is scoped only through ${helper}() — a static scan can't see inside it; verify it restricts the caller${prove}`,
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
      detail: `[${cmd}] scoped by auth.uid() but an OR branch widens it — ${who} may read rows outside the caller: USING (${short(p.qual)}). Prove the branch restricts (add --url/--anon-key) or allow-list if it's intentional public sharing.`,
    })
  }

  // 2) Write side — WITH CHECK literal-true, tautology, present-but-unscoped, or
  // missing, but only if a role can actually write.
  if (writeish && (anonWrite || authWrite)) {
    const wc = p.with_check
    const wcTaut = wc === 'true' || isPermissiveTautology(wc)
    const role = anonWrite ? 'anon' : 'authenticated'
    // The finding here is about the VALUE of the new row, so only a restrictive
    // WITH CHECK narrows it — and for a `FOR ALL` policy the write spans both
    // INSERT and UPDATE, so EVERY one must be narrowed (a restrictive scoping
    // only INSERT does not make the UPDATE-forge safe).
    const saved = restrictiveScopesEvery(restrictives, writeCmds, role, 'check')
    if (wcTaut) {
      // A vacuous WITH CHECK on top of a vacuous USING: this one finding already
      // says the policy constrains nothing, so the targeting section below would
      // only restate it. When the USING is merely UNSCOPED (not provably
      // always-true) the targeting IS new information and must still be said.
      //
      // `!saved` is load-bearing. `saved` here speaks ONLY for the check side, so
      // a restrictive that scopes the new row while leaving USING open
      // (`RESTRICTIVE USING (true) WITH CHECK (owner = auth.uid())`) downgraded
      // this finding to a warn AND suppressed the targeting finding — the gate
      // opened on a proven row-takeover: every row is reachable because both
      // USINGs are true, and each rewrite passes the check by setting owner to
      // self. Suppress only when this finding stands as a fail on its own.
      if ((taut || p.qual === 'true') && !saved) usingJudgedAsCheck = true
      out.push({
        kind: 'permissive_true',
        severity: saved ? 'warn' : 'fail',
        object,
        detail: `[${cmd}] WITH CHECK(${wc === 'true' ? 'true' : short(wc)}) always passes — writes are not tied to the caller (a row can be forged as anyone)${saved ? ' (restrictive-narrowed — verify)' : ''}`,
      })
    } else if (wc != null && wc !== '' && !isScoped(wc)) {
      // A WITH CHECK is present but doesn't scope the new row to the caller, so
      // anon (or any authenticated user) can INSERT rows attributed to another
      // tenant. anon → fail; authenticated-only → warn (a notch less exposed).
      out.push({
        kind: 'write_unscoped',
        severity: anonWrite && !saved ? 'fail' : 'warn',
        object,
        detail: `[${cmd}] WITH CHECK (${short(wc)}) doesn't tie the row to the caller — ${anonWrite ? 'anon' : 'any authenticated user'} can forge rows as another tenant${saved ? ' (restrictive-narrowed — verify)' : ''}`,
      })
    } else if ((wc == null || wc === '') && !scoped) {
      // When WITH CHECK is omitted, Postgres uses the USING expression as the
      // check for new/updated rows — so an unscoped USING is an unguarded write.
      //
      // This branch used to carry `&& p.qual !== 'true' && !taut`, excluding the
      // WORST case on the grounds that a literal-true USING was "already flagged
      // above". It wasn't: the read branch is gated on READ_CMDS, and UPDATE is
      // not a READ_CMD. The exclusion pointed at a flag that never fired, so
      // `FOR UPDATE TO anon USING (true)` with no WITH CHECK produced zero
      // findings — while the SAME policy written with an explicit
      // `WITH CHECK (true)` was caught. Writing less SQL looked safer to the
      // gate than writing more.
      const literalUsing = p.qual === 'true' || taut
      const how = p.qual === 'true' ? 'USING(true)' : `USING (${short(p.qual)}) always evaluates true`
      // With WITH CHECK omitted the USING expression is BOTH the row filter and
      // the check, so a restrictive only rescues this when it narrows both
      // sides. Fail closed when either one is open.
      usingJudgedAsCheck = true
      const savedBoth = saved && restrictiveScopesEvery(restrictives, writeCmds, role, 'using')
      out.push({
        kind: literalUsing ? 'permissive_true' : 'write_unchecked',
        // A tautological USING with no WITH CHECK means anyone addressed by the
        // policy can rewrite any row: that is a fail, not a nudge. A merely
        // unscoped (but not always-true) USING stays a warn for anon, as before.
        severity: literalUsing && !savedBoth ? 'fail' : 'warn',
        object,
        detail: literalUsing
          ? `[${cmd}] ${how} and no WITH CHECK — Postgres applies USING as the check, so ${anonWrite ? 'anon' : 'any authenticated user'} can rewrite ANY row${savedBoth ? ' (restrictive-narrowed — verify)' : ''}`
          : `[${cmd}] no WITH CHECK and USING doesn't scope to the caller — writes aren't tied to the tenant`,
      })
    }
  }

  // 3) Delete side. DELETE has no WITH CHECK — the USING expression alone
  // decides which rows can be destroyed. An always-true or unscoped USING means
  // the addressed role can empty the table.
  //
  // `authenticated` is a FAIL here, not the warn it gets for reads: letting any
  // logged-in user delete another tenant's rows is destructive and
  // irreversible, which is strictly worse than letting them read those rows.
  if (deleteish && (p.qual === 'true' || taut || (p.qual != null && !scoped))) {
    const literal = p.qual === 'true' || taut
    const how = p.qual === 'true' ? 'USING(true)' : `USING (${short(p.qual)}) always evaluates true`
    const saved = restrictiveScopes(restrictives, 'DELETE', anonDelete ? 'anon' : 'authenticated')
    if (anonDelete || authDelete) {
      const who = anonDelete ? 'anon (anyone with the public key)' : 'any authenticated user'
      out.push({
        kind: literal ? 'permissive_true' : 'delete_unscoped',
        severity: saved ? 'warn' : 'fail',
        object,
        detail: `[DELETE] ${literal ? how : `USING (${short(p.qual)}) doesn't scope to the caller`} — ${who} can delete rows they don't own${saved ? ' (restrictive-narrowed — verify)' : ''}`,
      })
    }
  }

  // 4) UPDATE row TARGETING. `USING` and `WITH CHECK` answer different questions:
  // USING decides WHICH EXISTING ROWS the caller may update, WITH CHECK decides
  // what the resulting row may look like. A correct WITH CHECK does not make an
  // open USING safe.
  //
  // The write branch above only inspects USING when WITH CHECK is absent, so a
  // policy with a properly scoped WITH CHECK and `USING (true)` produced ZERO
  // findings — and that combination is a complete tenant takeover, proven on
  // Postgres:
  //
  //   CREATE POLICY upd ON notes FOR UPDATE TO app
  //     USING (true) WITH CHECK (owner = current_user);
  //   -- as bob, with no WHERE clause:
  //   UPDATE notes SET owner = 'bob', body = 'PWNED';   -- UPDATE 2  (alice's rows)
  //
  // Every row is targetable because USING is true, and each rewritten row passes
  // the check because bob sets himself as owner. Note the perverse inversion the
  // old shape produced: writing the CORRECT WITH CHECK blinded the gate, while
  // writing `WITH CHECK (true)` was caught.
  const updateish = cmd === 'UPDATE' || cmd === 'ALL'
  if (updateish && (p.qual === 'true' || taut || (p.qual != null && !scoped))) {
    const literal = p.qual === 'true' || taut
    // Targeting is the UPDATE slice, decided by USING, so only a restrictive
    // scoping the UPDATE command's USING narrows it.
    const saved = restrictiveScopes(restrictives, 'UPDATE', anonWrite ? 'anon' : 'authenticated', 'using')
    // Only report here when the write branch already judged this same USING
    // expression as the check (WITH CHECK omitted) — that finding says the same
    // thing.
    //
    // This used to be `out.some((f) => f.detail.startsWith('[' + cmd + ']'))`,
    // a match on the finding TEXT rather than on what was actually judged. Any
    // earlier finding carrying the same prefix swallowed this one, and for a
    // `FOR ALL` policy that is guaranteed: the read branch emits `[ALL] …`
    // first, so `FOR ALL TO anon USING (true) WITH CHECK (owner = auth.uid())`
    // reported the read leak and silently dropped the tenant takeover — the
    // exact finding this section exists to make. A soft `helper_scoped` warn on
    // an `[ALL]` policy did the same.
    if ((anonWrite || authWrite) && !usingJudgedAsCheck) {
      const who = anonWrite ? 'anon (anyone with the public key)' : 'any authenticated user'
      out.push({
        kind: 'update_using_unscoped',
        // Row takeover destroys data and is irreversible, so `authenticated` is
        // a fail here for the same reason DELETE is.
        severity: saved ? 'warn' : 'fail',
        object,
        detail: `[${cmd}] USING (${short(p.qual)})${literal ? ' always evaluates true' : " doesn't scope to the caller"} — ${who} can target ANY row for update. A scoped WITH CHECK only constrains the new value; it does not stop the row from being taken over${saved ? ' (restrictive-narrowed — verify)' : ''}`,
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
  matviews = [],
  storagePolicies = [],
  realtimeTables = [],
  grants = null,
  clientRoles = null,
  allow = new Set(),
  skipped = [],
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

  // Which tables carry each policy name? A name on more than one table cannot
  // be waived by its bare spelling.
  // Storage policies count too: they carry policy names from the same namespace
  // the author types into --allow, so leaving them out would let a bare name be
  // treated as unique when it is not.
  const tablesByPolicyName = new Map()
  for (const p of [...policies, ...storagePolicies.map((sp) => ({ ...sp, tablename: 'storage.objects' }))]) {
    const set = tablesByPolicyName.get(p.policyname) || new Set()
    set.add(p.tablename)
    tablesByPolicyName.set(p.policyname, set)
  }

  // Which --allow entries actually silenced something, and which bare names
  // would have silenced a non-policy object before namespaces were required.
  const usedAllow = new Set()
  const bareHits = new Map()
  const noteBare = (ns, ...names) => {
    for (const n of names) {
      if (n == null || n === '' || !allowSet.has(n)) continue
      const set = bareHits.get(n) || new Set()
      set.add(`${ns}:${n}`)
      bareHits.set(n, set)
    }
  }

  const allowed = []
  for (const p of policies) {
    const ctx = { grants: grantsFor(p.tablename), restrictives: restrictivesByTable[p.tablename] || [], clientRoles }
    for (const f of classifyPolicy(p, ctx)) {
      const hit = policyAllowed(allowSet, p, tablesByPolicyName)
      if (hit) {
        usedAllow.add(hit)
        allowed.push(f)
      } else findings.push(f)
    }
  }

  // Tell the author when an --allow entry did not apply, instead of leaving
  // them to believe a finding was waived.
  for (const entry of allowSet) {
    if (entry.includes('.')) continue
    const tables = tablesByPolicyName.get(entry)
    if (!tables || tables.size < 2) continue
    // Already explained to the author here, so don't also report it as unused.
    usedAllow.add(entry)
    findings.push({
      kind: 'allow_ambiguous',
      severity: 'warn',
      object: entry,
      detail: `--allow ${entry} was NOT applied: ${tables.size} tables carry a policy named "${entry}" (${[...tables].sort().join(', ')}). Qualify the one you mean, e.g. --allow ${[...tables].sort()[0]}.${entry}`,
    })
  }

  // Coverage beyond RLS policies.
  for (const b of publicBuckets) {
    const f = {
      kind: 'public_bucket',
      severity: 'warn',
      object: `storage:${b.id || b.name}`,
      detail: 'storage bucket is public — anyone with the URL can read its files',
    }
    if (nsAllowed(allowSet, usedAllow, 'storage', b.id, b.name)) allowed.push(f)
    else {
      noteBare('storage', b.id, b.name)
      findings.push(f)
    }
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
    if (nsAllowed(allowSet, usedAllow, 'fn', fn.proname)) allowed.push(f)
    else {
      noteBare('fn', fn.proname)
      findings.push(f)
    }
  }
  // Storage object-level policies (storage.objects) — same logic, prefixed.
  for (const p of storagePolicies) {
    for (const f of classifyPolicy({ ...p, tablename: 'storage.objects' }, { grants: null, restrictives: [], clientRoles })) {
      const hit = policyAllowed(allowSet, { ...p, tablename: 'storage.objects' }, tablesByPolicyName)
      if (hit) {
        usedAllow.add(hit)
        allowed.push(f)
      } else findings.push({ ...f, kind: 'storage_' + f.kind })
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
      if (nsAllowed(allowSet, usedAllow, 'realtime', name)) allowed.push(f)
      else {
        noteBare('realtime', name)
        findings.push(f)
      }
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
      if (nsAllowed(allowSet, usedAllow, 'view', v.viewname)) allowed.push(f)
      else {
        noteBare('view', v.viewname)
        findings.push(f)
      }
    }
  }
  // Materialized views: RLS has no effect on them whatsoever, so any client-role
  // grant is a full dump of whatever the matview selects. This is a FAIL, not a
  // warn — unlike a plain view, there is no `security_invoker` switch that could
  // make it safe. The only fixes are revoking the grant or moving it out of the
  // exposed schema.
  for (const mv of matviews) {
    if (!mv.anon_select && !mv.auth_select) continue
    const who = mv.anon_select ? 'anon (anyone with the public key)' : 'any authenticated user'
    const f = {
      kind: 'matview_exposed',
      severity: 'fail',
      object: `matview:${mv.matviewname}`,
      detail: `RLS does not apply to materialized views — ${who} can SELECT every row it holds. Revoke the grant, or move it to a schema PostgREST does not expose.`,
    }
    if (nsAllowed(allowSet, usedAllow, 'matview', mv.matviewname)) allowed.push(f)
    else {
      noteBare('matview', mv.matviewname)
      findings.push(f)
    }
  }

  // A bare name that would have silenced a non-policy object no longer does.
  // Say so with the exact spelling to use, instead of leaving the author to
  // believe the finding was waived.
  for (const [entry, targets] of bareHits) {
    usedAllow.add(entry)
    const forms = [...targets].sort()
    findings.push({
      kind: 'allow_needs_namespace',
      severity: 'warn',
      object: entry,
      detail: `--allow ${entry} was NOT applied: it matches ${forms.length > 1 ? 'objects' : 'an object'} outside the policy namespace (${forms.join(', ')}). Only policy names may be given bare, because one flat name would otherwise silence a bucket, view, function or matview that happens to share it. Use the qualified form, e.g. --allow ${forms[0]}.`,
    })
  }

  // Every waiver target that EXISTS in this database, whether or not it produced
  // a finding. A policy that is correct today produces nothing to waive, and the
  // entry guarding it is not stale — it is doing its job quietly. Keying
  // staleness off findings alone accused a well-kept allow-list of rot.
  const existingTargets = new Set()
  for (const p of [...policies, ...storagePolicies.map((sp) => ({ ...sp, tablename: 'storage.objects' }))]) {
    existingTargets.add(p.policyname)
    existingTargets.add(`${p.tablename}.${p.policyname}`)
  }
  for (const b of publicBuckets) {
    if (b.id) existingTargets.add(`storage:${b.id}`)
    if (b.name) existingTargets.add(`storage:${b.name}`)
  }
  for (const fn of secDefFns) existingTargets.add(`fn:${fn.proname}`)
  for (const v of views) existingTargets.add(`view:${v.viewname}`)
  for (const mv of matviews) existingTargets.add(`matview:${mv.matviewname}`)
  for (const t of realtimeTables) existingTargets.add(`realtime:${t.tablename || t}`)

  // An --allow entry that names nothing at all is a stale waiver: the object was
  // renamed or dropped, and the entry now protects nothing while reading like it
  // does. Accepting it in silence is how an allow-list rots into a blindfold.
  for (const entry of allowSet) {
    if (usedAllow.has(entry) || existingTargets.has(entry)) continue
    findings.push({
      kind: 'allow_unused',
      severity: 'warn',
      object: entry,
      detail: `--allow ${entry} matched nothing in this audit — the object was renamed, dropped, or never existed. Remove the entry, or fix its spelling: a waiver that applies to nothing is not protecting anything.`,
    })
  }

  // fail before warn, stable otherwise
  findings.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'fail' ? -1 : 1))

  // NOTHING AUDITED IS NOT THE SAME AS NOTHING WRONG.
  // Every catalog query filters on `schemaname = $1`, so a schema that does not
  // exist (a typo like `pubic`, or tables that moved to `app` while the workflow
  // still points at `public`) returns zero rows everywhere — and zero rows means
  // zero findings, which used to render as "✓ No RLS problems". The gate would
  // stay green forever while auditing nothing at all. Fail instead: a gate must
  // never report on a target it did not read.
  // The condition is "the catalog came back empty ACROSS THE BOARD" — not just
  // "no tables". If any query returned a row (a policy, a bucket, a function, a
  // view), we did read the database and the result means something. Only when
  // every single one is empty is it indistinguishable from having audited the
  // wrong target, which is the failure this guards (a wrong schema empties every
  // query at once — proven). Stating it this way also keeps focused unit tests
  // able to exercise one classifier without staging an entire schema.
  const readNothing =
    allTables.length === 0 &&
    policies.length === 0 &&
    noRls.length === 0 &&
    publicBuckets.length === 0 &&
    secDefFns.length === 0 &&
    views.length === 0 &&
    storagePolicies.length === 0 &&
    realtimeTables.length === 0 &&
    matviews.length === 0
  if (readNothing) {
    findings.unshift({
      kind: 'nothing_audited',
      severity: 'fail',
      object: schema,
      detail: `no tables or policies found in schema "${schema}" — nothing was audited`,
      fix: `Check the --schema value (and that the audit role can see it). An empty or misspelled schema is not proof that your RLS is correct.`,
    })
  }

  // A check that could not RUN is not a check that passed. Surface each one as a
  // warn so it appears in the report instead of vanishing — the caller can
  // escalate with --fail-on warn when a complete audit is required.
  for (const s of skipped) {
    findings.push({
      kind: 'check_skipped',
      severity: 'warn',
      object: s.check,
      detail: `this check did not run (${s.reason}) — its result is UNKNOWN, not clean. Grant the audit role read access, or re-run with a role that has it.`,
    })
  }

  const problems = findings.filter((f) => f.severity === 'fail').length
  const warnings = findings.filter((f) => f.severity === 'warn').length

  return {
    schema,
    findings,
    allowed,
    skipped,
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
    // Checks that could not RUN are surfaced (as check_skipped), never assumed
    // clean. Declared up front because the grants query below may push to it.
    const skipped = []
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
    //
    // This MUST NOT use information_schema.role_table_grants: that view only
    // returns rows where the CURRENT role is the grantor or a member of the
    // grantee. An audit role following the README's own advice (a least-
    // privilege, read-only role that is NOT a member of anon/authenticated) sees
    // ZERO rows there — no error, no exception — and every policy finding is then
    // silently suppressed, turning the whole gate green on a live leak. Proven:
    // a payments table `FOR SELECT TO anon USING (true)` audited clean as a
    // restricted role while anon read the card numbers.
    //
    // has_table_privilege() answers from the catalog regardless of who is asking
    // (it also folds in PUBLIC grants and role membership), so a restricted role
    // gets the true answer. It is the same function the matview/secDef queries
    // below already rely on. A FAILURE here becomes `null` — "unknown" — which
    // classifyPolicy treats as fail-open (assume granted). It must never collapse
    // to `[]`, which would read as "no grants" and re-hide every finding.
    let grants
    try {
      const res = await client.query(
        `select t.relname as table_name, roles.grantee, privs.privilege_type
           from pg_catalog.pg_class t
           join pg_catalog.pg_namespace n on n.oid = t.relnamespace
           cross join (values ('anon'),('authenticated')) as roles(grantee)
           cross join (values ('SELECT'),('INSERT'),('UPDATE'),('DELETE')) as privs(privilege_type)
          where n.nspname = $1
            and t.relkind in ('r','p')
            and to_regrole(roles.grantee) is not null
            and has_table_privilege(roles.grantee, t.oid, privs.privilege_type)`,
        [schema]
      )
      grants = res.rows
    } catch (err) {
      grants = null // unknown → fail-open in classifyPolicy, never a silent green
      skipped.push({ check: 'table grants', reason: err?.code ? `${err.code} ${err.message}` : String(err?.message || err) })
    }
    // Roles a client actually REACHES. A policy names roles literally (`TO
    // app_role`), but a custom role granted to `authenticated` (`GRANT app_role
    // TO authenticated`) is reached by every logged-in user WITHOUT `SET ROLE` —
    // so `FOR SELECT TO app_role USING (true)` leaks to all of them while
    // matching neither 'anon' nor 'authenticated' literally. The README called
    // this "undecidable statically"; for inherited membership it is not —
    // pg_has_role answers it from the catalog (caller-independent, like the
    // grants query). Role-switch via `authenticator` (SET ROLE) stays genuinely
    // undecidable and is out of scope here. Failure → null → literal-only
    // matching (the prior behaviour), never a crash.
    let clientRoles = null
    try {
      const res = await client.query(
        `select r.rolname,
                coalesce(to_regrole('anon') is not null and pg_has_role('anon', r.oid, 'MEMBER'), false) as anon_reach,
                coalesce(to_regrole('authenticated') is not null and pg_has_role('authenticated', r.oid, 'MEMBER'), false) as auth_reach
           from pg_catalog.pg_roles r
          where r.rolname not like 'pg\\_%'`
      )
      clientRoles = {
        anon: new Set(res.rows.filter((r) => r.anon_reach === true).map((r) => r.rolname)),
        authenticated: new Set(res.rows.filter((r) => r.auth_reach === true).map((r) => r.rolname)),
      }
    } catch (err) {
      clientRoles = null // unknown → literal-only role matching (prior behaviour)
      skipped.push({ check: 'role membership', reason: err?.code ? `${err.code} ${err.message}` : String(err?.message || err) })
    }
    const { rows: allTables } = await client.query(
      `select tablename from pg_catalog.pg_tables where schemaname = $1 order by tablename`,
      [schema]
    )
    // SECURITY DEFINER functions + who can EXECUTE them (anon running owner-priv
    // code is the real danger).
    const { rows: secDefFns } = await client.query(
      `select p.proname,
              coalesce(to_regrole('anon') is not null and has_function_privilege('anon', p.oid, 'EXECUTE'), false) as anon_exec,
              coalesce(to_regrole('authenticated') is not null and has_function_privilege('authenticated', p.oid, 'EXECUTE'), false) as auth_exec
         from pg_proc p join pg_namespace n on n.oid = p.pronamespace
        where n.nspname = $1 and p.prosecdef = true
        order by p.proname`,
      [schema]
    )
    // Optional checks that only exist on a Supabase database. Two very different
    // failures used to collapse into the same empty array:
    //   · 42P01 undefined_table  — "storage schema isn't here" (plain Postgres).
    //     Benign: there is genuinely nothing to audit.
    //   · 42501 insufficient_privilege — "you may not read this". The check did
    //     NOT RUN, and the report said nothing, so a CI using a restricted role
    //     (good practice!) got a green result while a public bucket stayed
    //     invisible forever.
    // Silence is only acceptable for the first. Everything else is recorded and
    // surfaced, because a gate must say which checks it could not perform.
    // (`skipped` is declared at the top of the try — the grants query feeds it.)
    const optional = async (name, run) => {
      try {
        return await run()
      } catch (err) {
        if (err?.code === '42P01') return [] // object absent — nothing to audit
        skipped.push({ check: name, reason: err?.code ? `${err.code} ${err.message}` : String(err?.message || err) })
        return []
      }
    }

    // Storage object-level RLS (policies on storage.objects).
    const storagePolicies = await optional('storage.objects policies', async () => {
      const { rows } = await client.query(
        `select tablename, policyname, cmd, roles, qual, with_check, permissive
           from pg_policies where schemaname = 'storage' and tablename = 'objects'`
      )
      return rows
    })
    // Realtime: tables published to the supabase_realtime publication.
    const realtimeTables = await optional('realtime publication', async () => {
      const { rows } = await client.query(
        `select tablename from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = $1`,
        [schema]
      )
      return rows
    })
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
    // MATERIALIZED views (relkind 'm'). RLS does not apply to a matview AT ALL —
    // there is no policy mechanism for them — so one built over a protected table
    // and granted to a client role is a complete, permanent dump of that table.
    // `pg_tables` and the relkind='v' query above both exclude them, so this was
    // a total blind spot: `CREATE MATERIALIZED VIEW public.everything AS SELECT *
    // FROM private_t` + `GRANT SELECT TO anon` audited perfectly clean.
    const { rows: matviews } = await client.query(
      `select c.relname as matviewname,
              coalesce(to_regrole('anon') is not null and has_table_privilege('anon', c.oid, 'SELECT'), false) as anon_select,
              coalesce(to_regrole('authenticated') is not null and has_table_privilege('authenticated', c.oid, 'SELECT'), false) as auth_select
         from pg_class c join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = $1 and c.relkind = 'm'
        order by c.relname`,
      [schema]
    )
    // Public storage buckets (Supabase only — guarded for plain Postgres).
    const publicBuckets = await optional('storage.buckets', async () => {
      const { rows } = await client.query(
        `select id, name from storage.buckets where public = true order by id`
      )
      return rows
    })
    return buildResult({ schema, noRls, policies, allTables, publicBuckets, secDefFns, views, matviews, storagePolicies, realtimeTables, grants, clientRoles, allow, skipped })
  } finally {
    await client.end()
  }
}
