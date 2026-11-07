// Airlock — does an RLS policy (or a SECURITY DEFINER body) decide access from
// `user_metadata`?
//
// Supabase lets every signed-in user rewrite their own `user_metadata` from the
// browser: `supabase.auth.updateUser({ data: { role: 'admin' } })`. It lands in
// `auth.users.raw_user_meta_data` and in the JWT claim `user_metadata`. So a
// policy like
//
//   USING ( (auth.jwt() -> 'user_metadata' ->> 'role') = 'admin' )
//   USING ( org_id = (auth.jwt() -> 'user_metadata' ->> 'org_id')::uuid )
//   USING ( exists (select 1 from auth.users u
//                   where u.id = auth.uid() and u.raw_user_meta_data ->> 'role' = 'admin') )
//
// is satisfiable by ANY user who sets the value themselves. The second one even
// looks "scoped" to the scope engine (the caller token is compared to a per-row
// column), so it used to pass green while any user could read any tenant by
// writing that tenant's id into their own metadata.
//
// `app_metadata` / `raw_app_meta_data` is server-only (only the service role can
// write it) and is the correct place for roles and tenant ids: it never fires.
//
// Decided on the parse tree (pgsql-ast-parser via ./scope.mjs), so the words
// inside a string literal (`note = 'user_metadata'`) are a leaf and never fire.
// An unparseable qualifier falls back to a narrow text match on the two exact
// syntactic shapes, reported the same way.

import { parseQual } from './scope.mjs'

const JSON_MEMBER_OPS = new Set(['->', '->>'])
const JSON_PATH_OPS = new Set(['#>', '#>>'])

function unwrap(n) {
  let cur = n
  while (cur && cur.type === 'cast') cur = cur.operand
  return cur
}

function fnName(call) {
  const f = call && call.function
  if (!f) return ''
  return ((f.schema ? f.schema + '.' : '') + (f.name || '')).toLowerCase()
}

/** The JWT the caller presents: auth.jwt() or current_setting('request.jwt.claims'…),
 *  through casts and a scalar subquery `(select auth.jwt())`. */
function isJwtSource(n) {
  n = unwrap(n)
  if (!n) return false
  if (n.type === 'call') {
    const name = fnName(n)
    if (name === 'auth.jwt') return true
    if (name === 'current_setting') {
      const a = unwrap(n.args && n.args[0])
      return !!a && a.type === 'string' && /^request\.jwt\.claims?$/i.test(a.value)
    }
    return false
  }
  if (n.type === 'select' && Array.isArray(n.columns) && n.columns.length === 1 && !n.from) {
    return isJwtSource(n.columns[0].expr)
  }
  return false
}

/** First element of a Postgres text[] path literal: '{user_metadata,role}' → 'user_metadata'. */
function firstPathElement(n) {
  n = unwrap(n)
  if (!n || n.type !== 'string') return null
  const m = /^\s*\{\s*"?([^",}]+)"?/.exec(n.value)
  return m ? m[1].trim().toLowerCase() : null
}

/**
 * Walk the whole tree (including subqueries) and return a short description of
 * the first place it reads user-editable metadata, or null.
 */
function findInTree(root) {
  const stack = [root]
  const seen = new Set()
  while (stack.length) {
    const n = stack.pop()
    if (!n || typeof n !== 'object' || seen.has(n)) continue
    seen.add(n)
    if (n.type === 'member' && JSON_MEMBER_OPS.has(n.op) && String(n.member).toLowerCase() === 'user_metadata' && isJwtSource(n.operand)) {
      return "auth.jwt() -> 'user_metadata'"
    }
    if (n.type === 'binary' && JSON_PATH_OPS.has(n.op) && isJwtSource(n.left) && firstPathElement(n.right) === 'user_metadata') {
      return "auth.jwt() #> '{user_metadata,…}'"
    }
    if (n.type === 'ref' && String(n.name).toLowerCase() === 'raw_user_meta_data') {
      return 'auth.users.raw_user_meta_data'
    }
    for (const v of Object.values(n)) {
      if (v && typeof v === 'object') stack.push(v)
    }
  }
  return null
}

// Fallback for an unparseable qualifier: only the exact syntactic shapes.
const TEXT_SHAPES = [
  [/->>?\s*'user_metadata'/i, "auth.jwt() -> 'user_metadata'"],
  [/#>>?\s*'\{\s*"?user_metadata\b/i, "auth.jwt() #> '{user_metadata,…}'"],
  [/\braw_user_meta_data\b/i, 'auth.users.raw_user_meta_data'],
]

/**
 * Where (if anywhere) this policy expression trusts user-editable metadata.
 * @param {string|null|undefined} qual  a pg_policies qual / with_check
 * @returns {string|null} a short label of the source, or null
 */
export function trustsUserMetadata(qual) {
  if (qual == null || qual === '') return null
  const tree = parseQual(qual)
  if (tree) return findInTree(tree)
  for (const [re, label] of TEXT_SHAPES) if (re.test(qual)) return label
  return null
}

/**
 * Same question for a function body (pg_proc.prosrc). Bodies are plpgsql/SQL
 * the policy parser can't read, so this is a text match on the exact shapes,
 * with SQL comments stripped first (a commented-out line must not fire).
 * @param {string|null|undefined} src
 * @returns {string|null}
 */
export function bodyTrustsUserMetadata(src) {
  if (src == null || src === '') return null
  const code = String(src).replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/--[^\n]*/g, ' ')
  for (const [re, label] of TEXT_SHAPES) if (re.test(code)) return label
  return null
}
