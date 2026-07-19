// Airlock — RLS policy-qualifier analysis on a REAL SQL parse tree.
//
// The old classifier reasoned about the qualifier with regexes (paren counting,
// `or`/`and` splitting on raw text). That is fundamentally unsafe: a string
// literal with a parenthesis (`note = '('`) unbalances the count and hides a
// top-level `OR 1=1`, so a policy that leaks every row passes green. This module
// parses the qualifier with `pgsql-ast-parser` and reasons over the boolean AST,
// where a string literal is just a leaf and can never change the structure.
//
// Public API mirrors the old regex module (string in → boolean/string out) so the
// classifier (audit.ts) is unchanged. FAIL-SAFE: an unparseable qualifier is
// treated as NOT scoped (surfaced as a finding), never silently passed.
import { parseFirst } from 'pgsql-ast-parser';
/** Parse a policy qualifier into its boolean expression node, or null on error. */
export function parseQual(qual) {
    try {
        const stmt = parseFirst(`SELECT 1 WHERE (${qual})`);
        return stmt && stmt.type === 'select' ? stmt.where ?? null : null;
    }
    catch {
        return null;
    }
}
function unwrap(n) {
    let cur = n;
    while (cur && cur.type === 'cast')
        cur = cur.operand;
    return cur;
}
function fnName(call) {
    const f = call && call.function;
    if (!f)
        return '';
    return ((f.schema ? f.schema + '.' : '') + (f.name || '')).toLowerCase();
}
/** auth.uid() / auth.jwt() / current_setting(...), through casts, `->>`, and a
 *  scalar subquery `(select auth.uid())`. */
function isCallerToken(n) {
    n = unwrap(n);
    if (!n)
        return false;
    if (n.type === 'call')
        return /^(auth\.uid|auth\.jwt|current_setting)$/.test(fnName(n));
    if (n.type === 'member')
        return isCallerToken(n.operand);
    if (n.type === 'select' && Array.isArray(n.columns) && n.columns.length === 1 && !n.from)
        return isCallerToken(n.columns[0].expr);
    return false;
}
function isAuthRoleCall(n) {
    n = unwrap(n);
    if (!n)
        return false;
    if (n.type === 'call')
        return fnName(n) === 'auth.role';
    // Postgres deparses the recommended form as a scalar subquery:
    // `(( SELECT auth.role() AS role) = 'service_role'::text)`
    if (n.type === 'select' && Array.isArray(n.columns) && n.columns.length === 1 && !n.from)
        return isAuthRoleCall(n.columns[0].expr);
    return false;
}
function isConst(n) {
    n = unwrap(n);
    return !!n && ['string', 'integer', 'numeric', 'float', 'boolean', 'null', 'constant'].includes(n.type);
}
function constValue(n) {
    n = unwrap(n);
    if (!n)
        return undefined;
    switch (n.type) {
        case 'integer':
        case 'numeric':
        case 'float':
            return Number(n.value);
        case 'string':
            return String(n.value);
        case 'boolean':
            return !!n.value;
        case 'null':
            return null;
        default:
            return undefined;
    }
}
function isStringConst(n, v) {
    n = unwrap(n);
    return !!n && n.type === 'string' && n.value === v;
}
function sameExpr(a, b) {
    return JSON.stringify(unwrap(a)) === JSON.stringify(unwrap(b));
}
// Built-ins whose result is always an integer >= 0, so `length(x) >= 0` and
// friends can never be false — a tautology dressed as a real predicate.
const NONNEG_FNS = new Set(['length', 'char_length', 'character_length', 'octet_length', 'bit_length', 'cardinality']);
function isNonNegativeCall(n) {
    n = unwrap(n);
    return !!n && n.type === 'call' && NONNEG_FNS.has(fnName(n));
}
const CMP_OPS = new Set(['=', '<', '>', '<=', '>=', '<>', '!=']);
function cmpConst(op, a, b) {
    if (a === undefined || b === undefined)
        return undefined;
    const bothNum = typeof a === 'number' && typeof b === 'number';
    const bothStr = typeof a === 'string' && typeof b === 'string';
    const bothBool = typeof a === 'boolean' && typeof b === 'boolean';
    if (!bothNum && !bothStr && !bothBool)
        return undefined;
    switch (op) {
        case '=': return a === b;
        case '<>':
        case '!=': return a !== b;
        case '<': return a < b;
        case '>': return a > b;
        case '<=': return a <= b;
        case '>=': return a >= b;
        default: return undefined;
    }
}
/** Any bare column reference NOT inside a caller-identity token — proof the
 *  expression depends on the row, so a comparison to it really scopes. */
function hasColumnRef(n) {
    n = unwrap(n);
    if (!n || isCallerToken(n))
        return false;
    if (n.type === 'ref')
        return true;
    if (n.type === 'member')
        return hasColumnRef(n.operand);
    if (n.type === 'call')
        return (n.args || []).some(hasColumnRef);
    if (n.type === 'array')
        return (n.expressions || n.value || n.items || []).some(hasColumnRef);
    if (n.type === 'binary')
        return hasColumnRef(n.left) || hasColumnRef(n.right);
    return false;
}
function isRowValue(n) {
    n = unwrap(n);
    return !isConst(n) && !isCallerToken(n) && hasColumnRef(n);
}
/** Does the whole expression evaluate TRUE for every row/caller (a tautology)? */
export function isAlwaysTrue(n) {
    n = unwrap(n);
    if (!n)
        return false;
    switch (n.type) {
        case 'boolean':
            return n.value === true;
        case 'call':
            // coalesce(true, …) is always true
            return fnName(n) === 'coalesce' && (n.args || []).length > 0 && isAlwaysTrue(n.args[0]);
        case 'unary':
            if (n.op === 'NOT')
                return isAlwaysFalse(n.operand);
            if (n.op === 'IS TRUE' || n.op === 'IS NOT FALSE')
                return isAlwaysTrue(n.operand);
            if (n.op === 'IS NULL')
                return isConst(n.operand) && constValue(n.operand) === null;
            if (n.op === 'IS NOT NULL')
                return isConst(n.operand) && constValue(n.operand) !== null;
            return false;
        case 'binary': {
            if (n.op === 'OR')
                return isAlwaysTrue(n.left) || isAlwaysTrue(n.right);
            if (n.op === 'AND')
                return isAlwaysTrue(n.left) && isAlwaysTrue(n.right);
            // reflexive: x = x / x <= x / x >= x  (owner_id = owner_id, auth.uid()=auth.uid())
            if (['=', '<=', '>='].includes(n.op) && sameExpr(n.left, n.right))
                return true;
            // x IN (x)
            if (n.op === 'IN' && sameExpr(n.left, n.right))
                return true;
            // a constant IN a constant list: `'a' in ('a','b')`
            if (n.op === 'IN' && isConst(n.left) && n.right && n.right.type === 'list') {
                const items = n.right.expressions || [];
                if (items.length && items.every(isConst))
                    return items.some((it) => constValue(it) === constValue(n.left));
            }
            // a non-negative built-in can never falsify the comparison:
            // `length(x) >= 0`, `char_length(y) > -1` are true for every row.
            if (isNonNegativeCall(n.left) && isConst(n.right) && typeof constValue(n.right) === 'number') {
                const v = constValue(n.right);
                if (n.op === '>=')
                    return v <= 0;
                if (n.op === '>')
                    return v < 0;
                if (n.op === '<>' || n.op === '!=')
                    return v < 0;
            }
            // both constants
            if (isConst(n.left) && isConst(n.right))
                return cmpConst(n.op, constValue(n.left), constValue(n.right)) === true;
            return false;
        }
        case 'select':
            if (Array.isArray(n.columns) && n.columns.length === 1 && !n.from)
                return isAlwaysTrue(n.columns[0].expr);
            return false;
        default:
            return false;
    }
}
/** Does the expression evaluate FALSE for every row (contributes nothing to OR)? */
export function isAlwaysFalse(n) {
    n = unwrap(n);
    if (!n)
        return false;
    if (n.type === 'boolean')
        return n.value === false;
    if (n.type === 'unary' && n.op === 'NOT')
        return isAlwaysTrue(n.operand);
    if (n.type === 'binary') {
        if (n.op === 'AND')
            return isAlwaysFalse(n.left) || isAlwaysFalse(n.right);
        if (n.op === 'OR')
            return isAlwaysFalse(n.left) && isAlwaysFalse(n.right);
        if (['<>', '!='].includes(n.op) && sameExpr(n.left, n.right))
            return true;
        if (isConst(n.left) && isConst(n.right))
            return cmpConst(n.op, constValue(n.left), constValue(n.right)) === false;
    }
    return false;
}
/** A single comparison that ties the caller's identity to a per-row value. */
function isCallerComparison(n) {
    const L = unwrap(n.left);
    const R = unwrap(n.right);
    // restricted to the backend role: auth.role() = 'service_role' (the FUNCTION,
    // never a data column compared to the string 'service_role')
    if ((isAuthRoleCall(L) && isStringConst(R, 'service_role')) || (isAuthRoleCall(R) && isStringConst(L, 'service_role')))
        return true;
    // col IN (subquery that itself restricts to the caller)
    if (n.op === 'IN' && R && R.type === 'select' && R.where && restrictsToCaller(R.where))
        return true;
    // auth.uid()/jwt/current_setting compared to a real row value (not a constant,
    // not the same token — reflexive is handled as a tautology above)
    if (CMP_OPS.has(n.op) || n.op === 'IN') {
        if (isCallerToken(L) && isRowValue(R))
            return true;
        if (isCallerToken(R) && isRowValue(L))
            return true;
    }
    return false;
}
/** Does this term (a top-level OR disjunct) actually restrict to the caller?
 *  AND → any conjunct restricts; nested OR → both branches must restrict. */
export function restrictsToCaller(n) {
    n = unwrap(n);
    if (!n)
        return false;
    if (n.type === 'binary') {
        if (n.op === 'AND')
            return restrictsToCaller(n.left) || restrictsToCaller(n.right);
        if (n.op === 'OR')
            return restrictsToCaller(n.left) && restrictsToCaller(n.right);
        return isCallerComparison(n);
    }
    // A helper handed the caller's identity — `is_admin(auth.uid())`. We can't see
    // inside it, but it is given the caller, so it is caller-dependent (the common
    // "owner OR admin" shape). A helper that does NOT receive the token
    // (`is_public()`) stays unproven and keeps widening an OR.
    if (n.type === 'call' && !BUILTINS.has(fnName(n)) && (n.args || []).some(isCallerToken))
        return true;
    return false;
}
/** Is there a real caller restriction ANYWHERE in this qualifier? Lenient by
 *  design: it answers "does this policy scope at all", while the per-disjunct
 *  fail-safe (hasUnprovenOrBranch) is what catches a branch that widens. */
function containsRealScope(n) {
    n = unwrap(n);
    if (!n || typeof n !== 'object')
        return false;
    if (n.type === 'binary' && (n.op === 'AND' || n.op === 'OR'))
        return containsRealScope(n.left) || containsRealScope(n.right);
    if (n.type === 'binary' && isCallerComparison(n))
        return true;
    if (n.type === 'call' && !BUILTINS.has(fnName(n)) && (n.args || []).some(isCallerToken))
        return true;
    for (const k of ['left', 'right', 'operand', 'where'])
        if (n[k] && containsRealScope(n[k]))
            return true;
    for (const arr of ['args', 'columns', 'expressions', 'items'])
        if (Array.isArray(n[arr]) && n[arr].some((x) => containsRealScope(x && x.expr ? x.expr : x)))
            return true;
    return false;
}
/** Flatten the top-level OR spine into its disjuncts. */
function topLevelOr(n) {
    n = unwrap(n);
    if (n && n.type === 'binary' && n.op === 'OR')
        return [...topLevelOr(n.left), ...topLevelOr(n.right)];
    return [n];
}
const BUILTINS = new Set([
    'auth.uid', 'auth.jwt', 'auth.role', 'current_setting', 'coalesce', 'any', 'all', 'array',
    'lower', 'upper', 'trim', 'length', 'char_length', 'cardinality', 'nullif', 'greatest', 'least',
]);
function helperCall(root) {
    let found = null;
    const visit = (n) => {
        if (found || !n || typeof n !== 'object')
            return;
        if (n.type === 'call' && !BUILTINS.has(fnName(n)) && n.function && n.function.name) {
            found = (n.function.schema ? n.function.schema + '.' : '') + n.function.name;
            return;
        }
        for (const k of ['left', 'right', 'operand', 'where', 'from'])
            if (n[k])
                visit(n[k]);
        for (const arr of ['args', 'columns', 'expressions', 'items'])
            if (Array.isArray(n[arr]))
                n[arr].forEach((x) => visit(x && x.expr ? x.expr : x));
    };
    visit(root);
    return found;
}
// ── Public API (same signatures as the old regex module) ────────────────────
/** Is this qualifier a tautology (always-true), so it scopes nothing? */
export function isTautology(qual) {
    if (qual == null)
        return false;
    const node = parseQual(qual);
    return node ? isAlwaysTrue(node) : false;
}
/**
 * Does this qualifier really SCOPE access to the caller? Fail-safe: it's scoped
 * only if EVERY top-level OR disjunct restricts to the caller (or is provably
 * false). A tautology, an unparseable qual, or any unproven OR branch → NOT scoped.
 */
export function isScoped(qual) {
    if (qual == null)
        return false;
    const node = parseQual(qual);
    if (!node)
        return false;
    if (isAlwaysTrue(node))
        return false;
    return topLevelOr(node).every((d) => restrictsToCaller(d) || isAlwaysFalse(d));
}
/**
 * If the qualifier is scoped ONLY through a helper function we can't see inside,
 * return the helper name (worth a warn, never a silent pass). Null when it's a
 * tautology, already really scoped, or unparseable.
 */
export function helperScope(qual) {
    if (qual == null)
        return null;
    const node = parseQual(qual);
    if (!node || isAlwaysTrue(node) || isScoped(qual))
        return null;
    return helperCall(node);
}
// ── Primitives, qualifier-string in ─────────────────────────────────────────
// Shared with the free CLI so both products decide "tautology / real scope /
// helper" from the SAME parse tree, while each keeps its own finding taxonomy.
/** Does this term really restrict to the caller (auth.uid() = <col>, or the
 *  backend service_role)? Merely mentioning the token does not count. */
export function restrictsToCallerQual(qual) {
    if (qual == null)
        return false;
    const node = parseQual(qual);
    if (!node)
        return false;
    // A tautology neutralises any scope it also mentions.
    if (isAlwaysTrue(node))
        return false;
    return containsRealScope(node);
}
/** Is this term provably always FALSE (so it widens nothing in an OR)? */
export function isAlwaysFalseQual(qual) {
    if (qual == null)
        return false;
    const node = parseQual(qual);
    return node ? isAlwaysFalse(node) : false;
}
/** First user-defined (non-built-in) function call in the qualifier, or null. */
export function helperCallQual(qual) {
    if (qual == null)
        return null;
    const node = parseQual(qual);
    return node ? helperCall(node) : null;
}
/**
 * FAIL-SAFE: does any top-level OR disjunct fail to prove it restricts the
 * caller (and isn't provably false)? Such a branch WIDENS access, so the caller
 * must warn rather than pass silently. An unparseable qualifier counts as
 * unproven.
 */
export function hasUnprovenOrBranch(qual) {
    if (qual == null)
        return false;
    const node = parseQual(qual);
    if (!node)
        return true; // can't prove it — never silent-green
    const disjuncts = topLevelOr(node);
    if (disjuncts.length <= 1)
        return false;
    return !disjuncts.every((d) => restrictsToCaller(d) || isAlwaysFalse(d));
}
