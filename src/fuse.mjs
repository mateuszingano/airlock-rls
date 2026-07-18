// Fuse static findings with DAST evidence, so severity is backed by proof.
//
//   static "anon can read T"  + DAST read real rows from T  → CONFIRMED (fail)
//   static "anon can read T"  + DAST read nothing from T     → downgrade to warn
//                                (empty table, or a grant/restrictive blocks it)
//   DAST read T, static didn't flag it                       → proven leak (fail)
//
// This kills the #1 adoption killer of a security tool: the false positive.

/** Table a finding is about (null for buckets/functions/views). */
export function extractTable(finding) {
  if (finding.kind === 'rls_disabled') return finding.object
  const m = /^(.+?)\."/.exec(finding.object || '')
  return m ? m[1] : null
}

/** Is this finding about an ANONYMOUS read — the thing DAST can confirm or deny? */
export function isAnonReadExposure(finding) {
  if (finding.kind === 'rls_disabled' || finding.kind === 'anon_unscoped') return true
  if (finding.kind === 'permissive_true') return /\[(SELECT|ALL)\]/.test(finding.detail || '')
  return false
}

/**
 * @param {import('./audit.mjs').AuditResult} staticResult
 * @param {{leakTables?: Set<string>|string[], probed?: Set<string>|string[]}} dast
 *        leakTables: tables DAST proved anon-readable; probed: tables DAST tried.
 * @returns {import('./audit.mjs').AuditResult & {dast: object}}
 */
export function fuse(staticResult, { leakTables = [], probed = [] } = {}) {
  const leaks = leakTables instanceof Set ? leakTables : new Set(leakTables)
  const probedSet = probed instanceof Set ? probed : new Set(probed)
  const fused = []

  for (const f of staticResult.findings) {
    if (!isAnonReadExposure(f)) {
      fused.push(f)
      continue
    }
    const table = extractTable(f)
    if (table && leaks.has(table)) {
      fused.push({ ...f, severity: 'fail', verdict: 'confirmed', detail: `${f.detail} — CONFIRMED: DAST read real rows with the anon key` })
    } else if (table && probedSet.has(table)) {
      // DAST read nothing. That is NOT proof of safety — the table may just be
      // empty (or hold no rows matching the qual right now); the permissive policy
      // still leaks the instant a matching row exists. So DON'T downgrade the
      // fail (that would be a false negative, the worst failure for a security
      // gate). Grants / RESTRICTIVE policies that truly block anon are already
      // handled in the static pass, so a surviving static fail is real. Keep the
      // severity; only annotate that DAST couldn't confirm it live.
      fused.push({ ...f, verdict: 'unconfirmed', detail: `${f.detail} — DAST read no rows (table may be empty; the permissive policy is still a latent exposure)` })
    } else {
      fused.push(f) // DAST didn't probe it — no evidence either way
    }
  }

  // DAST leaks that no static anon-read finding covered → proven fails.
  const covered = new Set(staticResult.findings.filter(isAnonReadExposure).map(extractTable))
  for (const t of leaks) {
    if (!covered.has(t)) {
      fused.push({
        kind: 'anon_read_leak',
        severity: 'fail',
        verdict: 'confirmed',
        object: t,
        detail: 'anon key read real rows over the REST API — proven leak (static analysis did not flag it)',
      })
    }
  }

  fused.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'fail' ? -1 : 1))
  const problems = fused.filter((f) => f.severity === 'fail').length
  const warnings = fused.filter((f) => f.severity === 'warn').length
  return {
    ...staticResult,
    findings: fused,
    problems,
    warnings,
    passed: problems === 0,
    dast: { probed: probedSet.size, confirmed: [...leaks] },
  }
}
