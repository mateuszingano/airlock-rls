// Airlock DAST — dynamic proof of exposure.
//
// The static audit reasons about policies. DAST does what a static scanner
// can't: it uses ONLY the anon key (exactly what an attacker holds) to actually
// read each table over the Supabase REST API. If real rows come back, the leak
// isn't inferred — it's *proven*. Zero false positives: a returned row is a
// returned row.
//
// Signal:
//   200 + rows      → PROVEN LEAK (fail): anon read real data
//   200 + []        → safe (no rows visible — RLS blocks, or table empty)
//   401/403/404/err → safe (blocked or not exposed)

/**
 * Classify one probe result. Pure.
 * @returns {import('./audit.mjs').Finding|null}
 */
export function classifyProbe(table, status, rows) {
  if (status === 200 && Array.isArray(rows) && rows.length > 0) {
    const cols = Object.keys(rows[0] || {}).slice(0, 6).join(', ')
    return {
      kind: 'anon_read_leak',
      severity: 'fail',
      object: table,
      detail: `anon key read real rows over the REST API — columns exposed: ${cols}`,
    }
  }
  return null
}

/**
 * Classify a write probe. We POST a minimal payload; the goal is to learn
 * whether RLS would ALLOW an anonymous write — without persisting real data.
 *
 *   RLS error / 401 / 403           → blocked (safe)
 *   201 created                     → PROVEN write leak (a row was inserted)
 *   400/409 NON-RLS (constraint)    → RLS let it through; only a column
 *                                     constraint stopped it → write is exposed
 *                                     (an attacker can craft a valid row). Safe:
 *                                     nothing was persisted.
 * @returns {import('./audit.mjs').Finding|null}
 */
export function classifyWriteProbe(table, status, bodyText = '') {
  const rlsBlocked = status === 401 || status === 403 || /row-level security|permission denied/i.test(bodyText)
  if (rlsBlocked) return null
  if (status === 201) {
    return {
      kind: 'anon_write_leak',
      severity: 'fail',
      object: table,
      detail: 'anon key INSERTED a row over the REST API — writes are open (a test row was created; delete it)',
    }
  }
  if ((status === 400 || status === 409) && !/row-level security/i.test(bodyText)) {
    return {
      kind: 'anon_write_leak',
      severity: 'fail',
      object: table,
      detail: 'anon write passed RLS (stopped only by a column constraint) — an attacker can forge a valid row',
    }
  }
  return null // 404 (not exposed) or anything else → no proven write leak
}

/**
 * Probe each table for an anonymous INSERT. Sends `{}` — on any table with a
 * required column this fails the constraint (revealing RLS passed) WITHOUT
 * persisting a row. Opt-in, because on an all-nullable open table it can create
 * a row (which is itself the proof).
 * @returns {Promise<{findings: import('./audit.mjs').Finding[], probed: number}>}
 */
export async function probeAnonWrites({ projectUrl, anonKey, tables, fetchImpl = fetch }) {
  if (!projectUrl || !anonKey) throw new Error('DAST needs { projectUrl, anonKey }')
  const base = projectUrl.replace(/\/$/, '')
  const list = tables || []
  const findings = []
  for (const t of list) {
    const res = await fetchImpl(`${base}/rest/v1/${encodeURIComponent(t)}`, {
      method: 'POST',
      headers: {
        apikey: anonKey,
        Authorization: `Bearer ${anonKey}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: '{}',
    })
    let body = ''
    try {
      body = await res.text()
    } catch {
      body = ''
    }
    const f = classifyWriteProbe(t, res.status, body)
    if (f) findings.push(f)
  }
  return { findings, probed: list.length }
}

/** Discover the tables the REST API exposes, using the anon key's OpenAPI root. */
export async function discoverTables({ projectUrl, anonKey, fetchImpl = fetch }) {
  const base = projectUrl.replace(/\/$/, '')
  const res = await fetchImpl(`${base}/rest/v1/`, {
    headers: { apikey: anonKey, Authorization: `Bearer ${anonKey}` },
  })
  if (!res.ok) throw new Error(`REST root → ${res.status}`)
  const spec = await res.json()
  return Object.keys(spec.paths || {})
    .filter((p) => /^\/[^/{}]+$/.test(p) && p !== '/')
    .map((p) => p.slice(1))
}

/**
 * Probe every exposed table for an anonymous read.
 * @param {{projectUrl:string, anonKey:string, tables?:string[], fetchImpl?:Function}} opts
 * @returns {Promise<{findings: import('./audit.mjs').Finding[], probed: number}>}
 */
export async function probeAnonReads({ projectUrl, anonKey, tables, fetchImpl = fetch }) {
  if (!projectUrl || !anonKey) throw new Error('DAST needs { projectUrl, anonKey }')
  const base = projectUrl.replace(/\/$/, '')
  const list = tables || (await discoverTables({ projectUrl, anonKey, fetchImpl }))
  const findings = []
  for (const t of list) {
    const res = await fetchImpl(`${base}/rest/v1/${encodeURIComponent(t)}?select=*&limit=1`, {
      headers: { apikey: anonKey, Authorization: `Bearer ${anonKey}` },
    })
    let rows = null
    try {
      rows = await res.json()
    } catch {
      rows = null
    }
    const f = classifyProbe(t, res.status, rows)
    if (f) findings.push(f)
  }
  return { findings, probed: list.length }
}
