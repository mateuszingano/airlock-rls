// Airlock — exposed service_role key scanner.
//
// The free hook: runs with ONLY the deployed site URL — no database, no keys,
// no setup. It fetches the page and its JS bundles and looks for a Supabase
// SERVICE key shipped to the browser:
//   - a legacy JWT whose payload role === 'service_role'
//   - a new-format secret key (sb_secret_...)
//
// A service key bypasses ALL Row Level Security — whoever reads it has full
// read/write to the database. It is the single worst leak a Supabase app can
// have, and it's a common vibe-coding mistake.
//
// CRITICAL, on purpose: this NEVER flags the anon/publishable key. Every
// Supabase frontend ships the anon key — that's by design and safe. We decode
// each JWT and only fire when the role is literally 'service_role'. Zero
// false positives: a real service key is a real service key.

// A JWT: three base64url segments. The Supabase keys start with the standard
// `eyJ...` header. We keep the match tight to avoid grabbing unrelated blobs.
const JWT_RE = /eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/g
// New-format Supabase secret key (server-side only — must never reach a browser).
const SECRET_KEY_RE = /sb_secret_[A-Za-z0-9]{8,}/g

/**
 * Decode a JWT's payload and return its `role` claim (or null). Pure, never
 * throws — a malformed token is simply "not a service key".
 * @param {string} token
 * @returns {string|null}
 */
export function decodeJwtRole(token) {
  try {
    const parts = String(token).split('.')
    if (parts.length !== 3) return null
    const json = Buffer.from(parts[1], 'base64url').toString('utf8')
    const payload = JSON.parse(json)
    return typeof payload.role === 'string' ? payload.role : null
  } catch {
    return null
  }
}

/**
 * Show enough of a key to identify it, never enough to use it. A security tool
 * must not echo the secret it found.
 */
export function redact(token) {
  const s = String(token)
  return `${s.slice(0, 12)}… (${s.length} chars)`
}

/**
 * Scan a blob of text for exposed service keys. Pure.
 *  - JWT with role 'service_role' → hit {type:'jwt'}
 *  - sb_secret_... key            → hit {type:'secret_key'}
 * The literal string 'service_role' in code (e.g. a policy `auth.role() =
 * 'service_role'`) is NOT a hit — only an actual decodable key is.
 * @param {string} text
 * @returns {{type:'jwt'|'secret_key', token:string}[]}
 */
export function scanText(text) {
  const s = String(text || '')
  const hits = []
  const seen = new Set()
  for (const m of s.matchAll(JWT_RE)) {
    const tok = m[0]
    if (seen.has(tok)) continue
    if (decodeJwtRole(tok) === 'service_role') {
      seen.add(tok)
      hits.push({ type: 'jwt', token: tok })
    }
  }
  for (const m of s.matchAll(SECRET_KEY_RE)) {
    const tok = m[0]
    if (seen.has(tok)) continue
    seen.add(tok)
    hits.push({ type: 'secret_key', token: tok })
  }
  return hits
}

/**
 * Build the single fail Finding for a source that leaked one or more keys. Pure.
 * @param {{type:string, token:string}[]} hits
 * @param {string} source  where it was found (page or script URL)
 * @returns {import('./audit.mjs').Finding|null}
 */
export function findingFor(hits, source) {
  if (!hits || !hits.length) return null
  const kinds = [...new Set(hits.map((h) => (h.type === 'jwt' ? 'service_role JWT' : 'sb_secret key')))]
  return {
    kind: 'service_role_exposed',
    severity: 'fail',
    object: source,
    detail:
      `Supabase service key exposed in the browser (${kinds.join(', ')}) — it bypasses ALL Row Level Security, ` +
      `giving anyone who reads it full read/write to your database. Rotate it now and move it server-side. ` +
      `Found: ${redact(hits[0].token)}`,
  }
}

/**
 * Extract same-page <script src="..."> URLs, resolved absolute against the page.
 * Pure. Only http(s) URLs are returned.
 * @param {string} html
 * @param {string} baseUrl
 * @returns {string[]}
 */
export function extractScriptUrls(html, baseUrl) {
  const urls = new Set()
  for (const m of String(html || '').matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)) {
    try {
      const u = new URL(m[1], baseUrl)
      if (u.protocol === 'http:' || u.protocol === 'https:') urls.add(u.href)
    } catch {
      // ignore unresolvable src (data:, blob:, malformed)
    }
  }
  return [...urls]
}

async function bodyText(res) {
  try {
    return await res.text()
  } catch {
    return ''
  }
}

/**
 * Scan a deployed site (its HTML + JS bundles) for an exposed service key.
 * Needs ONLY the site URL — no database, no credentials.
 * @param {{siteUrl:string, fetchImpl?:Function, maxScripts?:number}} opts
 * @returns {Promise<{findings: import('./audit.mjs').Finding[], scanned:number}>}
 */
export async function scanSiteForServiceRole({ siteUrl, fetchImpl = fetch, maxScripts = 50 } = {}) {
  if (!siteUrl) throw new Error('scanSiteForServiceRole needs { siteUrl }')
  const headers = { 'User-Agent': 'airlock-rls (service-role scan)' }
  const findings = []
  let scanned = 0

  const pageRes = await fetchImpl(siteUrl, { headers })
  const html = await bodyText(pageRes)
  scanned++
  const pageFinding = findingFor(scanText(html), siteUrl)
  if (pageFinding) findings.push(pageFinding)

  const scripts = extractScriptUrls(html, siteUrl).slice(0, maxScripts)
  for (const url of scripts) {
    let body = ''
    try {
      const r = await fetchImpl(url, { headers })
      body = await bodyText(r)
    } catch {
      continue // a script we can't fetch just isn't scanned
    }
    scanned++
    const f = findingFor(scanText(body), url)
    if (f) findings.push(f)
  }

  return { findings, scanned }
}
