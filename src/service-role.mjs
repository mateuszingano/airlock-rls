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

// Read at most this much of a response. A key is a short token near the top of a
// bundle; a multi-gigabyte body has nothing more to tell us and would exhaust
// the process heap.
const MAX_BODY_BYTES = 5 * 1024 * 1024
const FETCH_TIMEOUT_MS = 10_000

async function bodyText(res) {
  try {
    const text = await res.text()
    return text.length > MAX_BODY_BYTES ? text.slice(0, MAX_BODY_BYTES) : text
  } catch {
    return ''
  }
}

/**
 * Is this URL safe to fetch from a server?
 *
 * The site scanner follows `<script src>` from a page it was pointed at, so the
 * page decides what gets requested. Unbounded, that is a server-side request
 * forgery primitive: a hostile page (or a compromised third-party script tag)
 * can aim the scanner at cloud metadata or an internal service. In the CLI the
 * blast radius is a developer's laptop; in the hosted Monitor (which vendors its
 * own copy of this scanner) it is the production network.
 *
 * Only public http(s) hosts are allowed. Literal private, loopback, link-local
 * and CGNAT addresses are refused. This does NOT defeat DNS rebinding or a
 * hostname that resolves to a private IP, which is declared in SECURITY.md
 * rather than silently missed.
 */
/** Hostnames that only ever resolve to a cloud instance-metadata service. */
const METADATA_HOSTS = new Set([
  'metadata.google.internal', 'metadata.goog', 'metadata',
  'instance-data', 'instance-data.ec2.internal',
])

export function isFetchableUrl(raw) {
  let u
  try {
    u = new URL(raw)
  } catch {
    return false
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return false
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase()
  if (host === 'localhost' || host.endsWith('.localhost') || host === '::1' || host === '0.0.0.0') return false
  // The v6 unspecified address is not "no address": connecting to :: reaches
  // loopback on Linux, exactly like 0.0.0.0 does for v4. The URL parser folds
  // ::0 and 0:0:0:0:0:0:0:0 into this same spelling.
  if (host === '::') return false
  // Cloud metadata endpoints answer on a name as well as on 169.254.169.254,
  // and the name never resolves anywhere public.
  if (METADATA_HOSTS.has(host) || host.endsWith('.metadata.google.internal')) return false
  // IPv4-mapped IPv6 is the same address wearing a different hat — and the URL
  // parser rewrites it to HEX (`::ffff:169.254.169.254` → `::ffff:a9fe:a9fe`),
  // so matching only the dotted spelling would let the metadata endpoint through
  // under its normalized name. Fold it back to dotted before the checks below.
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host)
  const dotted = mapped
    ? [parseInt(mapped[1], 16) >> 8, parseInt(mapped[1], 16) & 0xff, parseInt(mapped[2], 16) >> 8, parseInt(mapped[2], 16) & 0xff].join('.')
    : host
  const v4 = /^(?:::ffff:)?(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(dotted)
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])]
    if (a === 10 || a === 127 || a === 0) return false
    if (a === 172 && b >= 16 && b <= 31) return false
    if (a === 192 && b === 168) return false
    if (a === 169 && b === 254) return false // cloud metadata
    if (a === 100 && b >= 64 && b <= 127) return false // CGNAT
    return true
  }
  if (host.startsWith('fd') || host.startsWith('fc') || host.startsWith('fe80:')) return false // ULA / link-local
  return true
}

// Cap on redirects we'll follow before giving up — matches the browser default
// and stops a redirect loop from hanging the scan.
const MAX_REDIRECTS = 5
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308])

/**
 * fetch with a timeout, so an endpoint that never answers can't hang CI, AND
 * with SAFE redirect handling.
 *
 * The default `redirect: 'follow'` was an SSRF hole: `isFetchableUrl` vets the
 * URL we were pointed at, but a public host answering `302 → 169.254.169.254`
 * (or a compromised CDN in a `<script src>`) sends the fetch onward to an
 * internal address that was never checked. So we drive redirects by hand with
 * `redirect: 'manual'` and re-run `isFetchableUrl` on every hop's Location.
 * A hop to a refused address throws — it is not silently followed, and not
 * silently skipped either.
 */
async function fetchWithTimeout(fetchImpl, url, init = {}) {
  let current = url
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const res = await fetchImpl(current, {
      ...init,
      redirect: 'manual',
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    })
    const status = res?.status
    if (!REDIRECT_STATUSES.has(status)) return res
    const location = res?.headers?.get?.('location')
    if (!location) return res // a 3xx with no Location — nothing to follow
    let next
    try {
      next = new URL(location, current).href
    } catch {
      throw new Error(`Refusing to follow malformed redirect from ${current} to "${location}".`)
    }
    if (!isFetchableUrl(next)) {
      throw new Error(
        `Refusing to follow redirect from ${current} to ${next}: only public http(s) hosts are allowed ` +
          `(no loopback, private, link-local or metadata addresses). This is the SSRF guard.`
      )
    }
    current = next
  }
  throw new Error(`Too many redirects (> ${MAX_REDIRECTS}) starting from ${url}.`)
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

  // The URL the CALLER gave us is checked too: pointing --site at a private
  // address is a usage error, and refusing it keeps the CLI and the hosted
  // Monitor on the same rule.
  if (!isFetchableUrl(siteUrl)) {
    throw new Error(`Refusing to scan ${siteUrl}: only public http(s) hosts are allowed (no loopback, private, link-local or metadata addresses).`)
  }
  const pageRes = await fetchWithTimeout(fetchImpl, siteUrl, { headers })
  const html = await bodyText(pageRes)
  scanned++
  const pageFinding = findingFor(scanText(html), siteUrl)
  if (pageFinding) findings.push(pageFinding)

  const fetchable = extractScriptUrls(html, siteUrl).filter(isFetchableUrl)
  const scripts = fetchable.slice(0, maxScripts)
  // Looking at the first N bundles and reporting "clean" is indistinguishable
  // from having looked at all of them — and a service key often lives in a
  // route chunk, not the entry bundle. Say out loud when we stopped short, so a
  // clean report keeps meaning "I looked", not "I looked at some".
  if (fetchable.length > maxScripts) {
    findings.push({
      kind: 'scan_truncated',
      severity: 'warn',
      object: siteUrl,
      detail:
        `Only the first ${maxScripts} of ${fetchable.length} script bundles were scanned — ` +
        `${fetchable.length - maxScripts} were NOT checked for an exposed service key. ` +
        `Raise the cap with --max-scripts to scan them all.`,
    })
  }
  for (const url of scripts) {
    let body = ''
    try {
      const r = await fetchWithTimeout(fetchImpl, url, { headers })
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
