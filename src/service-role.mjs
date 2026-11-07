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

// The PUBLIC Supabase key (legacy anon JWT or new sb_publishable_...). Shipping
// it is normal and is never a finding. But seeing it tells us something useful:
// this site talks to Supabase from the browser, so Row Level Security is the
// only thing between a visitor and the tables. The CLI turns that into a nudge
// to audit the policies, which a site scan cannot see.
const PUBLISHABLE_KEY_RE = /sb_publishable_[A-Za-z0-9_-]{8,}/

/**
 * True if the text carries a Supabase public key (anon JWT or sb_publishable_).
 * Pure, never throws.
 * @param {string} text
 * @returns {boolean}
 */
export function hasPublicKey(text) {
  const s = String(text || '')
  if (PUBLISHABLE_KEY_RE.test(s)) return true
  for (const m of s.matchAll(JWT_RE)) {
    if (decodeJwtRole(m[0]) === 'anon') return true
  }
  return false
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

// ---------------------------------------------------------------------------
// Exposed files: things a static host should never serve but often does after
// an AI-built deploy. Each check VALIDATES the body, because most SPA hosts
// answer 200 with index.html for any path; a 200 alone proves nothing.
// ---------------------------------------------------------------------------

/** A body that is clearly an HTML page (SPA fallback, 404 page), not the file. */
function looksLikeHtml(body) {
  return /^\s*(<!doctype|<html|<head|<body|<!--|<script|<meta|<div)/i.test(body)
}

/**
 * Is this body a real dotenv file? Counts KEY=value lines; 0 = not a .env
 * (an HTML fallback page never counts). Pure.
 * @param {string} body
 * @returns {number}
 */
export function countEnvVars(body) {
  const s = String(body || '')
  if (!s.trim() || looksLikeHtml(s)) return 0
  let n = 0
  for (const line of s.split(/\r?\n/)) {
    if (/^\s*(export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=/.test(line)) n++
  }
  return n
}

/** Is this body the contents of .git/HEAD? Pure. */
export function isGitHead(body) {
  return /^(ref: refs\/\S+|[0-9a-f]{40})$/.test(String(body || '').trim())
}

/** Is this body a JavaScript source map (JSON with mappings + sources)? Pure. */
export function isSourceMap(body) {
  const s = String(body || '').trim()
  if (!s.startsWith('{')) return false
  try {
    const j = JSON.parse(s)
    return typeof j.mappings === 'string' && Array.isArray(j.sources)
  } catch {
    return false
  }
}

/**
 * The URL a script's `//# sourceMappingURL=` comment points to, resolved
 * against the script, or null (none, or an inline data: map). Pure.
 * @param {string} body
 * @param {string} scriptUrl
 * @returns {string|null}
 */
export function sourceMapUrlFor(body, scriptUrl) {
  const m = /\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)\s*$/m.exec(String(body || '').slice(-2048))
  if (!m || m[1].startsWith('data:')) return null
  try {
    const u = new URL(m[1], scriptUrl)
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null
  } catch {
    return null
  }
}

// How many source maps we download to confirm they are public. One proves the
// point; a few more tell the reader it is the whole build, not a stray file.
const MAX_SOURCE_MAPS = 3

async function fetchOk(fetchImpl, url, headers) {
  try {
    const r = await fetchWithTimeout(fetchImpl, url, { headers })
    if (!r || r.status !== 200) return null
    return await bodyText(r)
  } catch {
    return null // unreachable / refused redirect: not exposed as far as we can tell
  }
}

/**
 * Probe /.env and /.git/HEAD on the site's origin. Returns fail findings.
 * Never echoes a value from the .env: only how many variables it holds.
 */
async function probeExposedFiles({ siteUrl, fetchImpl, headers }) {
  const findings = []
  const origin = new URL(siteUrl).origin
  const envUrl = `${origin}/.env`
  const envBody = await fetchOk(fetchImpl, envUrl, headers)
  const vars = envBody == null ? 0 : countEnvVars(envBody)
  if (vars > 0) {
    findings.push({
      kind: 'env_file_exposed',
      severity: 'fail',
      object: envUrl,
      detail:
        `Your .env file is downloadable by anyone (${vars} variable(s) in it). Remove it from the deployed site and ` +
        `rotate every secret it holds — they are already public.`,
    })
  }
  const gitUrl = `${origin}/.git/HEAD`
  const gitBody = await fetchOk(fetchImpl, gitUrl, headers)
  if (gitBody != null && isGitHead(gitBody)) {
    findings.push({
      kind: 'git_exposed',
      severity: 'fail',
      object: `${origin}/.git/`,
      detail:
        `Your .git folder is served publicly — anyone can download your source code and its full history, ` +
        `including any secret ever committed. Keep .git out of the deployed site.`,
    })
  }
  return findings
}

/**
 * Scan a deployed site (its HTML + JS bundles) for an exposed service key.
 * Needs ONLY the site URL — no database, no credentials.
 * With `exposedFiles` (default on) it also checks for a downloadable .env, a
 * public .git folder and public source maps, each confirmed by content (a 200
 * alone proves nothing on an SPA host). `publicKeyFound` says the site ships a
 * Supabase public key, i.e. RLS is the only lock on its tables: not a finding,
 * a hint for the caller.
 * @param {{siteUrl:string, fetchImpl?:Function, maxScripts?:number, exposedFiles?:boolean}} opts
 * @returns {Promise<{findings: import('./audit.mjs').Finding[], scanned:number, publicKeyFound:boolean}>}
 */
export async function scanSiteForServiceRole({ siteUrl, fetchImpl = fetch, maxScripts = 50, exposedFiles = true } = {}) {
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
  let publicKeyFound = hasPublicKey(html)
  const mapUrls = []

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
    if (!publicKeyFound && hasPublicKey(body)) publicKeyFound = true
    const mapUrl = exposedFiles ? sourceMapUrlFor(body, url) : null
    if (mapUrl && isFetchableUrl(mapUrl) && !mapUrls.includes(mapUrl)) mapUrls.push(mapUrl)
  }

  if (exposedFiles) {
    findings.push(...(await probeExposedFiles({ siteUrl, fetchImpl, headers })))

    // Source maps: confirm up to MAX_SOURCE_MAPS by content. A map can also
    // carry the original source (sourcesContent), so scan it for a key too.
    const confirmed = []
    for (const mapUrl of mapUrls.slice(0, MAX_SOURCE_MAPS)) {
      const body = await fetchOk(fetchImpl, mapUrl, headers)
      if (body == null || !isSourceMap(body)) continue
      confirmed.push(mapUrl)
      const f = findingFor(scanText(body), mapUrl)
      if (f) findings.push(f)
    }
    if (confirmed.length) {
      const more = mapUrls.length > confirmed.length
        ? ` (${mapUrls.length} script(s) point to a map; ${confirmed.length} checked)`
        : ''
      findings.push({
        kind: 'source_map_exposed',
        severity: 'warn',
        object: confirmed[0],
        detail:
          `Source maps are public, so anyone can download your original source code${more}. ` +
          `Turn them off in the production build or upload them privately to your error tracker.`,
      })
    }
  }

  findings.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'fail' ? -1 : 1))
  return { findings, scanned, publicKeyFound }
}
