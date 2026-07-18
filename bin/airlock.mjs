#!/usr/bin/env node
// Airlock CLI — the CI gate for Supabase RLS.
//
// Fails (exit 1) if any table in the target schema has RLS disabled, or if any
// policy is permissive (USING (true) / WITH CHECK (true)). Drop it into your CI
// so a migration can't ship a data leak.
//
// Usage:
//   SUPABASE_DB_URL=postgresql://... airlock
//   airlock postgresql://postgres:postgres@127.0.0.1:54322/postgres
//   airlock --allow public_read,status_select
//   airlock --json            # machine-readable output
//   airlock --schema public   # audit a different schema
//
// Exit codes:
//   0  audit passed — no exposure found
//   1  audit failed — at least one exposed table or permissive policy
//   2  usage / connection error (bad args, no URL, DB unreachable)
//
// Get the URL from `supabase status` (local) or your project's connection string.

import { audit } from '../src/audit.mjs'
import { probeAnonReads, probeAnonWrites } from '../src/dast.mjs'
import { scanSiteForServiceRole } from '../src/service-role.mjs'
import { fuse, extractTable } from '../src/fuse.mjs'

const RESET = '\x1b[0m'
const RED = '\x1b[31m'
const GREEN = '\x1b[32m'
const YELLOW = '\x1b[33m'
const DIM = '\x1b[2m'

const HELP = `Airlock — the CI gate for Supabase RLS.

Usage:
  airlock [DB_URL] [options]

Arguments:
  DB_URL             Postgres connection string. Falls back to $SUPABASE_DB_URL.

Options:
  --allow <names>    Comma-separated policy names to treat as intentionally
                     permissive (also read from $RLS_AUDIT_ALLOW).
  --schema <name>    Schema to audit (default: public).
  --url URL          Supabase project URL — enables the DAST pass ($SUPABASE_URL).
  --anon-key VALUE   Public anon credential for the DAST pass. Env: SUPABASE_ANON_KEY.
  --site URL         Deployed site URL — scans its HTML/JS for an exposed
                     service_role key. Needs no database. Env: SUPABASE_SITE_URL.
  --dast-write       Also probe anonymous INSERTs (safe: an empty payload fails a
                     column constraint, revealing RLS passed without persisting).
  --json             Print the result as JSON instead of a report.
  -h, --help         Show this help.
  -v, --version      Show the version.

With --url and --anon-key, Airlock also runs DAST: it uses the anon key to
actually read each table over the REST API and proves any anonymous leak.

Exit codes: 0 = passed, 1 = exposure found, 2 = usage/connection error.`

function parseArgs(argv) {
  const opts = { dbUrl: undefined, schema: 'public', json: false, allow: [], url: undefined, anonKey: undefined, site: undefined, dastWrite: false }
  const positional = []
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    switch (a) {
      case '-h':
      case '--help':
        opts.help = true
        break
      case '-v':
      case '--version':
        opts.version = true
        break
      case '--json':
        opts.json = true
        break
      case '--allow':
        opts.allow = splitList(argv[++i])
        break
      case '--schema':
        opts.schema = argv[++i] || 'public'
        break
      case '--url':
        opts.url = argv[++i]
        break
      case '--anon-key':
        opts.anonKey = argv[++i]
        break
      case '--site':
        opts.site = argv[++i]
        break
      case '--dast-write':
        opts.dastWrite = true
        break
      default:
        if (a.startsWith('--allow=')) opts.allow = splitList(a.slice('--allow='.length))
        else if (a.startsWith('--schema=')) opts.schema = a.slice('--schema='.length) || 'public'
        else if (a.startsWith('--url=')) opts.url = a.slice('--url='.length)
        else if (a.startsWith('--anon-key=')) opts.anonKey = a.slice('--anon-key='.length)
        else if (a.startsWith('--site=')) opts.site = a.slice('--site='.length)
        else if (a.startsWith('-')) throw new UsageError(`Unknown option: ${a}`)
        else positional.push(a)
    }
  }
  opts.dbUrl = positional[0] || process.env.SUPABASE_DB_URL
  opts.url = opts.url || process.env.SUPABASE_URL
  opts.anonKey = opts.anonKey || process.env.SUPABASE_ANON_KEY
  opts.site = opts.site || process.env.SUPABASE_SITE_URL
  // Env var merges with --allow; CLI names are additive, not a replacement.
  opts.allow = [...splitList(process.env.RLS_AUDIT_ALLOW), ...opts.allow]
  return opts
}

function splitList(v) {
  return (v || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}

class UsageError extends Error {}

async function readVersion() {
  const { readFile } = await import('node:fs/promises')
  const url = new URL('../package.json', import.meta.url)
  try {
    return JSON.parse(await readFile(url, 'utf8')).version || '0.0.0'
  } catch {
    return '0.0.0'
  }
}

function report(result) {
  const fails = result.findings.filter((f) => f.severity === 'fail')
  const warns = result.findings.filter((f) => f.severity === 'warn')

  if (fails.length) {
    console.log(`${RED}✗ ${fails.length} problem(s) in "${result.schema}":${RESET}`)
    for (const f of fails) console.log(`    ${RED}✗${RESET} ${f.object} ${DIM}${f.detail}${RESET}`)
  } else {
    console.log(`${GREEN}✓ No RLS problems in "${result.schema}".${RESET}`)
  }

  if (warns.length) {
    console.log(`${YELLOW}! ${warns.length} warning(s) worth a look:${RESET}`)
    for (const f of warns) console.log(`    ${YELLOW}!${RESET} ${f.object} ${DIM}${f.detail}${RESET}`)
  }

  if (result.allowed.length) {
    console.log(
      `${DIM}ℹ ${result.allowed.length} finding(s) allowed by config: ${result.allowed
        .map((f) => f.object)
        .join(', ')}${RESET}`
    )
  }

  if (result.passed) {
    const tail = warns.length ? ` ${DIM}(${warns.length} warning(s))${RESET}` : ''
    console.log(`\n${GREEN}RLS audit passed.${RESET}${tail}`)
  } else {
    console.log(`\n${RED}RLS audit failed: ${result.problems} problem(s) found.${RESET}`)
  }
}

async function main() {
  const opts = parseArgs(process.argv.slice(2))

  if (opts.help) {
    console.log(HELP)
    return 0
  }
  if (opts.version) {
    console.log(await readVersion())
    return 0
  }
  if (!opts.dbUrl && !opts.site) {
    console.error('Nothing to audit. Set SUPABASE_DB_URL (or pass it as the first argument)')
    console.error('and/or pass --site <url> to scan a deployed site for an exposed service key.')
    console.error('Run `airlock --help` for usage.')
    return 2
  }

  // With a DB URL we run the full RLS audit; with only --site we start from a
  // clean slate and add the service-key scan (the zero-setup free hook).
  let result = opts.dbUrl
    ? await audit({ dbUrl: opts.dbUrl, schema: opts.schema, allow: opts.allow })
    : { schema: opts.schema, findings: [], allowed: [], problems: 0, warnings: 0, passed: true, tables: [] }

  // DAST pass: prove exposure with the anon key, then FUSE it with the static
  // findings — a live read UPGRADES a static fail to "confirmed" and surfaces
  // leaks static missed. Reading nothing does NOT downgrade a fail (an empty
  // table is a latent leak, not a false positive — never trade a false negative).
  if (opts.dbUrl && opts.url && opts.anonKey) {
    const { findings } = await probeAnonReads({
      projectUrl: opts.url,
      anonKey: opts.anonKey,
      tables: result.tables,
    })
    // Tables whose static finding was intentionally allow-listed → their DAST
    // read is intentional too, so don't count it as a leak.
    const allowedTables = new Set(result.allowed.map(extractTable).filter(Boolean))
    const leakTables = findings.map((f) => f.object).filter((t) => !allowedTables.has(t))
    result = fuse(result, { leakTables, probed: result.tables })

    // Opt-in: prove anonymous WRITES too (pattern 3).
    if (opts.dastWrite) {
      const { findings: writeFindings } = await probeAnonWrites({
        projectUrl: opts.url,
        anonKey: opts.anonKey,
        tables: result.tables,
      })
      const freshWrites = writeFindings.filter((f) => !allowedTables.has(f.object))
      result.findings.push(...freshWrites)
      result.findings.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'fail' ? -1 : 1))
      result.problems = result.findings.filter((f) => f.severity === 'fail').length
      result.warnings = result.findings.filter((f) => f.severity === 'warn').length
      result.passed = result.problems === 0
    }
  }

  // Site scan: a service_role key shipped to the browser bypasses ALL RLS —
  // the worst leak there is. Needs only the deployed site URL (no DB).
  if (opts.site) {
    const { findings, scanned } = await scanSiteForServiceRole({ siteUrl: opts.site })
    result.siteScan = { scanned, url: opts.site }
    if (findings.length) {
      result.findings.push(...findings)
      result.findings.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'fail' ? -1 : 1))
      result.problems = result.findings.filter((f) => f.severity === 'fail').length
      result.warnings = result.findings.filter((f) => f.severity === 'warn').length
      result.passed = result.problems === 0
    }
  }

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2))
  } else {
    if (result.dast) console.log(`${DIM}(DAST: probed ${result.dast.probed} table(s) with the anon key)${RESET}`)
    report(result)
  }

  return result.passed ? 0 : 1
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    // Connection failures, bad args, etc. — never a false "pass".
    console.error(err instanceof UsageError ? `${err.message}\nRun \`airlock --help\`.` : err.message)
    process.exit(2)
  })
