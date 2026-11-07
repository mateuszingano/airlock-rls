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
import { fixPromptFor } from '../src/fix-prompts.mjs'
import { auditMigrations } from '../src/migrations.mjs'

const RESET = '\x1b[0m'
const RED = '\x1b[31m'
const GREEN = '\x1b[32m'
const YELLOW = '\x1b[33m'
const DIM = '\x1b[2m'

const HELP = `Airlock — the CI gate for Supabase RLS.

Usage:
  airlock [DB_URL] [options]
  airlock migrations [PATH...] [options]   (no database, no credentials)

Arguments:
  DB_URL             Postgres connection string. Falls back to $SUPABASE_DB_URL.
  migrations PATH    Replay SQL migrations (default: supabase/migrations; files
                     or folders, applied by file name) into an embedded Postgres
                     and run the same audit. Nothing leaves your machine.
                     --url/--anon-key/--dast-write/--site don't apply here.
  --no-default-grants  (migrations) Don't emulate Supabase's auto-grant of new
                     public tables to anon/authenticated (projects created after
                     Oct 30, 2026 no longer have it). Default: emulated.

Options:
  --fail-on <level>  What breaks the build: "fail" (default) or "warn". Most
                     rules here emit warn (including an authenticated tenant
                     leak) — without this flag they can only be printed, never
                     enforced. Also read from $RLS_AUDIT_FAIL_ON.
  --strict           Alias for --fail-on warn.
  --allow <names>    Comma-separated policy names to treat as intentionally
                     permissive (also read from $RLS_AUDIT_ALLOW). Prefer the
                     qualified form "table.policy": a bare name is only applied
                     when exactly one table carries it, because policy names are
                     unique per table, not per schema.
  --schema <name>    Schema to audit (default: public).
  --url URL          Supabase project URL — enables the DAST pass ($SUPABASE_URL).
  --anon-key VALUE   Public anon credential for the DAST pass. Env: SUPABASE_ANON_KEY.
  --site URL         Deployed site URL — scans its HTML/JS for an exposed
                     service_role key, plus a downloadable .env, a public .git
                     folder and public source maps. Needs no database.
                     Env: SUPABASE_SITE_URL.
  --max-scripts <n>  How many JS bundles the --site scan reads (default: 50).
                     If a site has more, a scan_truncated warning names how many
                     went unscanned rather than implying it looked at them all.
  --dast-write       Also probe anonymous INSERTs (safe: an empty payload fails a
                     column constraint, revealing RLS passed without persisting).
  --prompts          After the report, print a copy-paste fix prompt for each
                     problem, ready for Cursor, Lovable, Bolt or Claude Code.
                     (--json always includes them, as "fixPrompt".)
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
      case '--prompts':
        opts.prompts = true
        break
      case '--fail-on':
        opts.failOn = argv[++i]
        break
      case '--strict':
        opts.failOn = 'warn' // convenience alias
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
      case '--max-scripts':
        opts.maxScripts = parseMaxScripts(argv[++i])
        break
      case '--no-default-grants':
        opts.defaultGrants = false
        break
      case '--dast-write':
        opts.dastWrite = true
        break
      default:
        if (a.startsWith('--fail-on=')) opts.failOn = a.slice('--fail-on='.length)
        else if (a.startsWith('--allow=')) opts.allow = splitList(a.slice('--allow='.length))
        else if (a.startsWith('--schema=')) opts.schema = a.slice('--schema='.length) || 'public'
        else if (a.startsWith('--url=')) opts.url = a.slice('--url='.length)
        else if (a.startsWith('--anon-key=')) opts.anonKey = a.slice('--anon-key='.length)
        else if (a.startsWith('--site=')) opts.site = a.slice('--site='.length)
        else if (a.startsWith('--max-scripts=')) opts.maxScripts = parseMaxScripts(a.slice('--max-scripts='.length))
        else if (a.startsWith('-')) throw new UsageError(`Unknown option: ${a}`)
        else positional.push(a)
    }
  }
  if (positional[0] === 'migrations') {
    // No-database mode: the rest of the positionals are migration paths, and
    // the DB/DAST/site flags have nothing to act on. Refuse them rather than
    // silently ignore them (a user passing --url expects a DAST pass).
    opts.mode = 'migrations'
    opts.paths = positional.slice(1).length ? positional.slice(1) : ['supabase/migrations']
    const bad = [opts.url && '--url', opts.anonKey && '--anon-key', opts.dastWrite && '--dast-write', opts.site && '--site']
      .filter(Boolean)
    if (bad.length) throw new UsageError(`${bad.join(', ')} can't be used with "migrations" (no database is contacted).`)
  } else if (opts.defaultGrants === false) {
    throw new UsageError('--no-default-grants only applies to "airlock migrations".')
  }
  opts.dbUrl = opts.mode === 'migrations' ? undefined : positional[0] || process.env.SUPABASE_DB_URL
  opts.url = opts.url || process.env.SUPABASE_URL
  opts.anonKey = opts.anonKey || process.env.SUPABASE_ANON_KEY
  opts.site = opts.site || process.env.SUPABASE_SITE_URL
  // Env var merges with --allow; CLI names are additive, not a replacement.
  opts.allow = [...splitList(process.env.RLS_AUDIT_ALLOW), ...opts.allow]
  opts.failOn = (opts.failOn || process.env.RLS_AUDIT_FAIL_ON || 'fail').toLowerCase()
  if (opts.failOn !== 'fail' && opts.failOn !== 'warn') {
    throw new UsageError(`Invalid --fail-on "${opts.failOn}". Use "fail" (default) or "warn".`)
  }
  return opts
}

function splitList(v) {
  return (v || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}

function parseMaxScripts(v) {
  const n = Number(v)
  if (!Number.isInteger(n) || n < 1) {
    throw new UsageError(`Invalid --max-scripts "${v}". Use a positive integer.`)
  }
  return n
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

// Where a finding came from, when it is known (the migrations mode traces
// findings back to the migration file and line that created the object).
const at = (f) => (f.file ? ` ${DIM}(${f.file}${f.line ? `:${f.line}` : ''})${RESET}` : '')

function report(result, { dbAudited = true, prompts = false } = {}) {
  const fails = result.findings.filter((f) => f.severity === 'fail')
  const warns = result.findings.filter((f) => f.severity === 'warn')

  if (fails.length) {
    console.log(`${RED}✗ ${fails.length} problem(s) in "${result.schema}":${RESET}`)
    for (const f of fails) console.log(`    ${RED}✗${RESET} ${f.object} ${DIM}${f.detail}${RESET}${at(f)}`)
  } else {
    // A --site-only run never touched a database, so it must not claim the
    // schema is clean; say what was actually looked at.
    if (dbAudited) console.log(`${GREEN}✓ No RLS problems in "${result.schema}".${RESET}`)
    if (result.siteScan) {
      console.log(`${GREEN}✓ No service key, .env, .git or source map exposed on ${result.siteScan.url} (${result.siteScan.scanned} file(s) scanned).${RESET}`)
    }
  }

  if (warns.length) {
    console.log(`${YELLOW}! ${warns.length} warning(s) worth a look:${RESET}`)
    for (const f of warns) console.log(`    ${YELLOW}!${RESET} ${f.object} ${DIM}${f.detail}${RESET}${at(f)}`)
  }

  if (result.allowed.length) {
    console.log(
      `${DIM}ℹ ${result.allowed.length} finding(s) allowed by config: ${result.allowed
        .map((f) => f.object)
        .join(', ')}${RESET}`
    )
  }

  // The site ships a Supabase public key: normal, but it means RLS is the only
  // lock on the tables, and a site scan can't see RLS. Point at the audit that can.
  if (!dbAudited && result.siteScan?.publicKeyFound) {
    console.log(
      `${DIM}ℹ This site ships your Supabase public (anon/publishable) key. That's normal, but it means Row Level\n` +
        `  Security is the only thing protecting your tables, and a site scan can't see it. Audit the policies too:\n` +
        `    npx airlock-rls "postgresql://..."   (Supabase dashboard → Connect → connection string)${RESET}`
    )
  }

  if (result.gatePassed) {
    const tail = warns.length ? ` ${DIM}(${warns.length} warning(s))${RESET}` : ''
    console.log(`\n${GREEN}${dbAudited ? 'RLS audit' : 'Site scan'} passed.${RESET}${tail}`)
    // Eleven of the rules only ever emit `warn`. Saying nothing here lets a
    // reader assume "passed" means "nothing worth acting on" — including for
    // an `authenticated` tenant leak, which is a warn today.
    if (warns.length) {
      console.log(`${DIM}  ${warns.length} warning(s) did not fail the build. Use --fail-on warn to gate on them.${RESET}`)
    }
  } else {
    const what = result.problems ? `${result.problems} problem(s) found` : `${warns.length} warning(s) with --fail-on warn`
    console.log(`\n${RED}${dbAudited ? 'RLS audit' : 'Site scan'} failed: ${what}.${RESET}`)
  }

  const withPrompt = result.findings.filter((f) => f.fixPrompt)
  if (prompts && withPrompt.length) {
    console.log(`\n${DIM}── Fix prompts: paste one at a time into your AI tool (Cursor, Lovable, Bolt, Claude Code) ──${RESET}`)
    withPrompt.forEach((f, i) => {
      console.log(`\n[${i + 1}/${withPrompt.length}] ${f.object}`)
      console.log(f.fixPrompt)
    })
  } else if (!prompts && withPrompt.length) {
    console.log(`${DIM}  Run again with --prompts for a copy-paste fix for each problem (Cursor, Lovable, Bolt, Claude Code).${RESET}`)
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
  if (opts.mode === 'migrations') {
    // No database, no DAST, no site scan (an env-provided site URL is ignored
    // here: the user asked for an offline run).
    opts.site = undefined
  } else if (!opts.dbUrl && !opts.site) {
    console.error('Nothing to audit. Set SUPABASE_DB_URL (or pass it as the first argument)')
    console.error('and/or pass --site <url> to scan a deployed site for an exposed service key.')
    console.error('Run `airlock --help` for usage.')
    return 2
  }

  // With a DB URL we run the full RLS audit; with only --site we start from a
  // clean slate and add the service-key scan (the zero-setup free hook).
  let result = opts.mode === 'migrations'
    ? await auditMigrations({ paths: opts.paths, schema: opts.schema, allow: opts.allow, defaultGrants: opts.defaultGrants !== false })
    : opts.dbUrl
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
    let scan
    try {
      scan = await scanSiteForServiceRole({ siteUrl: opts.site, ...(opts.maxScripts != null ? { maxScripts: opts.maxScripts } : {}) })
    } catch (err) {
      // A bare "fetch failed" doesn't say which URL, or that nothing was
      // scanned. Still exits 2: never a false pass.
      throw new Error(`Couldn't scan ${opts.site}: ${err.cause?.code || err.message}`)
    }
    const { findings, scanned, publicKeyFound } = scan
    result.siteScan = { scanned, url: opts.site, publicKeyFound: Boolean(publicKeyFound) }
    if (findings.length) {
      result.findings.push(...findings)
      result.findings.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'fail' ? -1 : 1))
      result.problems = result.findings.filter((f) => f.severity === 'fail').length
      result.warnings = result.findings.filter((f) => f.severity === 'warn').length
      result.passed = result.problems === 0
    }
  }

  // `passed` is the rule-level verdict (no fail-severity findings). `gatePassed`
  // is the BUILD verdict, which --fail-on can widen to include warnings. Set it
  // here, after every pass (static + DAST + site scan) has contributed findings.
  result.gatePassed = opts.failOn === 'warn' ? result.problems === 0 && result.warnings === 0 : result.passed

  // Attach a copy-paste fix prompt to every finding that has one (additive
  // field; findings without a fix, like config bookkeeping, get none).
  for (const f of result.findings) {
    const prompt = fixPromptFor(f)
    if (prompt) f.fixPrompt = prompt
  }

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2))
  } else {
    if (result.dast) console.log(`${DIM}(DAST: probed ${result.dast.probed} table(s) with the anon key)${RESET}`)
    if (result.migrations) {
      const m = result.migrations
      const ext = m.extensionsSkipped.length ? `, ${m.extensionsSkipped.length} extension(s) skipped (${m.extensionsSkipped.join(', ')})` : ''
      const grants = m.defaultGrants ? '' : ', default grants off'
      console.log(
        `${DIM}(migrations: ${m.files.length} file(s), ${m.applied} of ${m.statements} statement(s) loaded into an embedded Postgres, ` +
          `${m.failed.length} failed${ext}${grants})${RESET}`
      )
    }
    report(result, { dbAudited: Boolean(opts.dbUrl) || opts.mode === 'migrations', prompts: Boolean(opts.prompts) })
  }

  return result.gatePassed ? 0 : 1
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    // Connection failures, bad args, etc. — never a false "pass".
    console.error(err instanceof UsageError ? `${err.message}\nRun \`airlock --help\`.` : err.message)
    process.exit(2)
  })
