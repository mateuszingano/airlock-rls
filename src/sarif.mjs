// Airlock — GitHub-native output: SARIF 2.1.0 and workflow-command annotations.
//
// `--sarif <file>` writes a SARIF log that github/codeql-action/upload-sarif
// turns into code-scanning alerts. `--format github` prints `::error` /
// `::warning` workflow commands, which GitHub renders as annotations on the run
// (and on the file/line when a finding carries one).
//
// Findings come from two kinds of source:
//   - the live catalog (DB mode): no file — the location is the database
//     object, e.g. `notes."read all"`, emitted as a SARIF logicalLocation;
//   - a migrations file (migrations mode, optional `file` / `line` fields on a
//     finding): emitted as a physicalLocation, so GitHub can point at the line.
//
// Pure apart from writeFile / console in emitGithubOutputs. Never adds anything
// a finding didn't already carry (findings already redact keys).

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { createHash } from 'node:crypto'

const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json'
const INFO_URI = 'https://github.com/mateuszingano/airlock-rls'
const HELP_URI = 'https://github.com/mateuszingano/airlock-rls#what-it-checks'
const SITE_HELP_URI = 'https://github.com/mateuszingano/airlock-rls#scan-a-deployed-site-for-an-exposed-service-key-zero-setup'

/** kind → [short description, full description]. `storage_*` reuses the base kind. */
const RULES = {
  rls_disabled: ['Table with Row Level Security disabled', 'A table reachable by the API roles has RLS off, so every row is exposed to anyone holding the anon or authenticated key.'],
  permissive_true: ['Policy that always evaluates true', 'A policy is USING (true) / WITH CHECK (true) or reduces to always-true, so it lets every row through.'],
  anon_unscoped: ['Anonymous read not scoped to an owner', 'A policy lets the anon role read rows without scoping them to an owner or tenant.'],
  authenticated_unscoped: ['Signed-in read not scoped to the row owner', 'Any authenticated user can read every row, including other users\' data (a tenant leak).'],
  or_branch_unscoped: ['OR branch without an owner check', 'One OR branch of the policy has no owner check, so it lets every row through.'],
  write_unscoped: ['Write policy not tied to the row owner', 'A write policy does not check who owns the row, so a user can write on behalf of someone else.'],
  write_unchecked: ['INSERT/UPDATE without a scoped WITH CHECK', 'An INSERT or UPDATE policy has no WITH CHECK scoped to the user.'],
  update_using_unscoped: ['UPDATE policy targets rows the user does not own', 'The USING clause of an UPDATE policy lets a user target rows they do not own.'],
  delete_unscoped: ['DELETE policy not scoped to the owner', 'A DELETE policy lets a user delete rows they do not own.'],
  anon_read_leak: ['Anonymous read proven over the API', 'A live request with the public anon key actually read rows from this table (DAST).'],
  anon_write_leak: ['Anonymous write proven over the API', 'A live request with the public anon key was able to write to this table (DAST).'],
  anon_write_inconclusive: ['Anonymous write probe inconclusive', 'The DAST write probe could not tell whether anonymous writes are allowed.'],
  security_definer: ['SECURITY DEFINER function bypasses RLS', 'A SECURITY DEFINER function runs with its owner\'s rights and bypasses RLS.'],
  anon_executes_definer: ['Anon can call a SECURITY DEFINER function', 'The anon role can execute a SECURITY DEFINER function, which bypasses RLS.'],
  definer_search_path_mutable: ['SECURITY DEFINER function without a pinned search_path', 'A SECURITY DEFINER function has no fixed search_path, so unqualified names resolve against the caller\'s search_path.'],
  view_bypasses_rls: ['View that bypasses RLS', 'A view runs with its owner\'s rights and ignores the RLS of the tables underneath.'],
  matview_exposed: ['Materialized view readable through the API', 'Materialized views have no RLS, and this one is readable by the API roles.'],
  public_bucket: ['Public storage bucket', 'A storage bucket is public: anyone with a file URL can download it.'],
  realtime_exposure: ['Anon-readable table published to Realtime', 'An anon-readable table is in the Realtime publication, so its changes stream to anonymous subscribers.'],
  bypassrls_role: ['Role with BYPASSRLS', 'A role with BYPASSRLS or SUPERUSER ignores every policy.'],
  owner_bypasses_rls: ['Client-reachable owner bypasses RLS', 'The table is owned by a client-reachable role without FORCE ROW LEVEL SECURITY, so the owner bypasses its own policies.'],
  service_role_exposed: ['Supabase service key exposed in the browser', 'A service_role JWT or sb_secret key ships in the deployed site\'s HTML/JS. It bypasses all RLS.'],
  env_file_exposed: ['Downloadable .env file', 'The deployed site serves its .env file to anyone.'],
  git_exposed: ['Public .git folder', 'The deployed site serves its .git folder, exposing source code and history.'],
  source_map_exposed: ['Public source maps', 'The deployed site publishes JavaScript source maps, exposing the original source.'],
  scan_truncated: ['Site scan stopped short', 'Only part of the site\'s script bundles were scanned.'],
  nothing_audited: ['Nothing was audited', 'No tables or policies were found in the schema, so nothing was audited.'],
  check_skipped: ['Check skipped', 'A check could not run against this database.'],
  helper_scoped: ['Policy scoped only through a helper function', 'A read is scoped only through a helper function a static scan cannot see inside.'],
  allow_unused: ['Unused allow-list entry', 'An --allow entry matched nothing.'],
  allow_ambiguous: ['Ambiguous allow-list entry', 'A bare policy name in --allow matches more than one table.'],
  allow_needs_namespace: ['Allow-list entry needs a namespace', 'This --allow entry must carry its namespace (storage:, view:, fn:, ...).'],
}

const SITE_KINDS = new Set(['service_role_exposed', 'env_file_exposed', 'git_exposed', 'source_map_exposed', 'scan_truncated'])

function baseKind(kind) {
  return kind && kind.startsWith('storage_') && RULES[kind.slice('storage_'.length)] ? kind.slice('storage_'.length) : kind
}

/** The SARIF reportingDescriptor for one finding kind. Unknown kinds get a generic one. */
export function ruleFor(kind) {
  const base = baseKind(kind)
  const [short, full] = RULES[base] || [`Airlock finding: ${kind}`, `Airlock reported a "${kind}" finding.`]
  const storage = base !== kind ? ' (Supabase Storage policy on storage.objects)' : ''
  return {
    id: kind,
    name: kind.replace(/(^|_)([a-z])/g, (_, __, c) => c.toUpperCase()),
    shortDescription: { text: short + storage },
    fullDescription: { text: full + storage },
    helpUri: SITE_KINDS.has(base) ? SITE_HELP_URI : HELP_URI,
  }
}

/** fail → error, warn → warning, anything else → note. */
export function levelFor(severity) {
  return severity === 'fail' ? 'error' : severity === 'warn' ? 'warning' : 'note'
}

function readVersionSync() {
  try {
    return JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version || '0.0.0'
  } catch {
    return '0.0.0'
  }
}

/** Repo-relative, forward slashes, no leading ./ — what SARIF artifactLocation wants. */
function toUri(file) {
  return String(file).replace(/\\/g, '/').replace(/^\.\//, '')
}

/**
 * Build a SARIF 2.1.0 log from an audit result. Pure.
 * @param {{findings: Array<{kind:string, severity:string, object:string, detail:string, file?:string, line?:number, fixPrompt?:string}>, schema?:string}} result
 * @param {{version?: string}} [opts]
 */
export function toSarif(result, { version = readVersionSync() } = {}) {
  const findings = (result && result.findings) || []
  const kinds = [...new Set(findings.map((f) => f.kind))]
  const index = new Map(kinds.map((k, i) => [k, i]))
  const results = findings.map((f) => {
    const r = {
      ruleId: f.kind,
      ruleIndex: index.get(f.kind),
      level: levelFor(f.severity),
      message: { text: `${f.object}: ${f.detail}` },
      locations: [locationFor(f, result)],
      partialFingerprints: {
        'airlockFinding/v1': createHash('sha256').update(`${f.kind}\u0000${f.object}`).digest('hex'),
      },
    }
    if (f.fixPrompt) r.properties = { fixPrompt: f.fixPrompt }
    return r
  })
  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'airlock-rls',
            informationUri: INFO_URI,
            semanticVersion: version,
            version,
            rules: kinds.map(ruleFor),
          },
        },
        results,
      },
    ],
  }
}

function locationFor(f, result) {
  const logical = { fullyQualifiedName: logicalName(f, result), kind: 'object' }
  const loc = { logicalLocations: [logical] }
  if (f.file) {
    loc.physicalLocation = {
      artifactLocation: { uri: toUri(f.file) },
      region: { startLine: Number.isInteger(f.line) && f.line > 0 ? f.line : 1 },
    }
  }
  return loc
}

function logicalName(f, result) {
  const obj = String(f.object || '')
  // URLs (site scan) and already-namespaced objects ("role:x", "storage:...") stay as-is.
  if (/^[a-z]+:/i.test(obj) || obj.includes('.') || !result?.schema) return obj
  return `${result.schema}.${obj}`
}

// Workflow-command escaping (actions/toolkit `command.ts`).
const escData = (s) => String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A')
const escProp = (s) => escData(s).replace(/:/g, '%3A').replace(/,/g, '%2C')

/**
 * One GitHub workflow command per finding: `::error file=x,line=n,title=kind::msg`.
 * fail → error, warn → warning, anything else → notice. Pure.
 * @returns {string[]}
 */
export function toGithubAnnotations(result) {
  return ((result && result.findings) || []).map((f) => {
    const cmd = f.severity === 'fail' ? 'error' : f.severity === 'warn' ? 'warning' : 'notice'
    const props = []
    if (f.file) {
      props.push(`file=${escProp(toUri(f.file))}`)
      if (Number.isInteger(f.line) && f.line > 0) props.push(`line=${f.line}`)
    }
    props.push(`title=${escProp(`airlock: ${f.kind}`)}`)
    return `::${cmd} ${props.join(',')}::${escData(`${f.object}: ${f.detail}`)}`
  })
}

/**
 * The one call the CLI makes: write the SARIF file and/or print annotations.
 * Annotations are skipped under --json so stdout stays valid JSON.
 * @param {object} result
 * @param {{sarif?: string, format?: string, json?: boolean, log?: (s:string)=>void}} opts
 */
export function emitGithubOutputs(result, { sarif, format, json, log = console.log } = {}) {
  if (sarif) {
    const dir = dirname(sarif)
    if (dir && dir !== '.') mkdirSync(dir, { recursive: true })
    writeFileSync(sarif, JSON.stringify(toSarif(result), null, 2) + '\n')
  }
  if (format === 'github' && !json) {
    for (const line of toGithubAnnotations(result)) log(line)
  }
}
