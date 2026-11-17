// Pull request comment for the GitHub Action (`comment: true`).
//
// Reads the SARIF log the gate already wrote (so the audit runs once) and keeps
// ONE comment per PR up to date: found by a hidden marker, edited on every push
// instead of piling up. Never fails the job: a token without
// `pull-requests: write` (or a PR from a fork, whose token is read-only) only
// gets a warning in the log. The gate's own exit code is what blocks the merge.

import { readFile } from 'node:fs/promises'

export const MARKER = '<!-- airlock-rls:pr-comment -->'
const HOME = 'https://github.com/mateuszingano/airlock-rls'
const MAX_ROWS = 20

const cell = (s, max = 160) => {
  const t = String(s ?? '').replace(/\s+/g, ' ').trim()
  return (t.length > max ? t.slice(0, max - 1) + '…' : t).replace(/\|/g, '\\|')
}

/**
 * Markdown body for the comment. Pure.
 * @param {object} sarif SARIF 2.1.0 log written by `airlock --sarif`
 * @param {{passed: boolean, schema?: string, sha?: string, runUrl?: string}} ctx
 */
export function buildComment(sarif, { passed, schema = 'public', sha = '', runUrl = '' } = {}) {
  const results = sarif?.runs?.[0]?.results || []
  const rows = results.map((r) => {
    const object = r.locations?.[0]?.logicalLocations?.[0]?.fullyQualifiedName || ''
    const text = String(r.message?.text || '')
    // The message is "<object>: <detail>", with the object as the engine wrote
    // it (no schema prefix); the logical name may carry "schema.".
    const prefix = [object, object.replace(/^[^.:]+\./, '')].find((o) => o && text.startsWith(o + ': '))
    const detail = prefix ? text.slice(prefix.length + 2) : text
    return { fail: r.level === 'error', kind: r.ruleId, object, detail }
  })
  const fails = rows.filter((r) => r.fail)
  const warns = rows.filter((r) => !r.fail)

  const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`
  let title
  if (!passed && fails.length) title = `❌ Airlock RLS: ${plural(fails.length, 'problem')} must be fixed before merging`
  else if (!passed && warns.length) title = `❌ Airlock RLS: ${plural(warns.length, 'warning')} block this PR (fail-on: warn)`
  else if (!passed) title = '❌ Airlock RLS: the gate failed'
  else if (warns.length) title = `✅ Airlock RLS: passed, ${plural(warns.length, 'warning')} worth a look`
  else title = '✅ Airlock RLS: no exposure found'

  const lines = [MARKER, `### ${title}`, '']
  const shown = [...fails, ...warns].slice(0, MAX_ROWS)
  if (shown.length) {
    lines.push('| | Finding | Object | Detail |', '|---|---|---|---|')
    for (const r of shown) lines.push(`| ${r.fail ? '✗' : '!'} | \`${cell(r.kind, 60)}\` | \`${cell(r.object, 80)}\` | ${cell(r.detail)} |`)
    if (rows.length > shown.length) lines.push('', `…and ${rows.length - shown.length} more in the job log.`)
    lines.push('')
  }
  const where = [`schema \`${cell(schema, 60)}\``, sha ? `commit ${sha.slice(0, 7)}` : '', runUrl ? `[job log](${runUrl})` : '']
    .filter(Boolean).join(' · ')
  lines.push(`<sub>Checked by [Airlock RLS](${HOME}) · ${where}</sub>`)
  return lines.join('\n')
}

async function gh(fetchImpl, api, token, method, path, body) {
  const res = await fetchImpl(api + path, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      accept: 'application/vnd.github+json',
      'x-github-api-version': '2022-11-28',
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  })
  return res
}

/**
 * Create or update the PR comment. Returns what it did; never throws for an
 * API refusal (that is a warning, not a gate failure).
 * @returns {Promise<'created'|'updated'|'skipped'>}
 */
export async function upsertComment({ env = process.env, fetchImpl = fetch, read = readFile, log = console.log } = {}) {
  const skip = (why) => {
    log(`::notice title=Airlock RLS PR comment::${why}`)
    return 'skipped'
  }
  const token = env.GITHUB_TOKEN
  if (!token) return skip('No token; pass github-token to post the comment.')
  let event
  try {
    event = JSON.parse(await read(env.GITHUB_EVENT_PATH, 'utf8'))
  } catch {
    return skip('Could not read the event payload.')
  }
  const pr = event?.pull_request?.number
  if (!pr) return skip('Not a pull request event; nothing to comment on.')
  let sarif
  try {
    sarif = JSON.parse(await read(env.AIRLOCK_SARIF, 'utf8'))
  } catch {
    return skip('The audit did not produce a result (it may have stopped before checking anything); see the gate step.')
  }

  const api = (env.GITHUB_API_URL || 'https://api.github.com').replace(/\/$/, '')
  const repo = env.GITHUB_REPOSITORY
  const runUrl = env.GITHUB_RUN_ID ? `${env.GITHUB_SERVER_URL || 'https://github.com'}/${repo}/actions/runs/${env.GITHUB_RUN_ID}` : ''
  const body = buildComment(sarif, {
    passed: env.AIRLOCK_OUTCOME === 'success',
    schema: env.INPUT_SCHEMA || 'public',
    sha: event.pull_request.head?.sha || '',
    runUrl,
  })

  const refused = (res) =>
    skip(`GitHub refused the comment (HTTP ${res.status}). The workflow needs "permissions: pull-requests: write"; PRs from forks get a read-only token.`)

  let existing = null
  for (let page = 1; page <= 10 && !existing; page++) {
    const res = await gh(fetchImpl, api, token, 'GET', `/repos/${repo}/issues/${pr}/comments?per_page=100&page=${page}`)
    if (!res.ok) return refused(res)
    const list = await res.json()
    existing = list.find((c) => typeof c.body === 'string' && c.body.includes(MARKER)) || null
    if (list.length < 100) break
  }
  const res = existing
    ? await gh(fetchImpl, api, token, 'PATCH', `/repos/${repo}/issues/comments/${existing.id}`, { body })
    : await gh(fetchImpl, api, token, 'POST', `/repos/${repo}/issues/${pr}/comments`, { body })
  if (!res.ok) return refused(res)
  log(`Airlock RLS: ${existing ? 'updated' : 'posted'} the pull request comment.`)
  return existing ? 'updated' : 'created'
}
