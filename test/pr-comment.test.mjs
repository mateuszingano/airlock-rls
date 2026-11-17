import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildComment, upsertComment, MARKER } from '../src/pr-comment.mjs'
import { toSarif } from '../src/sarif.mjs'

const leaky = toSarif({
  schema: 'public',
  findings: [
    { kind: 'rls_disabled', severity: 'fail', object: 'profiles', detail: 'RLS is off — every row is readable with the anon key' },
    { kind: 'public_bucket', severity: 'warn', object: 'storage:avatars', detail: 'storage bucket is public | anyone with the URL reads it' },
  ],
}, { version: '0.0.0' })
const clean = toSarif({ schema: 'public', findings: [] }, { version: '0.0.0' })

test('failing gate: title counts problems, rows list each finding, marker first', () => {
  const body = buildComment(leaky, { passed: false, schema: 'public', sha: 'abcdef1234', runUrl: 'https://x/run/1' })
  assert.ok(body.startsWith(MARKER))
  assert.match(body, /❌ Airlock RLS: 1 problem must be fixed before merging/)
  assert.match(body, /\| ✗ \| `rls_disabled` \| `public\.profiles` \| RLS is off/)
  assert.match(body, /\| ! \| `public_bucket` \| `storage:avatars` \|/)
  assert.match(body, /bucket is public \\\| anyone/, 'a pipe in the detail is escaped so the table does not break')
  assert.match(body, /commit abcdef1 · \[job log\]\(https:\/\/x\/run\/1\)/)
})

test('passing gate with warnings and clean gate', () => {
  const warnOnly = toSarif({ schema: 'public', findings: [{ kind: 'security_definer', severity: 'warn', object: 'fn:x', detail: 'd' }] }, { version: '0' })
  assert.match(buildComment(warnOnly, { passed: true }), /✅ Airlock RLS: passed, 1 warning worth a look/)
  assert.match(buildComment(warnOnly, { passed: false }), /1 warning block this PR \(fail-on: warn\)/)
  const body = buildComment(clean, { passed: true })
  assert.match(body, /✅ Airlock RLS: no exposure found/)
  assert.doesNotMatch(body, /\| Finding \|/, 'no empty table')
})

test('long lists are cut at 20 rows with a pointer to the log', () => {
  const many = toSarif({ schema: 'public', findings: Array.from({ length: 25 }, (_, i) => ({ kind: 'rls_disabled', severity: 'fail', object: `t${i}`, detail: 'off' })) }, { version: '0' })
  const body = buildComment(many, { passed: false })
  assert.equal(body.split('\n').filter((l) => l.startsWith('| ✗')).length, 20)
  assert.match(body, /…and 5 more in the job log/)
})

function fakeEnv(files, extra = {}) {
  return {
    env: { GITHUB_TOKEN: 't', GITHUB_EVENT_PATH: 'event.json', AIRLOCK_SARIF: 'a.sarif', AIRLOCK_OUTCOME: 'failure', GITHUB_REPOSITORY: 'o/r', GITHUB_RUN_ID: '9', ...extra },
    read: async (p) => {
      if (!(p in files)) throw new Error('ENOENT')
      return files[p]
    },
    log: () => {},
  }
}
const event = JSON.stringify({ pull_request: { number: 7, head: { sha: 'abc1234' } } })

function fakeFetch(existing, { failWith } = {}) {
  const calls = []
  const fetchImpl = async (url, init) => {
    calls.push({ url, method: init.method, body: init.body && JSON.parse(init.body) })
    if (failWith) return { ok: false, status: failWith, json: async () => ({}) }
    if (init.method === 'GET') return { ok: true, status: 200, json: async () => existing }
    return { ok: true, status: 201, json: async () => ({}) }
  }
  return { calls, fetchImpl }
}

test('posts a new comment when none exists', async () => {
  const { calls, fetchImpl } = fakeFetch([{ id: 1, body: 'someone else' }])
  const done = await upsertComment({ ...fakeEnv({ 'event.json': event, 'a.sarif': JSON.stringify(leaky) }), fetchImpl })
  assert.equal(done, 'created')
  assert.equal(calls[1].method, 'POST')
  assert.match(calls[1].url, /\/repos\/o\/r\/issues\/7\/comments$/)
  assert.ok(calls[1].body.body.includes(MARKER))
})

test('edits its own comment instead of adding another', async () => {
  const { calls, fetchImpl } = fakeFetch([{ id: 1, body: 'hi' }, { id: 42, body: `${MARKER}\nold` }])
  const done = await upsertComment({ ...fakeEnv({ 'event.json': event, 'a.sarif': JSON.stringify(clean) }, { AIRLOCK_OUTCOME: 'success' }), fetchImpl })
  assert.equal(done, 'updated')
  assert.equal(calls[1].method, 'PATCH')
  assert.match(calls[1].url, /\/issues\/comments\/42$/)
})

test('never throws: no permission, not a PR, or no SARIF only skip', async () => {
  const denied = fakeFetch([], { failWith: 403 })
  assert.equal(await upsertComment({ ...fakeEnv({ 'event.json': event, 'a.sarif': JSON.stringify(leaky) }), fetchImpl: denied.fetchImpl }), 'skipped')
  const push = fakeFetch([])
  assert.equal(await upsertComment({ ...fakeEnv({ 'event.json': '{}', 'a.sarif': '{}' }), fetchImpl: push.fetchImpl }), 'skipped')
  assert.equal(push.calls.length, 0)
  const noSarif = fakeFetch([])
  assert.equal(await upsertComment({ ...fakeEnv({ 'event.json': event }), fetchImpl: noSarif.fetchImpl }), 'skipped')
  assert.equal(noSarif.calls.length, 0, 'no comment when the audit never produced a result')
})
