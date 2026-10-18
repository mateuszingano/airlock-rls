import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const BIN = fileURLToPath(new URL('../bin/airlock.mjs', import.meta.url))
const run = (...args) => spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', env: { ...process.env, SUPABASE_DB_URL: '', SUPABASE_SITE_URL: '' } })

test('#cli nothing to audit exits 2', () => {
  const r = run()
  assert.equal(r.status, 2)
  assert.match(r.stderr, /Nothing to audit/)
})

test('#cli an unreachable --site names the URL and exits 2 (never a pass)', () => {
  // .invalid is reserved (RFC 2606): it never resolves, online or offline.
  const r = run('--site', 'https://airlock-test.invalid')
  assert.equal(r.status, 2)
  assert.match(r.stderr, /Couldn't scan https:\/\/airlock-test\.invalid/)
  assert.doesNotMatch(r.stdout, /No RLS problems/)
})
