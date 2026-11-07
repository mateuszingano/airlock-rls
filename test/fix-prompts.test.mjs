import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fixPromptFor, PROMPT_KINDS } from '../src/fix-prompts.mjs'

test('every rule that reports a real exposure has a fix prompt', () => {
  for (const k of [
    'rls_disabled', 'permissive_true', 'anon_unscoped', 'authenticated_unscoped', 'or_branch_unscoped',
    'write_unscoped', 'write_unchecked', 'update_using_unscoped', 'delete_unscoped', 'anon_read_leak',
    'anon_write_leak', 'security_definer', 'anon_executes_definer', 'definer_search_path_mutable',
    'view_bypasses_rls', 'matview_exposed', 'public_bucket', 'realtime_exposure', 'bypassrls_role',
    'owner_bypasses_rls', 'policy_trusts_user_metadata', 'service_role_exposed', 'env_file_exposed', 'git_exposed', 'source_map_exposed',
  ]) assert.ok(PROMPT_KINDS.includes(k), `missing prompt for ${k}`)
})

test('a prompt carries the exact object and detail, plus the guard rails', () => {
  const p = fixPromptFor({
    kind: 'permissive_true',
    severity: 'fail',
    object: 'invoices."public read"',
    detail: 'USING(true) — anon reads every row',
  })
  assert.match(p, /invoices\."public read"/)
  assert.match(p, /USING\(true\) — anon reads every row/)
  assert.match(p, /Do not fix this by disabling Row Level Security/)
  assert.match(p, /npx airlock-rls/)
})

test('storage_ findings reuse the base prompt and say it is a Storage policy', () => {
  const p = fixPromptFor({ kind: 'storage_permissive_true', severity: 'fail', object: 'storage.objects."open"', detail: 'x' })
  assert.match(p, /Supabase Storage policy/)
  assert.match(p, /lets every row through/)
})

test('bookkeeping findings get no prompt', () => {
  for (const kind of ['allow_unused', 'allow_ambiguous', 'scan_truncated', 'nothing_audited', 'check_skipped', 'helper_scoped']) {
    assert.equal(fixPromptFor({ kind, severity: 'warn', object: 'x', detail: 'y' }), null)
  }
  assert.equal(fixPromptFor(null), null)
})
