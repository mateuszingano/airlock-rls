import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fuse, extractTable, isAnonReadExposure } from '../src/fuse.mjs'

const staticResult = (findings) => ({
  schema: 'public',
  findings,
  allowed: [],
  problems: findings.filter((f) => f.severity === 'fail').length,
  warnings: findings.filter((f) => f.severity === 'warn').length,
  passed: !findings.some((f) => f.severity === 'fail'),
  tables: [],
})

test('extractTable pulls the table from a policy finding and an rls finding', () => {
  assert.equal(extractTable({ kind: 'anon_unscoped', object: 'articles."pub"' }), 'articles')
  assert.equal(extractTable({ kind: 'rls_disabled', object: 'payments' }), 'payments')
  assert.equal(extractTable({ kind: 'public_bucket', object: 'storage:avatars' }), null)
})

test('isAnonReadExposure only true for anon reads', () => {
  assert.equal(isAnonReadExposure({ kind: 'anon_unscoped', detail: '' }), true)
  assert.equal(isAnonReadExposure({ kind: 'rls_disabled' }), true)
  assert.equal(isAnonReadExposure({ kind: 'permissive_true', detail: '[SELECT] USING(true)' }), true)
  assert.equal(isAnonReadExposure({ kind: 'permissive_true', detail: '[INSERT] WITH CHECK(true)' }), false)
  assert.equal(isAnonReadExposure({ kind: 'write_unchecked', detail: '' }), false)
})

test('DAST confirms a static finding → stays fail, marked confirmed', () => {
  const r = fuse(staticResult([{ kind: 'anon_unscoped', severity: 'fail', object: 'articles."pub"', detail: 'x' }]), {
    leakTables: ['articles'],
    probed: ['articles'],
  })
  assert.equal(r.problems, 1)
  assert.equal(r.findings[0].verdict, 'confirmed')
  assert.match(r.findings[0].detail, /CONFIRMED/)
})

test('DAST reads nothing → static finding downgraded to warn (false positive killed)', () => {
  const r = fuse(staticResult([{ kind: 'anon_unscoped', severity: 'fail', object: 'drafts."pub"', detail: 'x' }]), {
    leakTables: [],
    probed: ['drafts'],
  })
  assert.equal(r.problems, 0)
  assert.equal(r.warnings, 1)
  assert.equal(r.findings[0].verdict, 'unconfirmed')
})

test('DAST leak with no static finding → added as a proven fail', () => {
  const r = fuse(staticResult([]), { leakTables: ['secrets'], probed: ['secrets'] })
  assert.equal(r.problems, 1)
  assert.equal(r.findings[0].kind, 'anon_read_leak')
  assert.equal(r.findings[0].object, 'secrets')
})

test('a table DAST did not probe is left untouched', () => {
  const r = fuse(staticResult([{ kind: 'anon_unscoped', severity: 'fail', object: 'x."p"', detail: 'x' }]), {
    leakTables: [],
    probed: [], // never probed x
  })
  assert.equal(r.problems, 1) // unchanged — no evidence either way
  assert.equal(r.findings[0].verdict, undefined)
})

test('non-read findings pass through untouched', () => {
  const r = fuse(staticResult([{ kind: 'write_unchecked', severity: 'warn', object: 't."w"', detail: 'x' }]), {
    leakTables: [],
    probed: ['t'],
  })
  assert.equal(r.warnings, 1)
  assert.equal(r.findings[0].kind, 'write_unchecked')
})
