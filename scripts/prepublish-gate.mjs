#!/usr/bin/env node
// Publish gate.
//
// `npm test` is allowed to run offline: test/integration.test.mjs skips itself
// when no database URL is present, so contributors get a green suite without
// standing up Postgres. Publishing under that same rule is not acceptable.
//
// The reason is a scar, not a theory. A refactor of role parsing passed 101
// green unit tests and was still broken against a real database, because every
// unit fixture spelled `roles` as a JS array while node-pg hands back the raw
// Postgres string `{anon}`. Only the integration test — the one that skips
// itself — could see it. Publishing without it means shipping the classifier
// unverified against the one data shape that actually reaches users.
//
// So: this gate refuses to publish unless the integration test really ran.

import { spawnSync } from 'node:child_process'

const DB_URL = process.env.AIRLOCK_TEST_DB_URL || process.env.DATABASE_URL

if (!DB_URL) {
  console.error(`
airlock: refusing to publish without the integration test.

  test/integration.test.mjs skips itself when no database is configured, so
  "npm test" can pass offline having never run the audit against a real
  Postgres. That is the exact gap that let a broken role parser ship green.

  Stand up a database and set the URL, then publish:

    docker run --rm -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:16
    AIRLOCK_TEST_DB_URL=postgresql://postgres:postgres@127.0.0.1:5432/postgres npm publish
`)
  process.exit(1)
}

const run = spawnSync('node', ['--test'], { stdio: 'inherit' })
if (run.status !== 0) process.exit(run.status ?? 1)

// Belt and braces: a green run still has to prove the integration file was not
// skipped for some other reason (renamed env var, moved file).
const check = spawnSync('node', ['--test', 'test/integration.test.mjs'], { encoding: 'utf8' })
const skipped = /^# skipped\s+([1-9]\d*)/m.exec(check.stdout || '')
if (skipped) {
  console.error(`\nairlock: the integration test reported ${skipped[1]} skipped test(s). Refusing to publish.\n`)
  process.exit(1)
}
