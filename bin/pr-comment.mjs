#!/usr/bin/env node
// Used by action.yml (`comment: true`). Always exits 0: the comment is a
// courtesy, the gate step's exit code is what blocks the merge.
import { upsertComment } from '../src/pr-comment.mjs'

try {
  await upsertComment()
} catch (err) {
  console.log(`::warning title=Airlock RLS PR comment::Could not post the comment: ${err?.message || err}`)
}
