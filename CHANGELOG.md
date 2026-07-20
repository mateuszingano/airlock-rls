# Changelog

## 0.3.0 — BREAKING

Verdicts got stricter in three places. A project whose CI was green on 0.2.x can
fail on this version **without its database having changed** — the earlier
release was reporting some real exposures as warnings, or not at all.

### BREAKING: `USING (true)` reachable by `authenticated` is now a fail

It was a warning. In a B2B SaaS, `FOR SELECT TO authenticated USING (true)`
means every customer reads every other customer's rows — broken tenant
isolation, not a style note. Warnings do not break builds, so this shipped green.

If the table really is a shared feed or a public directory, waive it explicitly:

```
airlock --allow public_directory.everyone_reads
```

### BREAKING: `FOR DELETE` and `FOR UPDATE` are classified

`DELETE` was in neither the read nor the write command set, so
`FOR DELETE TO anon USING (true)` produced **zero findings and exit 0** — anyone
with the anon key could delete rows. `FOR UPDATE` with no `WITH CHECK` was
excluded by a condition pointing at a branch that could never run, so writing
*less* SQL looked safer to the gate than writing it explicitly.

Both are now `delete_unscoped` / `update_using_unscoped`, and both are a fail for
`authenticated` as well as `anon`: destroying or taking over another tenant's
rows is worse than reading them, and it is not reversible.

### BREAKING: `--allow <name>` is refused when the name is ambiguous

Policy names are unique per **table**, not per schema. `--allow public_read`
silenced that policy on every table carrying the name — including tables the
author never reviewed. A bare name now applies only when exactly one table (or
storage policy) carries it; otherwise nothing is waived and an `allow_ambiguous`
warning names the qualified form to use.

### Added

- **Materialized views are audited.** RLS does not apply to a matview at all, so
  `CREATE MATERIALIZED VIEW public.all_payments AS SELECT * FROM payments` plus a
  grant to `anon` is a full dump. It was not checked and not declared.
- **`--site` refuses more SSRF targets**: the IPv6 unspecified address (`[::]`,
  which reaches loopback on Linux, and the spellings the URL parser folds into
  it) and cloud metadata hostnames (`metadata.google.internal`, `metadata.goog`,
  `instance-data`), which resolve where `169.254.169.254` did.
- **`prepublishOnly` refuses to publish unless the integration test really ran.**
  `node --test` lets that file skip itself when no database is configured, which
  is how a broken role parser once shipped past 101 green unit tests.

### Fixed

- `airlock --allow <name>` **crashed the entire audit** on any project with a
  storage policy of that name, instead of waiving one finding.
- `nothing_audited` no longer fires alongside `matview_exposed`.
- `SECURITY.md` ships in the tarball.
- README documents `delete_unscoped`, `update_using_unscoped`, `matview_exposed`,
  `--fail-on` and `--strict`, and declares the allow-list refusal as deliberate.

## 0.2.6 and earlier

See the git history. Note that 0.2.x classified neither `DELETE` nor
`UPDATE`-without-`WITH CHECK`, and treated an `authenticated` tenant leak as a
warning — treat a green run on it as silent about those cases.
