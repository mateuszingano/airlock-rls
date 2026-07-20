# Changelog

## 0.4.0 — 2026-07-20 — BREAKING

Findings from the 20/07 re-audit. Each made the gate report a real exposure as a
warning, or not at all, so a green result on an earlier version can go red here
without the database having changed. 0.4.0 is the first published build to carry
these fixes AND the 0.3.0 changes below (0.3.0 was tagged but never released to
npm, so upgrading from 0.2.x brings both).

### The gate no longer goes green under a least-privilege audit role

`audit()` read table grants from `information_schema.role_table_grants`, a view
that only returns rows the CURRENT role granted or is a member of. A read-only
audit role that is not a member of `anon`/`authenticated` — the exact role this
README recommends — saw ZERO grants there, no error, and every policy finding was
then silently suppressed: a `payments` table `FOR SELECT TO anon USING (true)`
audited clean while anon read the card numbers. Grants are now read with
`has_table_privilege()`, which answers from the catalog regardless of the caller
(and folds in PUBLIC grants and role membership). A restricted role gets the true
answer. A failure of that query now becomes "unknown" (fail-open), never a silent
empty. Covered by a new integration test that audits as a restricted role.

### `FOR ALL` policies are now judged on every command they expose

Two collapses of `ALL` into a single command are fixed:
- The write check asked only for the INSERT grant, so `FOR ALL USING (true)` with
  a grant of UPDATE-but-not-INSERT produced no finding while anon rewrote every
  row. It now asks for the whole set the command implies (INSERT **or** UPDATE).
- A legitimate schema — a permissive `FOR ALL` plus one scoped RESTRICTIVE per
  command — was failed with three findings, because the restrictive rescue asked
  "does a restrictive cover ALL?" instead of asking per concrete command. Each
  finding is now matched to a restrictive on its own command.

### Custom roles reached by inheritance are no longer invisible

A policy `TO app_role` where `GRANT app_role TO authenticated` was done leaks to
every logged-in user, but matched neither `anon` nor `authenticated` literally
and produced no finding. `audit()` now resolves the membership closure with
`pg_has_role()` and treats an inherited role as client-reachable. The README's
"custom roles are undecidable statically" now applies only to role-switch via
`authenticator` (SET ROLE), which remains genuinely undecidable.

### `--site` no longer follows a redirect to an internal address, or stops silently

- The scanner followed HTTP redirects with the default `follow`, so a public host
  answering `302 → 169.254.169.254` (or a compromised CDN script) reached an
  internal address that `isFetchableUrl` never vetted. Redirects are now driven
  by hand and every hop's `Location` is re-validated; a hop to a refused address
  throws instead of being followed.
- The scan read at most 50 JS bundles and reported "clean" — indistinguishable
  from having read them all. It now emits a `scan_truncated` warning naming how
  many went unscanned, and `--max-scripts <n>` raises the cap.

### Earlier re-audit findings (unchanged from the first pass)

### A RESTRICTIVE policy now narrows only the side it actually guards

`restrictiveScopes` read the restrictive's `USING` for every case, including
findings about `WITH CHECK`. So `RESTRICTIVE ... USING (owner = auth.uid())
WITH CHECK (true)` was taken as narrowing INSERT — it narrows nothing there.
A permissive policy letting `anon` forge rows as another tenant was downgraded
to a warn labelled "restrictive-narrowed — verify".

`USING` decides which existing rows are reachable; `WITH CHECK` decides what a
new row may look like. Each finding is now matched against the expression that
actually runs, with the documented fallback to `USING` when `WITH CHECK` is
omitted. A restrictive covering one command also no longer counts as narrowing
a permissive `FOR ALL`.

### The UPDATE takeover finding is no longer swallowed by an unrelated one

The dedupe matched on finding TEXT (`detail.startsWith('[ALL]')`) rather than on
what had been judged. On a `FOR ALL` policy the read finding is emitted first
and always carries that prefix, so
`FOR ALL TO anon USING (true) WITH CHECK (owner = auth.uid())` reported the read
leak and silently dropped `update_using_unscoped` — the full tenant takeover.
Writing the CORRECT `WITH CHECK` made the gate quieter. It now keys off whether
the `USING` expression was already judged in its role as the check.

### BREAKING: non-policy objects must be qualified in `--allow`

The allow-list was one flat namespace silencing six kinds of object, so
`--allow reports` muted a policy, a bucket, a view, a function, a realtime table
and a `matview_exposed` **fail** at once. Buckets, views, matviews, functions and
realtime tables now need their namespace — the same prefix the finding prints:

```
airlock --allow matview:reports,storage:receipts,view:summary,fn:is_admin,realtime:orders
```

A bare name that would have matched one of those waives nothing and raises
`allow_needs_namespace` with the spelling to use. An entry that matches nothing
at all now raises `allow_unused`, instead of being accepted in silence.

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
