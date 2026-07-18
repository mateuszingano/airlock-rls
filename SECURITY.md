# Security Policy

## Reporting a vulnerability

Found a security issue? Please report it **privately**:

- Open a private GitHub security advisory (Security → Advisories → Report a vulnerability), or
- Email the maintainer.

Please do **not** open a public issue for security problems. We aim to acknowledge
reports within a few business days.

## Supported versions

The latest published version on npm receives security fixes.

## Scope — what Airlock touches, by mode

Airlock ships no telemetry. Keep the connection string and anon key you pass it in
a secret store, never in source control. What it does to your data depends on the
mode:

- **Static audit (default).** Reads only the catalog — `pg_tables`, `pg_policies`,
  grants, functions, views. It never reads row data and never writes.
- **DAST read (`--url` + `--anon-key`).** Uses the anon key — exactly what an
  attacker holds — to actually `SELECT` from each exposed table over the REST API,
  to *prove* a leak instead of inferring it. This **reads row data** (that is the
  point); it writes nothing.
- **DAST write (`--dast-write`, opt-in).** Attempts an anonymous `INSERT` of an
  empty payload to prove whether writes are open. On most tables a NOT NULL column
  rejects it and nothing is persisted. On an all-nullable, open table it **can
  create one test row** — Airlock then **deletes that row automatically when it
  can target it by the row's own primary key** (a column named `id`/`uuid`). It
  never deletes by a foreign key (`user_id`) or a non-unique column, so a cleanup
  can't touch your existing rows; if there's no `id`/`uuid` to target, it doesn't
  delete at all and the finding names the row so you can remove it. It never reads,
  updates, or deletes any of your existing data.

## TLS to Supabase (`rejectUnauthorized: false`)

When the connection targets Supabase (or the URL carries `sslmode=require`),
Airlock connects over TLS but does **not** verify the certificate chain
(`ssl: { rejectUnauthorized: false }` in `src/audit.mjs`). This is deliberate:
Supabase serves a certificate that isn't in the system CA bundle, and recent
`pg` treats `sslmode=require` as `verify-full`, which fails with
"self-signed certificate in certificate chain".

The trade-off: the connection is encrypted but not authenticated, so it does not
protect against an active man-in-the-middle on the path to the database. This is
an acceptable trade-off for Airlock's use — the database connection (the `pg`
catalog audit) only queries metadata (`pg_tables`, `pg_policies`, grants), reads
no row data and writes nothing. (The optional DAST probes go over the separate
HTTPS REST API with the anon key — see **Scope** above.) If you pass
`sslmode=verify-full`/`verify-ca` explicitly, Airlock prints a one-line stderr
warning that it is overriding it. Local plaintext connections (e.g. `localhost`
with no `sslmode`) are left untouched.
