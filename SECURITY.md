# Security Policy

## Reporting a vulnerability

Found a security issue? Please report it **privately**:

- Open a private GitHub security advisory (Security → Advisories → Report a vulnerability), or
- Email the maintainer.

Please do **not** open a public issue for security problems. We aim to acknowledge
reports within a few business days.

## Supported versions

The latest published version on npm receives security fixes.

## Scope

This tool reads your database catalog and (optionally) probes your REST API to
detect exposed tables. It never writes to your database and ships no telemetry.
Keep the connection string you pass it in a secret store, never in source control.

## TLS to Supabase (`rejectUnauthorized: false`)

When the connection targets Supabase (or the URL carries `sslmode=require`),
Airlock connects over TLS but does **not** verify the certificate chain
(`ssl: { rejectUnauthorized: false }` in `src/audit.mjs`). This is deliberate:
Supabase serves a certificate that isn't in the system CA bundle, and recent
`pg` treats `sslmode=require` as `verify-full`, which fails with
"self-signed certificate in certificate chain".

The trade-off: the connection is encrypted but not authenticated, so it does not
protect against an active man-in-the-middle on the path to the database. This is
an acceptable trade-off for Airlock's use — it's a **read-only** audit that only
queries the catalog (`pg_tables`, `pg_policies`, grants) and never reads row data
or writes anything. Local plaintext connections (e.g. `localhost` with no
`sslmode`) are left untouched.
