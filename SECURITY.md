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
