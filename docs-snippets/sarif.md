### GitHub code scanning (SARIF) and annotations

Two outputs make findings show up where you already look on GitHub. Both are
**additive**: the normal report still prints and the exit code doesn't change.

```bash
npx airlock-rls "$SUPABASE_DB_URL" --sarif airlock.sarif   # also write a SARIF 2.1.0 log
npx airlock-rls "$SUPABASE_DB_URL" --format github         # also print ::error / ::warning annotations
```

- **`--sarif <file>`** writes a SARIF 2.1.0 log (validated against the official
  OASIS schema in the test suite): one rule per finding kind, `fail` → `error`,
  `warn` → `warning`, the finding's detail as the message, a stable fingerprint,
  and the copy-paste fix prompt under `properties.fixPrompt`.
- **`--format github`** prints one workflow command per finding, so GitHub
  renders it as an annotation on the run. It's skipped under `--json`, which
  stays parseable. Also read from `$AIRLOCK_FORMAT`.

**Where a finding points.** A finding from the live database has no file: its
location is the database object (`public.payments`, `notes."read all"`), as a
SARIF *logical* location. A finding that carries a file and line (from a
migrations file) gets a *physical* location, and GitHub points at that line.

#### Upload to code scanning (GitHub Action)

```yaml
permissions:
  contents: read
  security-events: write   # needed by upload-sarif

steps:
  - uses: actions/checkout@v4
  - uses: mateuszingano/airlock-rls@v1
    with:
      db-url: ${{ secrets.SUPABASE_DB_URL }}
      sarif: airlock.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()            # the gate fails the step on a leak; upload anyway
    with:
      sarif_file: airlock.sarif
      category: airlock-rls
```

The `sarif` input only adds the file; the gate still fails the job on a leak.

> Note: GitHub code scanning is built around files. Database findings carry a
> logical location only, so they may show without a line link (or, depending on
> GitHub's ingestion rules, not as an alert at all). Findings with a file and
> line (migrations mode) map cleanly. `--format github` annotations work for both.
