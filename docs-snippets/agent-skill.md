### Use it from a coding agent (skill)

Airlock ships an agent skill so Claude Code, Cursor and other agents that support skills can
run the audit and fix what it finds, without you remembering the flags:

```bash
npx skills add https://github.com/mateuszingano/airlock-rls --skill airlock-rls
```

Or copy `skills/airlock-rls/` into `~/.claude/skills/` (Claude Code). Then ask your agent:

```
audit the RLS of this Supabase project
is my deployed app leaking a service key? https://your-app.com
```

The skill picks the mode (site scan with just a URL, or the full DB audit from
`$SUPABASE_DB_URL`, never printing it), reads the `--json` findings, turns each `fixPrompt` into
a migration it shows you before applying, never "fixes" by disabling RLS or writing
`USING (true)`, and re-runs the check to confirm.
