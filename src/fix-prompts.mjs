// Airlock — copy-paste fix prompts for AI coding tools (Cursor, Lovable, Bolt,
// Claude Code, Copilot...).
//
// A finding tells you WHAT is wrong. Most people who ship a Supabase app with an
// AI tool can't turn "update_using_unscoped" into a migration on their own, but
// they can paste a precise request into the tool that wrote the code. Each prompt
// carries the exact object and detail Airlock found, the specific change to make,
// and the guard rails an AI tends to skip (never "fix" by disabling RLS or by
// writing USING (true), show the SQL before running it, re-run the check).
//
// Pure: no I/O. The prompt never contains a secret: findings already redact keys.

const GUARD =
  'Do not fix this by disabling Row Level Security or by adding a policy with USING (true). ' +
  'Show me the SQL migration and explain each change before applying it. ' +
  'When done, I will re-run `npx airlock-rls` to confirm the finding is gone.'

/** kind → the specific change to ask for. `storage_` findings reuse the base kind. */
const ASK = {
  rls_disabled:
    'Enable Row Level Security on this table and add policies so each user can only read and change their own rows ' +
    '(usually by comparing a user_id / owner column to (select auth.uid())). If some rows must be public, write a ' +
    'SELECT-only policy that names exactly which rows.',
  permissive_true:
    'This policy lets every row through. Replace its condition with one scoped to the row owner or tenant, e.g. ' +
    '(select auth.uid()) = user_id. If the data really is public, keep it SELECT-only and say so in a comment.',
  anon_unscoped:
    'Anonymous visitors can read rows this policy was meant to protect. Restrict it to the authenticated role and ' +
    'scope it to the row owner or tenant.',
  authenticated_unscoped:
    'Any signed-in user can read every row here, including other users\' data. Scope the policy to the row owner or ' +
    'to the tenant the user belongs to (e.g. a membership lookup), not just "is logged in".',
  or_branch_unscoped:
    'One OR branch of this policy has no owner check, so it lets every row through. Rewrite the condition so every ' +
    'branch is scoped to the row owner or tenant.',
  write_unscoped:
    'This write policy does not check who owns the row. Add a WITH CHECK that ties the new row to (select auth.uid()) ' +
    'or the user\'s tenant, so nobody can write rows on behalf of someone else.',
  write_unchecked:
    'This INSERT/UPDATE policy has no WITH CHECK scoped to the user. Add one so a user can only create or modify rows ' +
    'they own.',
  update_using_unscoped:
    'This UPDATE policy\'s USING clause lets a user target rows they don\'t own. Scope USING to the row owner, and add a ' +
    'WITH CHECK so the owner column can\'t be changed to someone else.',
  delete_unscoped:
    'This DELETE policy lets a user delete rows they don\'t own. Scope it to the row owner or tenant.',
  anon_read_leak:
    'A live request with the public anon key actually read rows from this table. Find the policy or grant that allows ' +
    'it and scope it so anonymous visitors only see what is meant to be public (or nothing).',
  anon_write_leak:
    'A live request with the public anon key was able to write to this table. Remove anonymous INSERT/UPDATE/DELETE ' +
    'access (revoke the grant or scope the policy) unless anonymous writes are a deliberate feature.',
  security_definer:
    'This SECURITY DEFINER function runs with its owner\'s rights and bypasses RLS. Make it SECURITY INVOKER if it ' +
    'doesn\'t need elevated rights; otherwise check the caller inside it with (select auth.uid()) and revoke EXECUTE ' +
    'from anon and public.',
  anon_executes_definer:
    'Anonymous visitors can call this SECURITY DEFINER function, which bypasses RLS. Revoke EXECUTE from anon and ' +
    'public (grant it only to authenticated if needed) and check the caller inside the function.',
  definer_search_path_mutable:
    'This SECURITY DEFINER function has no fixed search_path, so a caller could make it run their own objects. Add ' +
    'SET search_path = \'\' to the function and schema-qualify every table and function it uses.',
  view_bypasses_rls:
    'This view runs with its owner\'s rights, so it ignores the RLS on the tables underneath. Recreate it WITH ' +
    '(security_invoker = true), or move it out of the exposed schema.',
  matview_exposed:
    'Materialized views have no RLS at all, and this one is readable through the API. Revoke SELECT from anon and ' +
    'authenticated, or move it to a schema the API does not expose and serve it through a scoped function.',
  public_bucket:
    'This storage bucket is public: anyone with a file\'s URL can download it. Make it private and serve files with ' +
    'signed URLs, unless every file in it is meant to be public.',
  realtime_exposure:
    'This table is published to Realtime and its rows are readable anonymously, so changes stream to anyone listening. ' +
    'Fix the table\'s read policy first, or remove it from the supabase_realtime publication.',
  bypassrls_role:
    'A role with BYPASSRLS ignores every policy. Check whether this role really needs it; if not, ALTER ROLE ... ' +
    'NOBYPASSRLS, and make sure no client-facing connection uses it.',
  owner_bypasses_rls:
    'The table owner bypasses RLS on this table. If anything client-facing connects as the owner, enable ' +
    'ALTER TABLE ... FORCE ROW LEVEL SECURITY, or switch that connection to a non-owner role.',
  service_role_exposed:
    'My Supabase service key (service_role / sb_secret) is in the JavaScript that ships to the browser. It bypasses ' +
    'all Row Level Security. Move every use of it to server-side code (API route, server action or Edge Function), ' +
    'read it from a server-only environment variable (never NEXT_PUBLIC_ / VITE_ / PUBLIC_), and use the anon / ' +
    'publishable key in the browser. Then tell me to rotate the key in the Supabase dashboard, because the old one ' +
    'is already public.',
  env_file_exposed:
    'My site serves its .env file to anyone who requests it. Make sure the build output and web root never contain ' +
    '.env files (fix the deploy config / .gitignore / hosting rules), then list which secrets were in it so I can ' +
    'rotate every one of them.',
  git_exposed:
    'My site serves its .git folder publicly, which lets anyone download the source code and its full history ' +
    '(including secrets committed in the past). Change the deploy so .git is never in the web root, then help me ' +
    'find and rotate any secret that was ever committed.',
  source_map_exposed:
    'My production site publishes JavaScript source maps, so anyone can download my original source code. Turn off ' +
    'public source maps in the production build (or upload them privately to the error tracker), and check the ' +
    'source for hard-coded secrets.',
}

/**
 * The copy-paste prompt for one finding, or null when there is nothing to fix
 * (config bookkeeping like allow_unused, scan_truncated, nothing_audited).
 * @param {{kind:string, severity:string, object:string, detail:string}} finding
 * @returns {string|null}
 */
export function fixPromptFor(finding) {
  if (!finding || !finding.kind) return null
  const base = finding.kind.startsWith('storage_') ? finding.kind.slice('storage_'.length) : finding.kind
  const ask = ASK[base]
  if (!ask) return null
  const where = finding.kind.startsWith('storage_') ? ' (a Supabase Storage policy on storage.objects)' : ''
  return (
    `airlock-rls found a security problem in my Supabase app${where}:\n` +
    `  ${finding.object}: ${finding.detail}\n\n` +
    `${ask}\n\n${GUARD}`
  )
}

/** Kinds that have a prompt — exported for tests. */
export const PROMPT_KINDS = Object.keys(ASK)
