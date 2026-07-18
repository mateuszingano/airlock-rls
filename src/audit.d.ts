export interface Finding {
  kind: string
  severity: 'fail' | 'warn'
  object: string
  detail: string
}

export interface AuditResult {
  schema: string
  findings: Finding[]
  allowed: Finding[]
  problems: number
  warnings: number
  passed: boolean
  tables: string[]
  dast?: { probed: number; confirmed: string[] }
}

export interface Policy {
  tablename: string
  policyname: string
  cmd: string
  roles: string[]
  qual: string | null
  with_check: string | null
  permissive?: string
}

/** True if the policy qualifier scopes access (auth.uid / service_role / helper). */
export function isScoped(qual: string | null): boolean

/** The helper name a policy is scoped through, if that's the ONLY scoping. */
export function helperScope(qual: string | null): string | null

/** Classify one PERMISSIVE policy into zero or more findings. */
export function classifyPolicy(
  p: Policy,
  ctx?: { grants?: Record<string, { anon: Set<string>; authenticated: Set<string> }> | null; restrictives?: Policy[] },
): Finding[]

/** Build the structured result from raw catalog rows. Pure — no I/O. */
export function buildResult(args: Record<string, unknown>): AuditResult

/** Run the RLS audit against a Postgres/Supabase database. */
export function audit(opts: {
  dbUrl: string
  schema?: string
  allow?: string[] | Set<string>
}): Promise<AuditResult>
