/**
 * Dangerous tool-call argument patterns checked by the `tools/pre-execute`
 * watcher: shell download-and-pipe, writing into ~/.ssh, destructive
 * filesystem commands, and token-draining loops. Data-driven so operators can
 * add patterns without code changes.
 * @module dsh-guard/threats
 */

import type { ScanSeverity } from '../types.ts'

/** One dangerous argument pattern. */
export interface ToolThreatPattern {
  readonly id: string
  readonly severity: ScanSeverity
  /** Tool names matched (regex against the tool name); all tools when absent. */
  readonly tools?: string
  /** Regex over the serialized tool arguments. */
  readonly regex: string
  readonly flags?: string
  readonly message: string
}

/** The bundled tool-call threat patterns. */
export const TOOL_THREATS: readonly ToolThreatPattern[] = [
  {
    id: 'rt.bash-download-pipe',
    severity: 'block',
    tools: '^(bash|pwsh|powershell|terminal|exec)',
    regex: '(curl|wget|nc\\b|ncat|powershell|Invoke-WebRequest|iwr|irm)[\\s\\S]{0,200}(\\|\\s*|;\\s*)(sh|bash|pwsh|cmd|powershell)\\b',
    flags: 'i',
    message: 'shell command downloads and pipes remote content into a shell',
  },
  {
    id: 'rt.bash-ssh-write',
    severity: 'block',
    tools: '^(bash|pwsh|powershell|terminal|exec)',
    regex: '(>>|>|tee\\s+-a?)[\\s\\S]{0,80}\\.ssh\\b',
    flags: 'i',
    message: 'shell command writes into ~/.ssh',
  },
  {
    id: 'rt.bash-destructive',
    severity: 'block',
    tools: '^(bash|pwsh|powershell|terminal|exec)',
    regex: 'rm\\s+-(rf|fr)\\s+(--no-preserve-root\\s+)?\\/\\s*$|rm\\s+-(rf|fr)\\s+--no-preserve-root\\b|mkfs(\\.|\\s)|dd\\s+if=[^\\s]+\\s+of=\\/dev\\b|:?\\(\\)\\s*\\{\\s*:\\|:&|chmod\\s+-R\\s+777\\s+\\/\\b',
    flags: 'i',
    message: 'destructive shell command (root wipe, mkfs, dd to /dev, fork bomb, chmod -R 777 /)',
  },
  {
    id: 'rt.bash-token-drain',
    severity: 'warn',
    tools: '^(bash|pwsh|powershell|terminal|exec)',
    regex: '\\byes\\s|while\\s+true|while\\s*\\(1\\)|dd\\s+if=\\/dev\\/zero\\b|cat\\s+\\/dev\\/zero\\b|seq\\s+\\d+\\s+inf\\b',
    flags: 'i',
    message: 'shell command likely runs forever and drains tokens',
  },
  {
    id: 'rt.exfil-context',
    severity: 'warn',
    regex: '(env|environ|api[_-]?key|secret|token|credential|password)[\\s\\S]{0,120}(https?://|curl|wget|fetch\\()',
    flags: 'i',
    message: 'tool call combines secret-looking data with a network transfer',
  },
]

/** Compile the bundled patterns once. */
const COMPILED = TOOL_THREATS.map(pattern => ({
  ...pattern,
  compiled: new RegExp(pattern.regex, pattern.flags ?? ''),
  toolRe: pattern.tools !== undefined ? new RegExp(pattern.tools, 'i') : undefined,
}))

/** A threat match. */
export interface ToolThreatMatch {
  readonly id: string
  readonly severity: ScanSeverity
  readonly message: string
}

/** Check a tool call (name + serialized arguments) against the patterns. */
export function matchToolThreats(toolName: string, argsText: string): ToolThreatMatch[] {
  const matches: ToolThreatMatch[] = []
  for (const pattern of COMPILED) {
    if (pattern.toolRe !== undefined && !pattern.toolRe.test(toolName)) continue
    pattern.compiled.lastIndex = 0
    if (pattern.compiled.test(argsText)) {
      matches.push({ id: pattern.id, severity: pattern.severity, message: pattern.message })
    }
  }
  return matches
}