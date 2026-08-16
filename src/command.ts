/**
 * The `/scan` slash command surface for dsh-guard.
 * @module dsh-guard/command
 */

import type { CommandInvocation, CommandResult } from '@deepseek-ai/dsh-commands'
import type { GuardStateSnapshot, RuntimeEvent, ScanReport, ScanSeverity } from './types.ts'
import { renderReport } from './report.ts'

/** The outcome of one scan request. */
export type ScanOutcome =
  | { readonly kind: 'report'; readonly report: ScanReport }
  | { readonly kind: 'error'; readonly message: string }

/** Everything the command, tool, and web panel need from the plugin core. */
export interface ScanDeps {
  /** Resolve and scan a target; never throws. */
  runScan(target: string): ScanOutcome
  /** The current runtime snapshot (whitelist, last scan, events). */
  snapshot(): GuardStateSnapshot
  /** Append a runtime event to the shared ring buffer. */
  record(source: RuntimeEvent['source'], severity: ScanSeverity, message: string, details?: Record<string, unknown>): void
  /** Whitelist a plugin name. */
  trust(name: string): boolean
  /** Remove a plugin from the whitelist. */
  untrust(name: string): boolean
  /** Whether a plugin name is whitelisted. */
  isTrusted(name: string): boolean
}

/** The structural shape of the dsh `commands` service. */
export interface CommandService {
  register(definition: {
    readonly name: string
    readonly description: string
    readonly handler: (invocation: CommandInvocation) => CommandResult | Promise<CommandResult>
  }): () => void
}

/** Register the `/scan` command. Returns a disposer. */
export function registerScanCommand(commands: CommandService, deps: ScanDeps): () => void {
  return commands.register({
    name: 'scan',
    description: 'Static security scan of a plugin directory or a single file. Usage: /scan <plugin-name-or-path>',
    async handler(invocation: CommandInvocation): Promise<CommandResult> {
      const target = invocation.rawInput.trim()
      if (target.length === 0) {
        return { kind: 'error', text: 'Usage: /scan <plugin-name-or-path> — e.g. /scan ./plugins/my-plugin or /scan my-plugin' }
      }
      const outcome = deps.runScan(target)
      if (outcome.kind === 'error') {
        return { kind: 'error', text: outcome.message }
      }
      return { kind: 'success', text: renderReport(outcome.report) }
    },
  })
}