/**
 * dsh-security-guard: a security scanner plugin for the DeepSeek Harness (dsh).
 *
 * - Static scan at install/load time (`/scan`, `plugin_scan`, web panel):
 *   malicious code (eval/child_process/network exfiltration), prompt- and
 *   context-injection payloads (English + Chinese directive phrases, hidden
 *   base64, zero-width characters), and token-waste (oversize files,
 *   repetition, base64-dominant content, filler comments).
 * - Runtime monitoring: context injection at `agent/pre-step` (reject),
 *   dangerous tool-call arguments at `tools/pre-execute` (deny), injected
 *   tool results at `tools/post-execute` (replace), sensitive fs access
 *   (`fs/observed`, recorded only), per-step token usage (`session/event`).
 *
 * The scanner is non-executing by design: scanned plugin code is parsed with
 * the TypeScript compiler API and examined with read-only passes — never
 * imported, required, or evaluated.
 * @module dsh-security-guard
 */

import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { existsSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'
import type { GuardConfig, GuardStateSnapshot, RuntimeEvent, ScanReport, ScanSeverity } from './types.ts'
import { compileRules, loadBundledAllowlist, loadBundledRules, loadRulesDir, mergeRules } from './rules.ts'
import { scanTarget, type ScanOptions } from './static/scanner.ts'
import { Whitelist } from './whitelist.ts'
import { GuardRuntime } from './runtime/watcher.ts'
import type { ScanDeps, ScanOutcome } from './command.ts'
import { registerScanCommand } from './command.ts'
import { registerScanTool } from './tool.ts'
import { registerPanel } from './web/panel.ts'

/** Cordis plugin name used by loader diagnostics. */
export const name = 'scan-guard'

/** No required services; tools/commands/webServer are wired when present. */
export const inject = []

/** The plugin configuration type (see {@link GuardConfig}). */
export type Config = GuardConfig

/** Runtime schema for {@link Config}. */
export const Config = z.object({
  scanRoots: z.array(z.string()).default([]),
  ruleSeverity: z.dict(z.union([z.const('block'), z.const('warn')])).default({}),
  allowlistDomains: z.array(z.string()).default([]),
  blocklistUrlPatterns: z.array(z.string()).default([]),
  rulesDir: z.string().default(''),
  workspaceRoots: z.array(z.string()).default([]),
  stateFile: z.string().default(''),
  maxFileBytes: z.number().min(1024).default(10 * 1024 * 1024),
  maxFiles: z.number().min(1).default(1000),
  skipSegments: z.array(z.string()).default(['node_modules', '.git', 'lib', 'dist', 'build', '.next', 'coverage']),
  maxStepChars: z.number().min(1).default(400_000),
  maxStepTokens: z.number().min(1).default(60_000),
  eventBuffer: z.number().min(10).max(100_000).default(500),
  denyDangerousToolCalls: z.boolean().default(true),
  webPanel: z.boolean().default(true),
}) as unknown as z<Config>

/**
 * Resolve a `/scan` target: a path when it looks like one, otherwise a plugin
 * directory name under one of the scan roots. Throws with a helpful message.
 */
function resolveTarget(input: string, scanRoots: readonly string[]): string {
  const trimmed = input.trim()
  if (trimmed.length === 0) throw new Error('usage: /scan <plugin-name-or-path>')
  const looksLikePath = /[\\/]/.test(trimmed) || /\.[a-z0-9]+$/i.test(trimmed)
  if (looksLikePath) {
    const abs = resolve(trimmed)
    if (!existsSync(abs)) throw new Error(`no such file or directory: ${abs}`)
    return abs
  }
  for (const root of scanRoots) {
    const candidate = join(resolve(root), trimmed)
    if (existsSync(candidate) && statSync(candidate).isDirectory()) return candidate
  }
  const roots = scanRoots.length === 0 ? '(none configured)' : scanRoots.join(', ')
  throw new Error(`plugin "${trimmed}" not found under scanRoots: ${roots}`)
}

/** Register the guard plugin on a context. */
export function apply(ctx: Context, config: Config): void {
  const cfg: GuardConfig = {
    ...config,
    scanRoots: config.scanRoots.length > 0 ? config.scanRoots : [process.cwd()],
    workspaceRoots: config.workspaceRoots.length > 0 ? config.workspaceRoots : [process.cwd()],
  }

  const whitelist = new Whitelist(cfg)
  whitelist.load()

  const bundled = loadBundledRules()
  const extra = cfg.rulesDir !== '' && existsSync(cfg.rulesDir) ? loadRulesDir(cfg.rulesDir) : []
  const rules = compileRules(mergeRules(bundled, extra), cfg)
  const phraseRules = rules.filter(resolved => resolved.matcher.kind === 'phrase')
  const urlRules = rules.filter(resolved => resolved.matcher.kind === 'url')
  const allowlist = [...loadBundledAllowlist(), ...cfg.allowlistDomains]

  const runtime = new GuardRuntime(cfg, phraseRules, allowlist, cfg.blocklistUrlPatterns)
  const disposeRuntime = runtime.attach(ctx)

  let lastScan: ScanReport | undefined
  const scanOptions: ScanOptions = { config: cfg, rules, phraseRules, urlRules, allowlist }

  const deps: ScanDeps = {
    runScan(target: string): ScanOutcome {
      let root: string
      try {
        root = resolveTarget(target, cfg.scanRoots)
      } catch (error: unknown) {
        return { kind: 'error', message: error instanceof Error ? error.message : String(error) }
      }
      try {
        const report = scanTarget(root, scanOptions)
        lastScan = report
        runtime.record('command', report.verdict === 'block' ? 'block' : 'warn', `scan ${report.target}: ${report.verdict} (${report.summary.block} block, ${report.summary.warn} warn)`)
        return { kind: 'report', report }
      } catch (error: unknown) {
        return { kind: 'error', message: `scan failed: ${error instanceof Error ? error.message : String(error)}` }
      }
    },
    snapshot(): GuardStateSnapshot {
      return { trusted: whitelist.list(), lastScan, events: [...runtime.events], ruleCount: rules.length }
    },
    record(source: RuntimeEvent['source'], severity: ScanSeverity, message: string, details?: Record<string, unknown>): void {
      runtime.record(source, severity, message, undefined, details)
    },
    trust(name: string): boolean {
      return whitelist.trust(name)
    },
    untrust(name: string): boolean {
      return whitelist.untrust(name)
    },
    isTrusted(name: string): boolean {
      return whitelist.isTrusted(name)
    },
  }

  // Wire services that are already present, and latch onto the ones that
  // arrive later (the plugin itself declares no `inject`). Teardown runs when
  // the fiber unloads.
  const teardowns: (() => void)[] = []
  const wired = { tools: false, commands: false, panel: false }

  const wire = (): void => {
    const tools = ctx.get('tools')
    if (tools !== undefined && !wired.tools) {
      wired.tools = true
      teardowns.push(registerScanTool(tools, deps))
    }
    const commands = ctx.get('commands')
    if (commands !== undefined && !wired.commands) {
      wired.commands = true
      teardowns.push(registerScanCommand(commands, deps))
    }
    if (cfg.webPanel) {
      const webServer = ctx.get('webServer')
      if (webServer !== undefined && !wired.panel) {
        wired.panel = true
        teardowns.push(registerPanel(webServer, deps))
      }
    }
  }

  ctx.effect(() => {
    wire()
    ctx.on('internal/service', (serviceName: string, value: unknown) => {
      if (value !== undefined && (serviceName === 'tools' || serviceName === 'commands' || serviceName === 'webServer')) {
        wire()
      }
    })
    return () => {
      disposeRuntime()
      for (const teardown of teardowns) teardown()
    }
  })
}