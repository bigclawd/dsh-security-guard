/**
 * Test helpers: build a default GuardConfig and a compiled rule set, plus a
 * tiny scan helper that writes temp files for size-based fixtures.
 */

import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import type { GuardConfig } from '../src/types.ts'
import { compileRules, loadBundledAllowlist, loadBundledRules } from '../src/rules.ts'
import { scanTarget, type ScanOptions } from '../src/static/scanner.ts'
import type { ScanReport } from '../src/types.ts'

/** A default config; override any field. */
export function testConfig(overrides: Partial<GuardConfig> = {}): GuardConfig {
  return {
    scanRoots: [],
    ruleSeverity: {},
    allowlistDomains: [],
    blocklistUrlPatterns: [],
    rulesDir: '',
    workspaceRoots: [],
    stateFile: '',
    maxFileBytes: 10 * 1024 * 1024,
    maxFiles: 1000,
    skipSegments: ['node_modules', '.git', 'lib', 'dist', 'build', '.next', 'coverage'],
    maxStepChars: 400_000,
    maxStepTokens: 60_000,
    eventBuffer: 500,
    denyDangerousToolCalls: true,
    webPanel: true,
    ...overrides,
  }
}

/** The compiled rule set + allowlist, ready for scanning. */
export function testScanOptions(config: GuardConfig): ScanOptions {
  const rules = compileRules(loadBundledRules(), config)
  return {
    config,
    rules,
    phraseRules: rules.filter(resolved => resolved.matcher.kind === 'phrase'),
    urlRules: rules.filter(resolved => resolved.matcher.kind === 'url'),
    allowlist: [...loadBundledAllowlist(), ...config.allowlistDomains],
  }
}

/** Write a file into a fresh temp directory; returns the directory path. */
export function writeTempFiles(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-guard-test-'))
  for (const [name, content] of Object.entries(files)) {
    const path = join(dir, name)
    mkdirSync(dirname(path), { recursive: true })
    writeFileSync(path, content)
  }
  return dir
}

/** Scan a directory with default rules; returns the report. */
export function scanDir(dir: string, config: GuardConfig = testConfig()): ScanReport {
  return scanTarget(dir, testScanOptions(config))
}

/** A pre-step payload-shaped object (typed loosely; the watcher only reads agent.id + messages). */
export function preStepPayload(agentId: string, text: string): unknown {
  return {
    agent: { id: agentId },
    messages: [{ role: 'user', content: [{ type: 'text', text }] }],
    turn: 1,
    step: 1,
    signal: new AbortController().signal,
  }
}