/**
 * Whitelist and report-rendering tests.
 */

import { describe, expect, it } from 'vitest'
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Whitelist } from '../src/whitelist.ts'
import { renderFinding, renderReport } from '../src/report.ts'
import { testConfig } from './helpers.ts'
import type { ScanFinding, ScanReport } from '../src/types.ts'

describe('Whitelist', () => {
  it('trusts, untrusts, and lists plugin names', () => {
    const whitelist = new Whitelist(testConfig())
    expect(whitelist.isTrusted('my-plugin')).toBe(false)
    expect(whitelist.trust('my-plugin')).toBe(true)
    expect(whitelist.trust('my-plugin')).toBe(false)
    expect(whitelist.isTrusted('my-plugin')).toBe(true)
    expect(whitelist.list()).toEqual(['my-plugin'])
    expect(whitelist.untrust('my-plugin')).toBe(true)
    expect(whitelist.isTrusted('my-plugin')).toBe(false)
  })

  it('persists to and reloads from the state file', () => {
    const stateFile = join(mkdtempSync(join(tmpdir(), 'dsh-security-guard-state-')), 'state.json')
    const first = new Whitelist(testConfig({ stateFile }))
    first.trust('alpha')
    first.trust('beta')
    first.persist()
    expect(existsSync(stateFile)).toBe(true)

    const second = new Whitelist(testConfig({ stateFile }))
    second.load()
    expect(second.isTrusted('alpha')).toBe(true)
    expect(second.isTrusted('beta')).toBe(true)
    expect(second.isTrusted('gamma')).toBe(false)
  })

  it('tolerates a corrupt state file', () => {
    const stateFile = join(mkdtempSync(join(tmpdir(), 'dsh-security-guard-state-')), 'state.json')
    writeFileSync(stateFile, 'not json at all')
    const whitelist = new Whitelist(testConfig({ stateFile }))
    expect(() => whitelist.load()).not.toThrow()
    expect(whitelist.list()).toEqual([])
  })

  it('writes a readable state file', () => {
    const stateFile = join(mkdtempSync(join(tmpdir(), 'dsh-security-guard-state-')), 'state.json')
    const whitelist = new Whitelist(testConfig({ stateFile }))
    whitelist.trust('alpha')
    const raw = readFileSync(stateFile, 'utf8')
    const parsed = JSON.parse(raw) as { version: number; trusted: string[] }
    expect(parsed.version).toBe(1)
    expect(parsed.trusted).toEqual(['alpha'])
  })
})

describe('report rendering', () => {
  const finding: ScanFinding = {
    ruleId: 'code.eval',
    severity: 'block',
    category: 'code',
    file: 'src/index.ts',
    line: 3,
    column: 5,
    excerpt: 'eval("1")',
    message: 'Direct eval() call',
  }

  const report: ScanReport = {
    target: './plugins/x',
    root: '/abs/plugins/x',
    verdict: 'block',
    findings: [finding],
    filesScanned: 7,
    filesSkipped: 0,
    bytesRead: 1234,
    scannedAt: '2026-01-01T00:00:00.000Z',
    ruleIds: ['code.eval'],
    summary: { block: 1, warn: 0, clean: 0 },
  }

  it('renders a finding line with severity, rule, location, and excerpt', () => {
    expect(renderFinding(finding)).toBe('[BLOCK] code.eval src/index.ts:3:5 Direct eval() call — eval("1")')
  })

  it('renders the report header, verdict, and findings', () => {
    const text = renderReport(report)
    expect(text).toContain('verdict: BLOCK (1 block, 0 warn)')
    expect(text).toContain('scanned 7 files')
    expect(text).toContain('[BLOCK] code.eval')
  })

  it('renders an empty report as clean with a placeholder line', () => {
    const clean = { ...report, verdict: 'clean' as const, findings: [], summary: { block: 0, warn: 0, clean: 0 } }
    const text = renderReport(clean)
    expect(text).toContain('verdict: CLEAN')
    expect(text).toContain('No findings.')
  })
})