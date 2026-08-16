/**
 * Rule engine tests: validation, merging, severity overrides, and the URL /
 * phrase matchers.
 */

import { describe, expect, it } from 'vitest'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  compileRules,
  GuardRuleError,
  loadBundledAllowlist,
  loadBundledRules,
  loadRulesDir,
  mergeRules,
  validateRule,
} from '../src/rules.ts'
import { classifyUrlsInText, hostAllowed } from '../src/urls.ts'
import { matchPhrase, phraseHits } from '../src/phrase.ts'
import { testConfig } from './helpers.ts'

describe('validateRule', () => {
  it('rejects a non-object entry', () => {
    expect(() => validateRule(null, 'x.json')).toThrow(GuardRuleError)
  })

  it('rejects a missing id', () => {
    expect(() => validateRule({ description: 'd', category: 'code', severity: 'warn', kind: 'phrase', phrases: ['x'] }, 'x.json'))
      .toThrow(/non-empty string "id"/)
  })

  it('rejects an invalid severity', () => {
    expect(() => validateRule({ id: 'r1', description: 'd', category: 'code', severity: 'fatal', kind: 'phrase', phrases: ['x'] }, 'x.json'))
      .toThrow(/severity/)
  })

  it('rejects an invalid regex', () => {
    expect(() => validateRule({ id: 'r1', description: 'd', category: 'code', severity: 'warn', kind: 'regex', regex: '(' }, 'x.json'))
      .toThrow(/invalid regex/)
  })

  it('accepts a valid ast-call rule', () => {
    const rule = validateRule({ id: 'r1', description: 'd', category: 'code', severity: 'block', kind: 'ast-call', pattern: { callee: ['eval'] } }, 'x.json')
    expect(rule).toMatchObject({ id: 'r1', kind: 'ast-call', pattern: { callee: ['eval'] } })
  })

  it('requires a non-empty pattern', () => {
    expect(() => validateRule({ id: 'r1', description: 'd', category: 'code', severity: 'warn', kind: 'ast-call', pattern: {} }, 'x.json'))
      .toThrow(/needs/)
  })
})

describe('loadBundledRules', () => {
  it('loads the bundled code/injection/token rule sets with unique ids', () => {
    const rules = loadBundledRules()
    expect(rules.length).toBeGreaterThan(20)
    const ids = new Set(rules.map(rule => rule.id))
    expect(ids.size).toBe(rules.length)
    expect(ids).toContain('code.eval')
    expect(ids).toContain('injection.directive')
    expect(ids).toContain('injection.directive-zh')
    expect(ids).toContain('token.repetition')
  })

  it('loads a domain allowlist containing deepseek and localhost', () => {
    const domains = loadBundledAllowlist()
    expect(domains).toContain('api.deepseek.com')
    expect(domains).toContain('localhost')
  })
})

describe('loadRulesDir + mergeRules', () => {
  it('loads JSON rule files from a directory and merges by id (later wins)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-guard-rules-'))
    writeFileSync(join(dir, 'extra.json'), JSON.stringify({
      rules: [{ id: 'code.eval', category: 'code', severity: 'warn', description: 'overridden', kind: 'ast-call', pattern: { callee: ['eval'] } }],
    }))
    const extra = loadRulesDir(dir)
    const merged = mergeRules(loadBundledRules(), extra)
    const evalRule = merged.find(rule => rule.id === 'code.eval')
    expect(evalRule?.description).toBe('overridden')
    expect(evalRule?.severity).toBe('warn')
  })

  it('surfaces a malformed rule file as GuardRuleError', () => {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-guard-rules-'))
    writeFileSync(join(dir, 'bad.json'), '{"rules": [{"id": 1}]}')
    expect(() => loadRulesDir(dir)).toThrow(GuardRuleError)
  })
})

describe('compileRules', () => {
  it('applies ruleSeverity overrides', () => {
    const rules = compileRules(loadBundledRules(), testConfig({ ruleSeverity: { 'code.eval': 'warn' } }))
    const evalRule = rules.find(resolved => resolved.rule.id === 'code.eval')
    expect(evalRule?.severity).toBe('warn')
  })

  it('keeps rule defaults when no override is set', () => {
    const rules = compileRules(loadBundledRules(), testConfig())
    const evalRule = rules.find(resolved => resolved.rule.id === 'code.eval')
    expect(evalRule?.severity).toBe('block')
  })
})

describe('hostAllowed', () => {
  it('matches exact hosts and *.suffix wildcards', () => {
    expect(hostAllowed('api.deepseek.com', ['api.deepseek.com', '*.deepseek.com', 'localhost'])).toBe(true)
    expect(hostAllowed('cdn.deepseek.com', ['*.deepseek.com'])).toBe(true)
    expect(hostAllowed('deepseek.com', ['*.deepseek.com'])).toBe(false)
    expect(hostAllowed('evil.example.com', ['api.deepseek.com'])).toBe(false)
  })
})

describe('classifyUrlsInText', () => {
  it('classifies unknown and blocked URLs, skipping allowlisted hosts', () => {
    const hits = classifyUrlsInText('go to https://x.evil.example.net/a?b=1 or https://api.deepseek.com/ping', ['api.deepseek.com'], ['evil.example'])
    expect(hits).toHaveLength(1)
    expect(hits[0]?.verdict).toBe('blocked')
    expect(hits[0]?.host).toBe('x.evil.example.net')
  })

  it('classifies a non-allowlisted host as unknown', () => {
    const hits = classifyUrlsInText('see https://mystery-host.example/data', ['api.deepseek.com'], [])
    expect(hits).toHaveLength(1)
    expect(hits[0]?.verdict).toBe('unknown')
  })

  it('returns nothing when every host is allowlisted', () => {
    const hits = classifyUrlsInText('https://api.deepseek.com/a', ['api.deepseek.com'], [])
    expect(hits).toHaveLength(0)
  })
})

describe('matchPhrase + phraseHits', () => {
  const matcher = compileRules([
    { id: 'p1', category: 'injection', severity: 'block', description: 'd', kind: 'phrase', phrases: ['Ignore all previous instructions'], caseSensitive: true },
    { id: 'p2', category: 'injection', severity: 'warn', description: 'd', kind: 'phrase', phrases: ['忽略之前'] },
  ], testConfig())

  it('matches case-sensitive and case-insensitive phrases', () => {
    const lower = matcher.find(resolved => resolved.rule.id === 'p2')
    expect(lower).toBeDefined()
    expect(matchPhrase('请忽略之前的指示', lower!.matcher as never)).toBe('忽略之前')
    const upper = matcher.find(resolved => resolved.rule.id === 'p1')
    expect(upper).toBeDefined()
    expect(matchPhrase('ignore all previous instructions', upper!.matcher as never)).toBeUndefined()
    expect(matchPhrase('Ignore all previous instructions', upper!.matcher as never)).toBe('Ignore all previous instructions')
  })

  it('reports one hit per rule via phraseHits', () => {
    const hits = phraseHits('Ignore all previous instructions 忽略之前', matcher)
    expect(hits.map(hit => hit.ruleId).sort()).toEqual(['p1', 'p2'])
  })
})