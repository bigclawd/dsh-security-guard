/**
 * Rule loading and compilation. Rules are plain JSON files so the community
 * can contribute new detectors without touching TypeScript: bundled rules
 * live in `src/rules/*.json`, and an operator can point `guard.rulesDir` at a
 * directory of extra rule files (each `*.json` with a `{ "rules": [...] }`
 * root, merged over the bundled set by `id`).
 * @module dsh-guard/rules
 */

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'
import type { GuardConfig, RuleDefinition, ScanCategory, ScanSeverity } from './types.ts'

/** Thrown when a rule file is malformed; carries the offending file. */
export class GuardRuleError extends Error {
  constructor(
    message: string,
    readonly file: string,
  ) {
    super(`${file}: ${message}`)
    this.name = 'GuardRuleError'
  }
}

/** Candidate JSON file names bundled with the package, in load order. */
const BUNDLED_FILES = ['code.json', 'injection.json', 'token.json', 'allowlist.json'] as const

/**
 * Resolve one bundled file. Works from the source tree (`src/rules.ts`) and
 * from the built artifact (`lib/types/rules.js` → `lib/rules/`), which the
 * package `prepack` step populates.
 */
function bundledPath(name: string): string {
  const source = fileURLToPath(new URL(`./rules/${name}`, import.meta.url))
  try {
    statSync(source)
    return source
  } catch {
    return fileURLToPath(new URL(`../rules/${name}`, import.meta.url))
  }
}

const CATEGORIES: ScanCategory[] = ['code', 'injection', 'token']
const SEVERITIES: ScanSeverity[] = ['block', 'warn']
const KINDS = ['ast-call', 'ast-member', 'ast-import', 'regex', 'phrase', 'url', 'file'] as const
const FILE_CHECKS = ['oversize', 'repetition', 'base64-ratio', 'zero-width', 'base64-hidden', 'comment-padding'] as const

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every(item => typeof item === 'string')
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function expectStringArray(
  rule: Record<string, unknown>,
  id: string,
  where: string,
  field: string,
): string[] {
  const value = rule[field]
  if (value !== undefined && !isStringArray(value)) {
    throw new GuardRuleError(`rule "${id}" ${field} must be a string array`, where)
  }
  return value as string[] | undefined ?? []
}

/** Shape-check one rule object from a rule file. */
export function validateRule(entry: unknown, where: string): RuleDefinition {
  if (!isRecord(entry)) {
    throw new GuardRuleError(`rule must be an object`, where)
  }
  const { id, category, severity, kind } = entry
  if (typeof id !== 'string' || id.length === 0) {
    throw new GuardRuleError(`rule requires a non-empty string "id"`, where)
  }
  if (typeof entry.description !== 'string' || entry.description.length === 0) {
    throw new GuardRuleError(`rule "${id}" requires a non-empty "description"`, where)
  }
  if (typeof category !== 'string' || !CATEGORIES.includes(category as ScanCategory)) {
    throw new GuardRuleError(`rule "${id}" requires "category" in ${CATEGORIES.join(', ')}`, where)
  }
  if (typeof severity !== 'string' || !SEVERITIES.includes(severity as ScanSeverity)) {
    throw new GuardRuleError(`rule "${id}" requires "severity" in ${SEVERITIES.join(', ')}`, where)
  }
  if (typeof kind !== 'string' || !KINDS.includes(kind as (typeof KINDS)[number])) {
    throw new GuardRuleError(`rule "${id}" requires "kind" in ${KINDS.join(', ')}`, where)
  }
  const base = {
    id,
    category: category as ScanCategory,
    severity: severity as ScanSeverity,
    description: entry.description,
  }
  switch (kind) {
    case 'ast-call': {
      if (!isRecord(entry.pattern)) {
        throw new GuardRuleError(`rule "${id}" requires an ast-call "pattern"`, where)
      }
      const pattern = {
        callee: expectStringArray(entry.pattern, id, where, 'callee'),
        object: expectStringArray(entry.pattern, id, where, 'object'),
        property: expectStringArray(entry.pattern, id, where, 'property'),
        module: expectStringArray(entry.pattern, id, where, 'module'),
      }
      if (pattern.callee.length === 0 && pattern.object.length === 0 && pattern.property.length === 0 && pattern.module.length === 0) {
        throw new GuardRuleError(`rule "${id}" ast-call pattern needs callee|object|property|module`, where)
      }
      return { ...base, kind: 'ast-call', pattern }
    }
    case 'ast-member': {
      if (!isRecord(entry.pattern)) {
        throw new GuardRuleError(`rule "${id}" requires an ast-member "pattern"`, where)
      }
      const object = expectStringArray(entry.pattern, id, where, 'object')
      const property = expectStringArray(entry.pattern, id, where, 'property')
      if (object.length === 0 || property.length === 0) {
        throw new GuardRuleError(`rule "${id}" ast-member pattern needs non-empty object and property`, where)
      }
      return { ...base, kind: 'ast-member', pattern: { object, property } }
    }
    case 'ast-import': {
      if (!isRecord(entry.pattern)) {
        throw new GuardRuleError(`rule "${id}" requires an ast-import "pattern"`, where)
      }
      const specifier = expectStringArray(entry.pattern, id, where, 'specifier')
      if (specifier.length === 0) {
        throw new GuardRuleError(`rule "${id}" ast-import pattern needs a non-empty specifier`, where)
      }
      return { ...base, kind: 'ast-import', pattern: { specifier } }
    }
    case 'regex': {
      if (typeof entry.regex !== 'string' || entry.regex.length === 0) {
        throw new GuardRuleError(`rule "${id}" requires a non-empty "regex"`, where)
      }
      const flags = entry.flags
      if (flags !== undefined && (typeof flags !== 'string' || !/^[a-z]*$/.test(flags))) {
        throw new GuardRuleError(`rule "${id}" flags must be a lowercase letters string`, where)
      }
      const scope = entry.scope
      if (scope !== undefined && scope !== 'all' && scope !== 'string' && scope !== 'comment') {
        throw new GuardRuleError(`rule "${id}" scope must be all|string|comment`, where)
      }
      const files = entry.files
      if (files !== undefined && !isStringArray(files)) {
        throw new GuardRuleError(`rule "${id}" files must be a string array`, where)
      }
      try {
        // Compile now so a broken rule file fails loudly at load time. The
        // expression is operator-authored configuration, never scanned code.
        new RegExp(entry.regex, flags as string | undefined)
      } catch (error: unknown) {
        throw new GuardRuleError(`rule "${id}" has an invalid regex: ${error instanceof Error ? error.message : String(error)}`, where)
      }
      return {
        ...base,
        kind: 'regex',
        regex: entry.regex,
        ...flags !== undefined ? { flags: flags as string } : {},
        ...scope !== undefined ? { scope: scope as 'all' | 'string' | 'comment' } : {},
        ...files !== undefined ? { files: files as string[] } : {},
      }
    }
    case 'phrase': {
      const phrases = entry.phrases
      if (!isStringArray(phrases) || phrases.length === 0) {
        throw new GuardRuleError(`rule "${id}" requires a non-empty "phrases" string array`, where)
      }
      const caseSensitive = entry.caseSensitive
      if (caseSensitive !== undefined && typeof caseSensitive !== 'boolean') {
        throw new GuardRuleError(`rule "${id}" caseSensitive must be a boolean`, where)
      }
      return {
        ...base,
        kind: 'phrase',
        phrases,
        ...caseSensitive !== undefined ? { caseSensitive: caseSensitive as boolean } : {},
      }
    }
    case 'url': {
      const match = entry.match
      if (match !== 'unknown-host' && match !== 'blocked-pattern') {
        throw new GuardRuleError(`rule "${id}" url match must be unknown-host|blocked-pattern`, where)
      }
      return { ...base, kind: 'url', match }
    }
    case 'file': {
      const check = entry.check
      if (typeof check !== 'string' || !FILE_CHECKS.includes(check as (typeof FILE_CHECKS)[number])) {
        throw new GuardRuleError(`rule "${id}" requires "check" in ${FILE_CHECKS.join(', ')}`, where)
      }
      const params = entry.params
      if (params !== undefined && !isRecord(params)) {
        throw new GuardRuleError(`rule "${id}" params must be an object`, where)
      }
      return {
        ...base,
        kind: 'file',
        check: check as 'oversize' | 'repetition' | 'base64-ratio' | 'zero-width' | 'base64-hidden' | 'comment-padding',
        ...params !== undefined ? { params } : {},
      }
    }
    default:
      throw new GuardRuleError(`rule "${id}" has an unknown kind`, where)
  }
}

/** Parse one JSON rule file into rule definitions. */
function parseRuleFile(path: string): RuleDefinition[] {
  let raw: string
  try {
    raw = readFileSync(path, 'utf8')
  } catch {
    throw new GuardRuleError(`cannot read rule file`, path)
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (error: unknown) {
    throw new GuardRuleError(`invalid JSON: ${error instanceof Error ? error.message : String(error)}`, path)
  }
  if (!isRecord(parsed) || !Array.isArray(parsed.rules)) {
    throw new GuardRuleError(`expected a JSON object with a "rules" array`, path)
  }
  return parsed.rules.map((entry, index) => validateRule(entry, `${path}#${index}`))
}

/** Load bundled rule definitions (code/injection/token). */
export function loadBundledRules(): RuleDefinition[] {
  const definitions: RuleDefinition[] = []
  for (const name of BUNDLED_FILES) {
    if (name === 'allowlist.json') continue
    definitions.push(...parseRuleFile(bundledPath(name)))
  }
  return definitions
}

/** Load the bundled domain allowlist. */
export function loadBundledAllowlist(): string[] {
  const path = bundledPath('allowlist.json')
  const parsed = JSON.parse(readFileSync(path, 'utf8')) as { domains?: unknown }
  if (!isStringArray(parsed.domains)) {
    throw new GuardRuleError(`"domains" must be a string array`, path)
  }
  return parsed.domains
}

/** Load every `*.json` rule file from a directory (sorted for determinism). */
export function loadRulesDir(dir: string): RuleDefinition[] {
  const definitions: RuleDefinition[] = []
  for (const entry of readdirSync(dir)) {
    if (!entry.endsWith('.json')) continue
    definitions.push(...parseRuleFile(join(dir, entry)))
  }
  return definitions
}

/** Merge rule lists by id: later definitions replace earlier ones. */
export function mergeRules(...sets: RuleDefinition[][]): RuleDefinition[] {
  const byId = new Map<string, RuleDefinition>()
  for (const set of sets) {
    for (const rule of set) byId.set(rule.id, rule)
  }
  return [...byId.values()]
}

/** A rule after severity overrides from `guard.ruleSeverity` are applied. */
export interface ResolvedRule {
  readonly rule: RuleDefinition
  readonly severity: ScanSeverity
  /** The compiled matcher artifact for the rule's kind. */
  readonly matcher: RuleMatcher
}

/** Compiled matcher artifacts, prepared once per scan. */
export type RuleMatcher =
  | {
    kind: 'ast-call'
    callee: ReadonlySet<string>
    object: ReadonlySet<string>
    property: ReadonlySet<string>
    module: ReadonlySet<string>
  }
  | { kind: 'ast-member'; object: ReadonlySet<string>; property: ReadonlySet<string> }
  | { kind: 'ast-import'; specifier: ReadonlySet<string> }
  | { kind: 'regex'; regex: RegExp; scope: 'all' | 'string' | 'comment'; files: ReadonlySet<string> }
  | { kind: 'phrase'; phrases: string[]; lower: string[]; caseSensitive: boolean }
  | { kind: 'url'; match: 'unknown-host' | 'blocked-pattern' }
  | {
    kind: 'file'
    check: 'oversize' | 'repetition' | 'base64-ratio' | 'zero-width' | 'base64-hidden' | 'comment-padding'
    params: Record<string, unknown>
  }

/** Compile the full rule set with config overrides applied. */
export function compileRules(
  definitions: RuleDefinition[],
  config: Pick<GuardConfig, 'ruleSeverity'>,
): ResolvedRule[] {
  return definitions.map((rule) => {
    const severity = config.ruleSeverity[rule.id] ?? rule.severity
    let matcher: RuleMatcher
    switch (rule.kind) {
      case 'ast-call':
        matcher = {
          kind: 'ast-call',
          callee: new Set(rule.pattern.callee ?? []),
          object: new Set(rule.pattern.object ?? []),
          property: new Set(rule.pattern.property ?? []),
          module: new Set(rule.pattern.module ?? []),
        }
        break
      case 'ast-member':
        matcher = { kind: 'ast-member', object: new Set(rule.pattern.object), property: new Set(rule.pattern.property) }
        break
      case 'ast-import':
        matcher = { kind: 'ast-import', specifier: new Set(rule.pattern.specifier) }
        break
      case 'regex': {
        const flags = (rule.flags ?? '').includes('g') ? rule.flags ?? '' : `${rule.flags ?? ''}g`
        matcher = {
          kind: 'regex',
          regex: new RegExp(rule.regex, flags),
          scope: rule.scope ?? 'all',
          files: new Set(rule.files ?? []),
        }
        break
      }
      case 'phrase':
        matcher = {
          kind: 'phrase',
          phrases: rule.phrases,
          lower: rule.caseSensitive ? [] : rule.phrases.map(phrase => phrase.toLowerCase()),
          caseSensitive: rule.caseSensitive ?? false,
        }
        break
      case 'url':
        matcher = { kind: 'url', match: rule.match }
        break
      case 'file':
        matcher = { kind: 'file', check: rule.check, params: (rule.params ?? {}) as Record<string, unknown> }
        break
    }
    return { rule, severity, matcher }
  })
}