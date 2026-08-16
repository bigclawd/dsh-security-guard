/**
 * The static scanner: walks a plugin directory (or single file), runs the AST
 * and content passes per file, aggregates findings, and produces the verdict.
 *
 * Safety contract: only file reading, size probing, and pure parsing/AST
 * passes happen here. Scanned plugin code is never imported or executed.
 * @module dsh-security-guard/scanner
 */

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { extname, join, relative, resolve } from 'node:path'
import type { GuardConfig, ScanFinding, ScanReport, ScanVerdict } from '../types.ts'
import type { ResolvedRule } from '../rules.ts'
import { analyzeSource } from './ast.ts'
import { analyzeContent } from './content.ts'

/** Extension sets (fixed; document in the README). */
const CODE_EXTS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts'])
const TEXT_EXTS = new Set(['.md', '.markdown', '.mdx', '.txt', '.text'])
const CONTENT_EXTS = new Set([...CODE_EXTS, ...TEXT_EXTS, '.json', '.yaml', '.yml', '.toml', '.ini', '.env', '.cfg', '.conf'])

/** Whether a file extension receives the source (AST) pass. */
export function isCodeExt(ext: string): boolean {
  return CODE_EXTS.has(ext)
}

/** Whether an extension is treated as documentation text. */
export function isTextExt(ext: string): boolean {
  return TEXT_EXTS.has(ext)
}

/** Whether a file receives the content (token-waste / hidden-injection) pass. */
export function isContentExt(ext: string): boolean {
  return CONTENT_EXTS.has(ext)
}

/** Decide whether a relative path should be skipped. */
export function isSkipped(rel: string, skipSegments: readonly string[]): boolean {
  const segments = rel.split(/[\\/]/)
  return segments.some(segment => skipSegments.includes(segment))
}

/** Walk a directory (sorted, deterministic) yielding relative file paths. */
export function listFiles(root: string, skipSegments: readonly string[]): string[] {
  const files: string[] = []
  const walk = (dir: string): void => {
    let entries: import('node:fs').Dirent[]
    try {
      entries = readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    for (const entry of entries) {
      const full = join(dir, entry.name)
      const rel = relative(root, full)
      if (isSkipped(rel, skipSegments)) continue
      if (entry.isDirectory()) {
        walk(full)
      } else if (entry.isFile()) {
        files.push(rel)
      }
    }
  }
  walk(root)
  return files
}

/** The concrete inputs for scanning one file. */
export interface ScanOptions {
  readonly config: GuardConfig
  readonly rules: readonly ResolvedRule[]
  readonly phraseRules: readonly ResolvedRule[]
  readonly urlRules: readonly ResolvedRule[]
  readonly allowlist: readonly string[]
}

/** Scan one file; returns findings. */
export function scanFile(relPath: string, root: string, options: ScanOptions): ScanFinding[] {
  const abs = resolve(root, relPath)
  const ext = extname(relPath).toLowerCase()
  const findings: ScanFinding[] = []
  let stat: import('node:fs').Stats
  try {
    stat = statSync(abs)
  } catch {
    return findings
  }
  if (!stat.isFile()) return findings
  if (stat.size > options.config.maxFileBytes) {
    // Too large to read; only the oversize check can run (from the size probe).
    for (const resolved of options.rules) {
      if (resolved.matcher.kind !== 'file' || resolved.matcher.check !== 'oversize') continue
      const maxBytes = typeof resolved.matcher.params.maxBytes === 'number' ? resolved.matcher.params.maxBytes : 10 * 1024 * 1024
      if (stat.size > maxBytes) {
        findings.push({
          ruleId: resolved.rule.id,
          severity: resolved.severity,
          category: resolved.rule.category,
          file: relPath,
          excerpt: `${stat.size} bytes`,
          message: `${resolved.rule.description} (${stat.size} bytes > ${maxBytes})`,
        })
      }
    }
    return findings
  }
  let text: string
  try {
    text = readFileSync(abs, 'utf8')
  } catch {
    return findings
  }

  if (isCodeExt(ext)) {
    const source = analyzeSource(relPath, ext, text, options.rules, options.phraseRules, options.urlRules, options.allowlist, options.config.blocklistUrlPatterns)
    findings.push(...source.findings)
    findings.push(...analyzeContent(relPath, text, options.rules, options.phraseRules, options.urlRules, options.allowlist, options.config.blocklistUrlPatterns, false, source.comments))
  } else if (isContentExt(ext)) {
    findings.push(...analyzeContent(relPath, text, options.rules, options.phraseRules, options.urlRules, options.allowlist, options.config.blocklistUrlPatterns, isTextExt(ext), []))
  }
  return findings
}

/** Scan a whole plugin directory or a single file. */
export function scanTarget(target: string, options: ScanOptions): ScanReport {
  const abs = resolve(target)
  const stat = statSync(abs)
  const isDir = stat.isDirectory()
  const root = isDir ? abs : resolve(abs, '..')
  const findings: ScanFinding[] = []
  let filesScanned = 0
  let filesSkipped = 0
  let bytesRead = 0

  const relPaths = isDir
    ? listFiles(root, options.config.skipSegments)
    : [relative(root, abs)]

  for (const relPath of relPaths) {
    if (filesScanned >= options.config.maxFiles) {
      filesSkipped += 1
      continue
    }
    const absPath = resolve(root, relPath)
    let size = 0
    try {
      size = statSync(absPath).size
    } catch {
      continue
    }
    findings.push(...scanFile(relPath, root, options))
    filesScanned += 1
    bytesRead += Math.min(size, options.config.maxFileBytes)
  }

  return buildReport(target, root, findings, filesScanned, filesSkipped, bytesRead, options.rules)
}

/** Build the final report: dedupe, summary, verdict. */
export function buildReport(
  target: string,
  root: string,
  rawFindings: ScanFinding[],
  filesScanned: number,
  filesSkipped: number,
  bytesRead: number,
  rules: readonly ResolvedRule[],
): ScanReport {
  // Dedupe: same rule + file + line merges into one finding.
  const seen = new Set<string>()
  const findings: ScanFinding[] = []
  for (const finding of rawFindings) {
    const key = `${finding.ruleId}|${finding.file}|${finding.line ?? ''}`
    if (seen.has(key)) continue
    seen.add(key)
    findings.push(finding)
  }

  let block = 0
  let warn = 0
  for (const finding of findings) {
    if (finding.severity === 'block') block += 1
    else warn += 1
  }
  const verdict: ScanVerdict = block > 0 ? 'block' : warn > 0 ? 'warn' : 'clean'
  return {
    target,
    root,
    verdict,
    findings,
    filesScanned,
    filesSkipped,
    bytesRead,
    scannedAt: new Date().toISOString(),
    ruleIds: rules.map(resolved => resolved.rule.id),
    summary: { block, warn, clean: 0 },
  }
}