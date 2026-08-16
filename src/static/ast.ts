/**
 * Static source analysis for JavaScript/TypeScript plugin code.
 *
 * Safety contract: the scanned text is parsed with the TypeScript compiler
 * API and inspected with read-only AST/scanner passes. The scanner never
 * imports, requires, evaluates, or executes any part of the scanned code —
 * `ts.createSourceFile` is pure parsing.
 * @module dsh-guard/ast
 */

import ts from 'typescript'
import type { ResolvedRule } from '../rules.ts'
import type { ScanFinding } from '../types.ts'
import { classifyUrlsInText } from '../urls.ts'
import { matchPhrase } from '../phrase.ts'

/** A snippet of the source with its 0-based start offset. */
export interface LocatedText {
  readonly text: string
  readonly start: number
}

/** The result of analyzing one source file. */
export interface SourceScan {
  readonly findings: ScanFinding[]
  readonly comments: LocatedText[]
  readonly strings: LocatedText[]
}

/** Pick the parse ScriptKind from a file extension. */
export function scriptKindFor(ext: string): ts.ScriptKind {
  switch (ext) {
    case '.ts': return ts.ScriptKind.TS
    case '.tsx': return ts.ScriptKind.TSX
    case '.js': return ts.ScriptKind.JS
    case '.jsx': return ts.ScriptKind.JSX
    default: return ts.ScriptKind.JS
  }
}

function visit(node: ts.Node, visitor: (node: ts.Node) => void): void {
  visitor(node)
  ts.forEachChild(node, (child) => visit(child, visitor))
}

/** The pattern-relevant shape of a call/new callee expression. */
type CalleeShape =
  | { kind: 'name'; name: string }
  | { kind: 'member'; object: string; property: string }

function calleeShape(node: ts.Expression): CalleeShape | undefined {
  if (ts.isIdentifier(node)) return { kind: 'name', name: node.text }
  if (ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.expression)) {
    return { kind: 'member', object: node.expression.text, property: node.name.text }
  }
  if (ts.isElementAccessExpression(node) && ts.isIdentifier(node.expression) && ts.isStringLiteral(node.argumentExpression)) {
    return { kind: 'member', object: node.expression.text, property: node.argumentExpression.text }
  }
  return undefined
}

/** The string specifier of `require('...')` when `node` is such a call. */
function requireSpecifier(node: ts.Node): string | undefined {
  if (!ts.isCallExpression(node) || !ts.isIdentifier(node.expression) || node.expression.text !== 'require') return undefined
  if (node.arguments.length === 0) return undefined
  const specifier = node.arguments[0]
  if (specifier === undefined) return undefined
  if (ts.isStringLiteral(specifier) || ts.isNoSubstitutionTemplateLiteral(specifier)) return specifier.text
  return undefined
}

/** Trim a node text to a bounded excerpt. */
function excerptOf(text: string): string {
  const single = text.replace(/\s+/g, ' ')
  return single.length > 120 ? `${single.slice(0, 117)}...` : single
}

/** Produce a finding at the node's position. */
function findingAt(
  file: string,
  sf: ts.SourceFile,
  node: ts.Node,
  resolved: ResolvedRule,
  message: string,
): ScanFinding {
  const pos = sf.getLineAndCharacterOfPosition(node.getStart(sf))
  return {
    ruleId: resolved.rule.id,
    severity: resolved.severity,
    category: resolved.rule.category,
    file,
    line: pos.line + 1,
    column: pos.character + 1,
    excerpt: excerptOf(node.getText(sf)),
    message,
  }
}

/**
 * Analyze one source file: AST rules plus a trivia pass that collects
 * comments and string literals for the content-level matchers.
 *
 * @param phraseRules phrase rules to run against strings/comments.
 * @param urlRules url rules to run against strings/comments.
 */
export function analyzeSource(
  file: string,
  ext: string,
  text: string,
  resolvedRules: readonly ResolvedRule[],
  phraseRules: readonly ResolvedRule[],
  urlRules: readonly ResolvedRule[],
  allowlist: readonly string[],
  blocklist: readonly string[],
): SourceScan {
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, /* setParentNodes */ true, scriptKindFor(ext))
  const findings: ScanFinding[] = []

  for (const resolved of resolvedRules) {
    const matcher = resolved.matcher
    if (matcher.kind !== 'ast-call' && matcher.kind !== 'ast-member' && matcher.kind !== 'ast-computed' && matcher.kind !== 'ast-import') continue
    visit(sf, (node) => {
      if (matcher.kind === 'ast-call' && (ts.isCallExpression(node) || ts.isNewExpression(node))) {
        const required = requireSpecifier(node)
        if (required !== undefined && matcher.module.has(required)) {
          findings.push(findingAt(file, sf, node, resolved, `${resolved.rule.description} (require("${required}"))`))
          return
        }
        const shape = calleeShape(node.expression)
        if (shape === undefined) return
        const matched =
          (shape.kind === 'name' && matcher.callee.has(shape.name))
          || (shape.kind === 'member' && matcher.object.has(shape.object) && matcher.property.has(shape.property))
        if (matched) {
          findings.push(findingAt(file, sf, node, resolved, `${resolved.rule.description} (${excerptOf(node.getText(sf))})`))
        }
      } else if (matcher.kind === 'ast-member' && ts.isPropertyAccessExpression(node)) {
        if (ts.isIdentifier(node.expression) && matcher.object.has(node.expression.text) && matcher.property.has(node.name.text)) {
          findings.push(findingAt(file, sf, node, resolved, `${resolved.rule.description} (${excerptOf(node.getText(sf))})`))
        }
      } else if (matcher.kind === 'ast-computed' && ts.isElementAccessExpression(node)) {
        if (ts.isIdentifier(node.expression) && matcher.object.has(node.expression.text)) {
          findings.push(findingAt(file, sf, node, resolved, `${resolved.rule.description} (${excerptOf(node.getText(sf))})`))
        }
      } else if (matcher.kind === 'ast-import') {
        const specifier =
          (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier) ? node.moduleSpecifier.text : undefined)
          ?? (ts.isExportDeclaration(node) && node.moduleSpecifier !== undefined && ts.isStringLiteral(node.moduleSpecifier) ? node.moduleSpecifier.text : undefined)
        if (specifier !== undefined && matcher.specifier.has(specifier)) {
          findings.push(findingAt(file, sf, node, resolved, `${resolved.rule.description} (import "${specifier}")`))
        }
      }
    })
  }

  // Trivia pass: comments and string literals with positions.
  const comments: LocatedText[] = []
  const strings: LocatedText[] = []
  const languageVariant = ext === '.tsx' || ext === '.jsx' ? ts.LanguageVariant.JSX : ts.LanguageVariant.Standard
  const scanner = ts.createScanner(ts.ScriptTarget.Latest, /* skipTrivia */ false, languageVariant, text)
  let token = scanner.scan()
  while (token !== ts.SyntaxKind.EndOfFileToken) {
    if (token === ts.SyntaxKind.SingleLineCommentTrivia || token === ts.SyntaxKind.MultiLineCommentTrivia) {
      comments.push({ text: text.slice(scanner.getTokenPos(), scanner.getTextPos()), start: scanner.getTokenPos() })
    } else if (
      token === ts.SyntaxKind.StringLiteral
      || token === ts.SyntaxKind.NoSubstitutionTemplateLiteral
      || token === ts.SyntaxKind.TemplateHead
      || token === ts.SyntaxKind.TemplateMiddle
      || token === ts.SyntaxKind.TemplateTail
    ) {
      strings.push({ text: scanner.getTokenValue(), start: scanner.getTokenPos() })
    }
    token = scanner.scan()
  }

  // Phrase rules against string literals and comments.
  for (const resolved of phraseRules) {
    const matcher = resolved.matcher
    if (matcher.kind !== 'phrase') continue
    for (const located of strings) {
      const hit = matchPhrase(located.text, matcher)
      if (hit === undefined) continue
      const pos = sf.getLineAndCharacterOfPosition(located.start)
      findings.push({
        ruleId: resolved.rule.id,
        severity: resolved.severity,
        category: resolved.rule.category,
        file,
        line: pos.line + 1,
        column: pos.character + 1,
        excerpt: excerptOf(located.text),
        message: `${resolved.rule.description} (found "${hit}" in a string literal)`,
      })
    }
    for (const located of comments) {
      const hit = matchPhrase(located.text, matcher)
      if (hit === undefined) continue
      const pos = sf.getLineAndCharacterOfPosition(located.start)
      findings.push({
        ruleId: resolved.rule.id,
        severity: resolved.severity,
        category: resolved.rule.category,
        file,
        line: pos.line + 1,
        column: pos.character + 1,
        excerpt: excerptOf(located.text),
        message: `${resolved.rule.description} (found "${hit}" in a comment)`,
      })
    }
  }

  // Regex rules against string literals (scope "string").
  for (const resolved of resolvedRules) {
    const matcher = resolved.matcher
    if (matcher.kind !== 'regex' || matcher.scope !== 'string') continue
    if (matcher.files.size > 0 && !matcher.files.has(basenameOf(file))) continue
    for (const located of strings) {
      matcher.regex.lastIndex = 0
      for (let match = matcher.regex.exec(located.text); match !== null; match = matcher.regex.exec(located.text)) {
        const pos = sf.getLineAndCharacterOfPosition(located.start + (match.index ?? 0))
        findings.push({
          ruleId: resolved.rule.id,
          severity: resolved.severity,
          category: resolved.rule.category,
          file,
          line: pos.line + 1,
          column: pos.character + 1,
          excerpt: excerptOf(match[0] ?? ''),
          message: `${resolved.rule.description} (matched "${excerptOf(match[0] ?? '')}" in a string literal)`,
        })
      }
    }
  }

  // URL rules against string literals and comments (positioned per entry).
  for (const resolved of urlRules) {
    const matcher = resolved.matcher
    if (matcher.kind !== 'url') continue
    for (const located of [...strings, ...comments]) {
      for (const hit of classifyUrlsInText(located.text, allowlist, blocklist)) {
        if (matcher.match === 'blocked-pattern' && hit.verdict !== 'blocked') continue
        if (matcher.match === 'unknown-host' && hit.verdict !== 'unknown') continue
        const pos = sf.getLineAndCharacterOfPosition(located.start + hit.offset)
        findings.push({
          ruleId: resolved.rule.id,
          severity: resolved.severity,
          category: resolved.rule.category,
          file,
          line: pos.line + 1,
          column: pos.character + 1,
          excerpt: excerptOf(hit.url),
          message: `${resolved.rule.description} (${hit.url} → host ${hit.host === '' ? '(unparsable)' : hit.host})`,
        })
      }
    }
  }

  return { findings, comments, strings }
}

/** The base file name of a scanned path. */
function basenameOf(path: string): string {
  const index = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'))
  return index >= 0 ? path.slice(index + 1) : path
}