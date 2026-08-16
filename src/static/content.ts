/**
 * Content-level analysis: documentation/skill text, markdown, and file-level
 * token-waste and hidden-injection checks. All checks are read-only scans of
 * the decoded text; nothing is executed.
 * @module dsh-guard/content
 */

import type { ResolvedRule } from '../rules.ts'
import type { ScanFinding } from '../types.ts'
import { classifyUrlsInText } from '../urls.ts'
import { matchPhrase } from '../phrase.ts'

/** A markdown image `![alt](target)` occurrence. */
export interface ImageAlt {
  readonly alt: string
  readonly start: number
}

/** The markdown image extraction regex: `![alt](anything-not-)`. */
const IMAGE_ALT_RE = /!\[([^\]]*)\]\([^)]*\)/g

/** Extract markdown image alt attributes with offsets. */
export function extractImageAlts(text: string): ImageAlt[] {
  const results: ImageAlt[] = []
  IMAGE_ALT_RE.lastIndex = 0
  for (let match = IMAGE_ALT_RE.exec(text); match !== null; match = IMAGE_ALT_RE.exec(text)) {
    const alt = (match[1] ?? '').trim()
    if (alt.length === 0) continue
    results.push({ alt, start: match.index })
  }
  return results
}

/** Find the 1-based line of a 0-based offset. */
export function lineAt(text: string, offset: number): number {
  let line = 1
  const end = Math.min(offset, text.length)
  for (let index = 0; index < end; index += 1) {
    if (text.charCodeAt(index) === 10) line += 1
  }
  return line
}

/** Characters considered "filler" for the comment-padding check. */
const FILLER_RE = /[\s\-_*#=/.,~'"`!]/

/** A long run of a repeated character or word. */
export interface RepetitionRun {
  readonly kind: 'char' | 'word'
  readonly value: string
  readonly length: number
  readonly offset: number
}

/** Scan for runs of one repeated character or one repeated word (linear, O(n)). */
export function findRepetition(text: string, maxCharRun: number, maxWordRun: number): RepetitionRun[] {
  const runs: RepetitionRun[] = []

  // Character runs.
  let runStart = 0
  for (let index = 1; index <= text.length; index += 1) {
    const current = text[index]
    const previous = text[index - 1]
    if (index === text.length || current !== previous) {
      const length = index - runStart
      if (previous !== undefined && length >= maxCharRun) {
        runs.push({ kind: 'char', value: previous, length, offset: runStart })
      }
      runStart = index
    }
  }

  // Word runs (consecutive identical whitespace-delimited words).
  const words = text.split(/\s+/)
  let wordStart = 0
  for (let index = 1; index <= words.length; index += 1) {
    const current = words[index]
    const previous = words[index - 1]
    if (index === words.length || current !== previous) {
      const length = index - wordStart
      if (previous !== undefined && previous !== '' && length >= maxWordRun) {
        // Approximate offset: search the first occurrence of the run.
        const probe = `${previous} `.repeat(Math.min(length, 8))
        const offset = text.indexOf(probe)
        runs.push({ kind: 'word', value: previous, length, offset: offset >= 0 ? offset : 0 })
      }
      wordStart = index
    }
  }

  return runs
}

/** Zero-width and bidi control characters (BOM at offset 0 is allowed). */
const ZERO_WIDTH_RE = /[\u200B-\u200F\u2060-\u2064\u202A-\u202E\uFEFF]/g

/** Find zero-width / bidi control characters; BOM at offset 0 is ignored. */
export function findZeroWidth(text: string): { char: string; offset: number }[] {
  const hits: { char: string; offset: number }[] = []
  ZERO_WIDTH_RE.lastIndex = 0
  for (let match = ZERO_WIDTH_RE.exec(text); match !== null; match = ZERO_WIDTH_RE.exec(text)) {
    const offset = match.index
    if (offset === 0 && match[0] === '\uFEFF') continue
    hits.push({ char: match[0] ?? '', offset })
    if (hits.length >= 20) break
  }
  return hits
}

/** Base64 candidate blobs: ≥ `minLength` chars of the base64 alphabet. */
const BASE64_RE = /[A-Za-z0-9+/]{20,}={0,2}/g

/** Examine base64 blobs; returns blobs whose decoded UTF-8 text is printable and long. */
export function findBase64Blobs(text: string, minLength: number): { blob: string; offset: number; decoded: string }[] {
  const blobs: { blob: string; offset: number; decoded: string }[] = []
  BASE64_RE.lastIndex = 0
  let examined = 0
  for (let match = BASE64_RE.exec(text); match !== null && examined < 200; match = BASE64_RE.exec(text)) {
    const blob = match[0] ?? ''
    if (blob.length < minLength || blob.length % 4 === 1) continue
    examined += 1
    let decoded: string
    try {
      decoded = Buffer.from(blob, 'base64').toString('utf8')
    } catch {
      continue
    }
    if (decoded.length < 20) continue
    // Skip binary-looking decoded content (control chars other than \n\t\r).
    let control = 0
    for (let index = 0; index < decoded.length; index += 1) {
      const code = decoded.charCodeAt(index)
      if (code < 32 && code !== 9 && code !== 10 && code !== 13) control += 1
    }
    if (control / decoded.length > 0.1) continue
    blobs.push({ blob, offset: match.index, decoded })
  }
  return blobs
}

/** The base64 ratio of a text: base64-alphabet chars / non-whitespace chars. */
export function base64Ratio(text: string): number {
  let base64Chars = 0
  let nonWhitespace = 0
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index)
    const isAlnum = (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122)
    const isB64 = isAlnum || code === 43 /* + */ || code === 47 /* / */ || code === 61 /* = */
    if (code !== 9 && code !== 10 && code !== 13 && code !== 32) {
      nonWhitespace += 1
      if (isB64) base64Chars += 1
    }
  }
  return nonWhitespace === 0 ? 0 : base64Chars / nonWhitespace
}

/**
 * Run every check against one file's text. `comments` comes from the source
 * pass when the file is code; text files pass the whole content.
 */
export function analyzeContent(
  file: string,
  text: string,
  resolvedRules: readonly ResolvedRule[],
  phraseRules: readonly ResolvedRule[],
  urlRules: readonly ResolvedRule[],
  allowlist: readonly string[],
  blocklist: readonly string[],
  isText: boolean,
  comments: readonly { text: string; start: number }[],
): ScanFinding[] {
  const findings: ScanFinding[] = []

  for (const resolved of resolvedRules) {
    const matcher = resolved.matcher
    if (matcher.kind !== 'file') continue
    const params = matcher.params
    switch (matcher.check) {
      case 'oversize': {
        const maxBytes = numberParam(params.maxBytes, 10 * 1024 * 1024)
        if (text.length > maxBytes) {
          findings.push({
            ruleId: resolved.rule.id,
            severity: resolved.severity,
            category: resolved.rule.category,
            file,
            excerpt: `${text.length} bytes`,
            message: `${resolved.rule.description} (${text.length} bytes > ${maxBytes})`,
          })
        }
        break
      }
      case 'repetition': {
        const maxCharRun = numberParam(params.maxCharRun, 10000)
        const maxWordRun = numberParam(params.maxWordRun, 10000)
        for (const run of findRepetition(text, maxCharRun, maxWordRun)) {
          const value = run.value.length > 24 ? `${run.value.slice(0, 21)}...` : run.value
          findings.push({
            ruleId: resolved.rule.id,
            severity: resolved.severity,
            category: resolved.rule.category,
            file,
            line: lineAt(text, run.offset),
            excerpt: `"${value}" × ${run.length}`,
            message: `${resolved.rule.description} (${run.kind} "${value}" repeated ${run.length} times)`,
          })
          if (findings.filter(finding => finding.ruleId === resolved.rule.id).length >= 3) break
        }
        break
      }
      case 'base64-ratio': {
        const minBytes = numberParam(params.base64RatioMinBytes, 256 * 1024)
        const threshold = numberParam(params.base64RatioThreshold, 0.7)
        if (text.length >= minBytes) {
          const ratio = base64Ratio(text)
          if (ratio >= threshold) {
            findings.push({
              ruleId: resolved.rule.id,
              severity: resolved.severity,
              category: resolved.rule.category,
              file,
              excerpt: `base64 ratio ${(ratio * 100).toFixed(1)}%`,
              message: `${resolved.rule.description} (base64 ratio ${(ratio * 100).toFixed(1)}% ≥ ${threshold * 100}%)`,
            })
          }
        }
        break
      }
      case 'zero-width': {
        for (const hit of findZeroWidth(text)) {
          findings.push({
            ruleId: resolved.rule.id,
            severity: resolved.severity,
            category: resolved.rule.category,
            file,
            line: lineAt(text, hit.offset),
            excerpt: `U+${hit.char.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}`,
            message: `${resolved.rule.description} (zero-width character U+${hit.char.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')} at offset ${hit.offset})`,
          })
          if (findings.filter(finding => finding.ruleId === resolved.rule.id).length >= 3) break
        }
        break
      }
      case 'base64-hidden': {
        const minLength = numberParam(params.minBase64Length, 40)
        const blobs = findBase64Blobs(text, minLength)
        for (const blob of blobs) {
          for (const phraseRule of phraseRules) {
            const phraseMatcher = phraseRule.matcher
            if (phraseMatcher.kind !== 'phrase') continue
            const hit = matchPhrase(blob.decoded, phraseMatcher)
            if (hit === undefined) continue
            findings.push({
              ruleId: resolved.rule.id,
              severity: resolved.severity,
              category: resolved.rule.category,
              file,
              line: lineAt(text, blob.offset),
              excerpt: excerptOf(blob.blob),
              message: `${resolved.rule.description} (base64 blob decodes to text containing "${hit}")`,
            })
            break
          }
          if (findings.filter(finding => finding.ruleId === resolved.rule.id).length >= 3) break
        }
        break
      }
      case 'comment-padding': {
        const minCommentChars = numberParam(params.minCommentChars, 2000)
        const fillerRatio = numberParam(params.fillerRatio, 0.9)
        for (const comment of comments) {
          if (comment.text.length < minCommentChars) continue
          let filler = 0
          for (let index = 0; index < comment.text.length; index += 1) {
            if (FILLER_RE.test(comment.text[index] ?? '')) filler += 1
          }
          if (filler / comment.text.length >= fillerRatio) {
            findings.push({
              ruleId: resolved.rule.id,
              severity: resolved.severity,
              category: resolved.rule.category,
              file,
              line: lineAt(text, comment.start),
              excerpt: `${comment.text.length} chars`,
              message: `${resolved.rule.description} (comment of ${comment.text.length} chars, ${((filler / comment.text.length) * 100).toFixed(0)}% filler)`,
            })
            break
          }
        }
        break
      }
    }
  }

  // Regex rules against the whole text (scope "all"); the source pass covers
  // scope "string" over code string literals.
  for (const resolved of resolvedRules) {
    const matcher = resolved.matcher
    if (matcher.kind !== 'regex' || matcher.scope !== 'all') continue
    if (matcher.files.size > 0 && !matcher.files.has(basenameOf(file))) continue
    matcher.regex.lastIndex = 0
    for (let match = matcher.regex.exec(text); match !== null; match = matcher.regex.exec(text)) {
      findings.push({
        ruleId: resolved.rule.id,
        severity: resolved.severity,
        category: resolved.rule.category,
        file,
        line: lineAt(text, match.index),
        excerpt: excerptOf(match[0] ?? ''),
        message: `${resolved.rule.description} (matched "${excerptOf(match[0] ?? '')}")`,
      })
    }
  }

  // Phrase rules against documentation text (whole file) and image alt texts.
  if (isText) {
    for (const resolved of phraseRules) {
      const matcher = resolved.matcher
      if (matcher.kind !== 'phrase') continue
      const hit = matchPhrase(text, matcher)
      if (hit === undefined) continue
      findings.push({
        ruleId: resolved.rule.id,
        severity: resolved.severity,
        category: resolved.rule.category,
        file,
        line: lineAt(text, text.toLowerCase().indexOf(hit.toLowerCase())),
        excerpt: excerptOf(hit),
        message: `${resolved.rule.description} (found "${hit}")`,
      })
    }
    for (const alt of extractImageAlts(text)) {
      for (const resolved of phraseRules) {
        const matcher = resolved.matcher
        if (matcher.kind !== 'phrase') continue
        const hit = matchPhrase(alt.alt, matcher)
        if (hit === undefined) continue
        findings.push({
          ruleId: resolved.rule.id,
          severity: resolved.severity,
          category: resolved.rule.category,
          file,
          line: lineAt(text, alt.start),
          excerpt: excerptOf(alt.alt),
          message: `${resolved.rule.description} (found "${hit}" in a Markdown image alt attribute)`,
        })
      }
    }
  }

  // URL rules against the whole text file (strings/comments handled by the source pass).
  if (isText) {
    for (const resolved of urlRules) {
      const matcher = resolved.matcher
      if (matcher.kind !== 'url') continue
      for (const hit of classifyUrlsInText(text, allowlist, blocklist)) {
        if (matcher.match === 'blocked-pattern' && hit.verdict !== 'blocked') continue
        if (matcher.match === 'unknown-host' && hit.verdict !== 'unknown') continue
        findings.push({
          ruleId: resolved.rule.id,
          severity: resolved.severity,
          category: resolved.rule.category,
          file,
          excerpt: excerptOf(hit.url),
          message: `${resolved.rule.description} (${hit.url} → host ${hit.host === '' ? '(unparsable)' : hit.host})`,
        })
      }
    }
  }

  return findings
}

/** Read a numeric rule param with a default. */
function numberParam(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : fallback
}

/** Trim a text to a bounded excerpt. */
function excerptOf(text: string): string {
  const single = text.replace(/\s+/g, ' ')
  return single.length > 120 ? `${single.slice(0, 117)}...` : single
}

/** The base file name of a scanned path. */
function basenameOf(path: string): string {
  const index = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'))
  return index >= 0 ? path.slice(index + 1) : path
}