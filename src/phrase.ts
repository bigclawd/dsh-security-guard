/**
 * Phrase matching, shared by the static content analysis and the runtime
 * injection detector. Case handling: rules either match case-insensitively
 * (lowercased haystack/needles) or verbatim.
 * @module dsh-guard/phrase
 */

import type { ResolvedRule, RuleMatcher } from './rules.ts'

/** Check `text` against one phrase matcher; returns the first matched phrase. */
export function matchPhrase(text: string, matcher: Extract<RuleMatcher, { kind: 'phrase' }>): string | undefined {
  if (matcher.caseSensitive) {
    return matcher.phrases.find(phrase => text.includes(phrase))
  }
  const lower = text.toLowerCase()
  for (let index = 0; index < matcher.phrases.length; index += 1) {
    const phrase = matcher.phrases[index]
    const needle = matcher.lower[index]
    if (phrase !== undefined && needle !== undefined && lower.includes(needle)) return phrase
  }
  return undefined
}

/** One phrase-rule hit. */
export interface PhraseHit {
  readonly ruleId: string
  readonly severity: import('./types.ts').ScanSeverity
  readonly phrase: string
}

/** Run every phrase rule in `rules` against `text`; one hit per rule. */
export function phraseHits(text: string, rules: readonly ResolvedRule[]): PhraseHit[] {
  const hits: PhraseHit[] = []
  for (const resolved of rules) {
    const matcher = resolved.matcher
    if (matcher.kind !== 'phrase') continue
    const phrase = matchPhrase(text, matcher)
    if (phrase !== undefined) {
      hits.push({ ruleId: resolved.rule.id, severity: resolved.severity, phrase })
    }
  }
  return hits
}