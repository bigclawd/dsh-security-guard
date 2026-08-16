/**
 * Runtime threat detection on live text: prompt-injection phrases in the
 * context the model is about to see and in tool results, plus URL
 * classification of tool-call arguments. Pure text analysis — no execution.
 * @module dsh-guard/detector
 */

import type { ResolvedRule } from '../rules.ts'
import type { ScanSeverity } from '../types.ts'
import { phraseHits } from '../phrase.ts'
import { classifyUrlsInText } from '../urls.ts'

/** One runtime-detected threat. */
export interface ThreatHit {
  readonly ruleId: string
  readonly severity: ScanSeverity
  readonly message: string
}

/** Run every phrase rule against live text (context or tool result). */
export function detectInjection(text: string, phraseRules: readonly ResolvedRule[]): ThreatHit[] {
  return phraseHits(text, phraseRules).map(hit => ({
    ruleId: hit.ruleId,
    severity: hit.severity,
    message: `injection phrase "${hit.phrase}"`,
  }))
}

/** Classify URLs in a tool-call argument text; returns non-allowed hits. */
export function detectUrls(
  text: string,
  allowlist: readonly string[],
  blocklist: readonly string[],
): ThreatHit[] {
  const hits: ThreatHit[] = []
  for (const classified of classifyUrlsInText(text, allowlist, blocklist)) {
    if (classified.verdict === 'blocked') {
      hits.push({
        ruleId: 'code.network-blocked',
        severity: 'block',
        message: `network target matches a blocked pattern: ${classified.url}`,
      })
    } else if (classified.verdict === 'unknown') {
      hits.push({
        ruleId: 'code.network-unknown-host',
        severity: 'warn',
        message: `network target outside the allowlist: ${classified.url} (host ${classified.host})`,
      })
    }
  }
  return hits
}