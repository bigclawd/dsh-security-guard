/**
 * URL extraction and host classification, shared by the static scanner and
 * the runtime tool-call watcher. A URL is classified against the configured
 * allowlist (exact hosts or `*.suffix` wildcards) and against operator
 * blocklist substrings.
 * @module dsh-security-guard/urls
 */

/** How one extracted URL was classified. */
export interface ClassifiedUrl {
  /** The URL as found (trimmed, scheme intact). */
  readonly url: string
  /** The host component, lowercased. */
  readonly host: string
  /** `unknown`: host absent from the allowlist; `blocked`: matches a blocklist pattern; `allowed`. */
  readonly verdict: 'unknown' | 'blocked' | 'allowed'
  /** 0-based offset of the URL inside the scanned text. */
  readonly offset: number
}

/** Match a host against allowlist entries (exact or `*.suffix` subdomains). */
export function hostAllowed(host: string, allowlist: readonly string[]): boolean {
  const lower = host.toLowerCase()
  for (const entry of allowlist) {
    const rule = entry.toLowerCase()
    if (rule.startsWith('*.')) {
      const suffix = rule.slice(1)
      if (lower.endsWith(suffix)) return true
    } else if (lower === rule) {
      return true
    }
  }
  return false
}

/** Classify one URL. */
export function classifyUrl(url: string, allowlist: readonly string[], blocklist: readonly string[]): ClassifiedUrl {
  const trimmed = url.trim()
  let host: string
  try {
    host = new URL(trimmed).host.toLowerCase()
  } catch {
    host = ''
  }
  let verdict: ClassifiedUrl['verdict'] = 'allowed'
  for (const pattern of blocklist) {
    if (trimmed.toLowerCase().includes(pattern.toLowerCase())) {
      verdict = 'blocked'
      break
    }
  }
  if (verdict === 'allowed' && host !== '' && !hostAllowed(host, allowlist)) {
    verdict = 'unknown'
  }
  return { url: trimmed, host, verdict, offset: 0 }
}

const URL_RE = /https?:\/\/[^\s"'<>)\]]+/g

/**
 * Extract candidate http(s) URLs from a piece of text. Trailing punctuation
 * (`.,;!?)`) is stripped; each candidate is passed through {@link classifyUrl}.
 */
export function classifyUrlsInText(
  text: string,
  allowlist: readonly string[],
  blocklist: readonly string[],
): ClassifiedUrl[] {
  const seen = new Set<string>()
  const results: ClassifiedUrl[] = []
  URL_RE.lastIndex = 0
  for (let match = URL_RE.exec(text); match !== null; match = URL_RE.exec(text)) {
    const raw = match[0] ?? ''
    const clean = raw.replace(/[.,;!?)\]}]+$/, '')
    if (clean.length < 8 || seen.has(clean)) continue
    seen.add(clean)
    const classified = classifyUrl(clean, allowlist, blocklist)
    if (classified.verdict !== 'allowed') results.push({ ...classified, offset: match.index })
  }
  return results
}