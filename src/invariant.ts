/**
 * Package-owned invariant companion for `dsh-security-guard`. The bundled
 * rule files are package configuration: the invariant verifies they parse and
 * expose the core detectors so a malformed release fails loudly in CI.
 * @module dsh-security-guard/invariant
 */

/* jscpd:ignore-start */
import type { Context } from '@deepseek-ai/cordis'
import type { InvariantInstaller } from '@deepseek-ai/dsh-invariants'
import { loadBundledAllowlist, loadBundledRules } from './rules.ts'

const PACKAGE_NAME = 'dsh-security-guard'

/** Cordis companion plugin name. */
export const name = 'guard-invariant'
/** Service required before the companion can reserve package ownership. */
export const inject = ['invariants']

/**
 * The bundled rule set must parse and cover the three detector families, and
 * the allowlist must resolve; otherwise every scan silently degrades.
 */
const install: InvariantInstaller = () => {
  const rules = loadBundledRules()
  const ids = new Set(rules.map(rule => rule.id))
  for (const required of ['code.eval', 'injection.directive', 'injection.directive-zh', 'token.repetition']) {
    if (!ids.has(required)) throw new Error(`dsh-security-guard invariant: bundled rules are missing "${required}"`)
  }
  if (rules.length !== ids.size) throw new Error('dsh-security-guard invariant: bundled rule ids are not unique')
  const domains = loadBundledAllowlist()
  if (!domains.includes('api.deepseek.com')) throw new Error('dsh-security-guard invariant: allowlist is missing api.deepseek.com')
}

/**
 * Register this package's invariant companion.
 * @param ctx - Cordis context carrying the invariant service.
 * @returns the installed registration's disposer after setup succeeds.
 */
export const apply = (ctx: Context): Promise<() => void> =>
  Promise.resolve(ctx.invariants.register(PACKAGE_NAME, install))
/* jscpd:ignore-end */