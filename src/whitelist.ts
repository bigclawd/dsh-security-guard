/**
 * Plugin whitelist: administrators mark trusted plugins so `/scan` and the
 * web panel skip them. Persisted to a JSON file when `guard.stateFile` is set.
 * @module dsh-security-guard/whitelist
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import type { GuardConfig } from './types.ts'

/** The on-disk state shape. */
interface StateFileShape {
  readonly version: 1
  readonly trusted: string[]
}

/** Whitelist + persistence. Safe for concurrent use from listeners (single-threaded). */
export class Whitelist {
  private readonly trusted = new Set<string>()

  constructor(private readonly config: GuardConfig) {}

  /** Load persisted state if `stateFile` is configured and exists. */
  load(): void {
    if (this.config.stateFile === '') return
    const path = resolve(this.config.stateFile)
    if (!existsSync(path)) return
    try {
      const parsed = JSON.parse(readFileSync(path, 'utf8')) as Partial<StateFileShape>
      if (Array.isArray(parsed.trusted)) {
        for (const name of parsed.trusted) {
          if (typeof name === 'string' && name.length > 0) this.trusted.add(name)
        }
      }
    } catch {
      // A corrupt state file must not prevent startup; it is rewritten on save.
    }
  }

  /** Whether a plugin name is trusted. */
  isTrusted(name: string): boolean {
    return this.trusted.has(name)
  }

  /** Mark a plugin trusted; persists when configured. */
  trust(name: string): boolean {
    const changed = !this.trusted.has(name)
    this.trusted.add(name)
    if (changed) this.persist()
    return changed
  }

  /** Remove a plugin from the whitelist; persists when configured. */
  untrust(name: string): boolean {
    const changed = this.trusted.delete(name)
    if (changed) this.persist()
    return changed
  }

  /** All trusted plugin names, sorted. */
  list(): string[] {
    return [...this.trusted].sort()
  }

  /** Persist to `stateFile` (no-op when unset). */
  persist(): void {
    if (this.config.stateFile === '') return
    const path = resolve(this.config.stateFile)
    const payload: StateFileShape = { version: 1, trusted: this.list() }
    try {
      mkdirSync(dirname(path), { recursive: true })
      writeFileSync(path, `${JSON.stringify(payload, null, 2)}\n`, 'utf8')
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error)
      console.error(`[dsh-security-guard] failed to persist state to ${path}: ${message}`)
    }
  }
}