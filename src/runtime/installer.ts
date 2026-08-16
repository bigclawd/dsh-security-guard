/**
 * Auto-scan of freshly installed plugins.
 *
 * The host exposes no "package installed" event: `dsh plugin add` runs pnpm in
 * a separate CLI process and only then rewrites the profile manifest
 * (`$DSH_HOME/profiles/<name>/package.json`). That file is the reliable
 * install-complete signal — this watcher polls it, diffs the dependency set,
 * and statically scans each newly added package's directory under the
 * profile's `node_modules`. Scanned code is never executed.
 * @module dsh-security-guard/installer
 */

import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'
import { scanTarget, type ScanOptions } from '../static/scanner.ts'
import type { ScanReport } from '../types.ts'

/** The profile directory and name derived from a module URL. */
export interface LocatedProfile {
  readonly profileDir: string
  readonly profileName: string
}

/**
 * Resolve the enclosing profile from this module's own URL:
 * `.../profiles/<name>/node_modules/<pkg>/...`. Returns undefined when the
 * module runs outside a profile (dev checkout, monorepo source).
 */
export function locateProfileFromModule(moduleUrl: string): LocatedProfile | undefined {
  const marker = /profiles[\\/]([^\\/]+)[\\/]node_modules[\\/]/.exec(moduleUrl)
  if (marker === null) return undefined
  const profileName = marker[1]
  if (profileName === undefined || profileName === '') return undefined
  const profileDir = fileURLToPath(moduleUrl.slice(0, marker.index) + 'profiles/' + profileName)
  return { profileDir, profileName }
}

/** Collect the package names the profile depends on (deps ∪ bundles). */
function manifestPackages(manifest: unknown): Set<string> {
  const names = new Set<string>()
  if (typeof manifest !== 'object' || manifest === null) return names
  const record = manifest as Record<string, unknown>
  const dependencies = record.dependencies
  if (typeof dependencies === 'object' && dependencies !== null) {
    for (const name of Object.keys(dependencies)) names.add(name)
  }
  const bundles = record.dsh as Record<string, unknown> | undefined
  const list = bundles?.profile as Record<string, unknown> | undefined
  const bundleNames = list?.bundles
  if (Array.isArray(bundleNames)) {
    for (const name of bundleNames) {
      if (typeof name === 'string') names.add(name)
    }
  }
  return names
}

/**
 * Diff two profile manifests; returns the packages present after the change
 * that were absent before (the freshly installed set). A manifest that fails
 * to parse yields no packages.
 */
export function diffInstalledPackages(beforeManifest: string, afterManifest: string): string[] {
  let before: unknown
  let after: unknown
  try {
    before = JSON.parse(beforeManifest)
    after = JSON.parse(afterManifest)
  } catch {
    return []
  }
  const beforeSet = manifestPackages(before)
  const afterSet = manifestPackages(after)
  const added: string[] = []
  for (const name of afterSet) {
    if (!beforeSet.has(name)) added.push(name)
  }
  return added.sort()
}

/** One auto-scan result, persisted as a JSONL record. */
export interface InstallScanEntry {
  readonly package: string
  readonly scannedAt: string
  readonly report: ScanReport
}

/** A consumer for a completed install scan (record/emit/persist). */
export type InstallScanHandler = (entry: InstallScanEntry) => void

/**
 * Polls the profile manifest and scans newly installed packages. Call
 * {@link start} from the plugin fiber and {@link stop} on teardown.
 */
export class InstallWatcher {
  private readonly manifestPath: string
  private readonly options: ScanOptions
  private readonly handler: InstallScanHandler
  private readonly intervalMs: number
  private timer: NodeJS.Timeout | undefined
  private lastManifest: string | undefined

  constructor(
    readonly profileDir: string,
    intervalMs: number,
    options: ScanOptions,
    handler: InstallScanHandler,
  ) {
    this.manifestPath = join(profileDir, 'package.json')
    this.intervalMs = intervalMs
    this.options = options
    this.handler = handler
  }

  /** Start polling; the first poll only establishes the baseline. */
  start(): void {
    this.poll()
    this.timer = setInterval(() => this.poll(), this.intervalMs)
  }

  /** Stop polling. */
  stop(): void {
    if (this.timer !== undefined) clearInterval(this.timer)
    this.timer = undefined
  }

  /** Poll once: baseline, no-op, or diff-and-scan. */
  poll(): void {
    let after: string
    try {
      after = readFileSync(this.manifestPath, 'utf8')
    } catch {
      return
    }
    const before = this.lastManifest
    this.lastManifest = after
    if (before === undefined || before === after) return
    for (const pkg of diffInstalledPackages(before, after)) {
      this.scanPackage(pkg)
    }
  }

  private scanPackage(pkg: string): void {
    const dir = join(this.profileDir, 'node_modules', pkg)
    if (!existsSync(dir)) return
    const report = scanTarget(dir, this.options)
    this.handler({ package: pkg, scannedAt: new Date().toISOString(), report })
  }
}
