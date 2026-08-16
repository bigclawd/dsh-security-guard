/**
 * Install-hook tests: profile location detection, manifest diffing, and the
 * profile-manifest watcher scanning freshly installed packages.
 */

import { describe, expect, it } from 'vitest'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { diffInstalledPackages, InstallWatcher, locateProfileFromModule } from '../src/runtime/installer.ts'
import { testConfig, testScanOptions } from './helpers.ts'
import type { ScanOptions } from '../src/static/scanner.ts'

describe('locateProfileFromModule', () => {
  it('resolves a Windows profile install path', () => {
    const located = locateProfileFromModule('file:///C:/Users/me/.dsh/profiles/web/node_modules/dsh-security-guard/lib/types/index.js')
    expect(located).toEqual({ profileDir: 'C:\\Users\\me\\.dsh\\profiles\\web', profileName: 'web' })
  })

  it('resolves the profile name from any install layout', () => {
    const located = locateProfileFromModule('file:///C:/Users/me/.dsh/profiles/headless/node_modules/dsh-security-guard/index.js')
    expect(located?.profileDir).toMatch(/profiles[\\/]headless$/)
    expect(located?.profileName).toBe('headless')
  })

  it('returns undefined outside a profile (dev checkout)', () => {
    expect(locateProfileFromModule('file:///C:/dev/dsh-security-guard/src/runtime/installer.ts')).toBeUndefined()
    expect(locateProfileFromModule('file:///C:/dev/dsh/packages/guard/guard/src/runtime/installer.ts')).toBeUndefined()
  })
})

describe('diffInstalledPackages', () => {
  const base = JSON.stringify({ name: 'p', dependencies: { a: '1.0.0' } })

  it('returns newly added dependencies', () => {
    const after = JSON.stringify({ name: 'p', dependencies: { a: '1.0.0', evil: '^2.0.0' } })
    expect(diffInstalledPackages(base, after)).toEqual(['evil'])
  })

  it('ignores removed and unchanged packages', () => {
    const after = JSON.stringify({ name: 'p', dependencies: { b: '1.0.0' } })
    expect(diffInstalledPackages(base, after)).toEqual(['b'])
  })

  it('treats bundles entries as installed packages', () => {
    const after = JSON.stringify({ name: 'p', dependencies: {}, dsh: { profile: { bundles: ['evil-bundle'] } } })
    expect(diffInstalledPackages(base, after)).toEqual(['evil-bundle'])
  })

  it('returns an empty set on unparseable manifests', () => {
    expect(diffInstalledPackages('not json', 'also not json')).toEqual([])
  })
})

describe('InstallWatcher', () => {
  it('baseline poll scans nothing, then scans newly added packages', () => {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-guard-install-hook-'))
    const manifest = join(dir, 'package.json')
    mkdirSync(join(dir, 'node_modules', 'evil-pkg', 'src'), { recursive: true })
    writeFileSync(manifest, JSON.stringify({ name: 'p', dependencies: {} }))
    writeFileSync(join(dir, 'node_modules', 'evil-pkg', 'package.json'), JSON.stringify({ name: 'evil-pkg', version: '1.0.0' }))
    writeFileSync(join(dir, 'node_modules', 'evil-pkg', 'src', 'index.js'), "eval('console.log(1)')\n")

    const config = testConfig()
    const options = testScanOptions(config)
    const scans: string[] = []
    const watcher = new InstallWatcher(dir, 100, options, entry => scans.push(entry.package))

    watcher.poll() // baseline
    expect(scans).toEqual([])

    writeFileSync(manifest, JSON.stringify({ name: 'p', dependencies: { 'evil-pkg': '1.0.0' } }))
    watcher.poll()
    expect(scans).toEqual(['evil-pkg'])

    // unchanged manifest → no re-scan
    watcher.poll()
    expect(scans).toEqual(['evil-pkg'])
  })

  it('scans the installed package directory and produces findings', () => {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-guard-install-scan-'))
    const manifest = join(dir, 'package.json')
    mkdirSync(join(dir, 'node_modules', 'malicious-pkg', 'src'), { recursive: true })
    writeFileSync(manifest, JSON.stringify({ name: 'p', dependencies: {} }))
    writeFileSync(join(dir, 'node_modules', 'malicious-pkg', 'package.json'), JSON.stringify({ name: 'malicious-pkg', version: '1.0.0' }))
    writeFileSync(join(dir, 'node_modules', 'malicious-pkg', 'src', 'index.js'), "require('node:child_process').execSync('whoami')\n")

    const options = testScanOptions(testConfig()) as ScanOptions
    let entry: { package: string; report: { verdict: string } } | undefined
    const watcher = new InstallWatcher(dir, 100, options, scanned => { entry = scanned })
    watcher.poll()

    writeFileSync(manifest, JSON.stringify({ name: 'p', dependencies: { 'malicious-pkg': '1.0.0' } }))
    watcher.poll()
    watcher.stop()

    expect(entry?.package).toBe('malicious-pkg')
    expect(entry?.report.verdict).toBe('block')
  })
})
