// Prepack: copy bundled rule JSON into the emitted artifact so the built
// package resolves rules relative to its own files (lib/rules/*.json).
import { cpSync, existsSync, mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const src = resolve(here, '../src/rules')
const out = resolve(here, '../lib/rules')

if (!existsSync(src)) throw new Error(`copy-rules: missing bundled rules at ${src}`)
mkdirSync(out, { recursive: true })
for (const file of ['code.json', 'injection.json', 'token.json', 'allowlist.json']) {
  cpSync(resolve(src, file), resolve(out, file))
}
console.log(`copy-rules: bundled ${out}`)