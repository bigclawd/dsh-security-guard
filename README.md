# 🛡️ dsh-security-guard

**English** | [中文](README.zh.md)

> A security guard for the [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (`dsh`).
> Static scanning and runtime interception that **never executes** the code it protects you from.

![Static Analysis](https://img.shields.io/badge/analysis-static-6a9fb5)
![Runtime](https://img.shields.io/badge/runtime-intercept-8b5cf6)
![Language](https://img.shields.io/badge/TypeScript-6.x-3178c6)
![Tests](https://img.shields.io/badge/tests-89%20passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)
![dsh](https://img.shields.io/badge/dsh-0.1.0--rc.5-4c6ef5)

---

## ✨ Highlights

| | |
| --- | --- |
| 🔍 **Static scan** | Rule-based analysis of source files — `ts.createSourceFile` only, scanned code is never imported or executed |
| 👁️ **Runtime watch** | Intercepts dangerous tool calls, prompt steps and file operations before they happen |
| 📊 **Verdicts** | Every finding classified `block \| warn \| clean`, written to JSON or human-readable reports |
| 🧩 **Extensible rules** | Plain auditable JSON rules, overridable per id, no opaque signatures |
| 🖥️ **Surfaces** | `/scan` command, `plugin_scan` tool, live web panel, user-managed allowlist |

## 🎯 Threat model

| Class | Examples | Default severity |
| --- | --- | --- |
| 🧨 **Malicious code** | `eval` / `new Function`, `child_process`, `require("node:...")`, `postinstall` hooks, `process.env` exfiltration, hidden base64/hex payloads, computed access on globals | `block` |
| 💉 **Context injection** | "ignore previous instructions" / `忽略之前的指令` prompt-override phrases, unvetted URL hosts | `block` / `warn` |
| ⏳ **Token waste** | oversized files, base64-dominant blobs, repeated words/characters, filler comments | `warn` |
| 🔐 **Sensitive paths** | `~/.ssh`, `.env`, credential stores touched by code | `warn` |

## 🔍 Detector families

- **AST pass** (`src/static/ast.ts`) — parses TS/JS with the TypeScript compiler
  API (`ts.createSourceFile`), walks the tree, matches rule patterns
  (`ast-call`, `ast-member`, `ast-computed`, `ast-import`). Text is never executed.
- **Content pass** (`src/static/content.ts`) — regex / phrase / url / file rules
  over text, code strings, image alt attributes and markdown.
- **Token pass** — size, base64 ratio, repetition and comment-padding heuristics
  (`src/static/content.ts` heuristics, `src/rules/token.json` tuning).
- **Runtime watch** (`src/runtime/watcher.ts`) — pre-step / pre-tool / post-tool
  gates, shell-pipe and destructive-shell patterns, SSH-write and token-drain
  telemetry, `session` usage monitoring.
- **Whitelist** (`src/whitelist.ts`) — user-managed allowlist persisted to disk;
  trust / untrust via CLI or panel.

## 📦 Rules

Rules are plain JSON bundled under `src/rules/` — `code.json`, `injection.json`,
`token.json`, `allowlist.json`. A `rulesDir` option overrides or extends them by
id. The full schema lives in `src/rules.ts`.

```json
{ "id": "code.eval", "kind": "ast-call", "severity": "block", "callee": ["eval"] }
```

Matcher kinds: `ast-call` (calls/`new`), `ast-member` (dotted access),
`ast-computed` (computed access on globals — obfuscation signal),
`ast-import` (imports/requires), `regex` (scoped to `all`/`string`/`comment`),
`phrase`, `url`, `file`. Beyond the classic malicious patterns, the bundled
rules harden against obfuscation: hex/base64 `Buffer.from`/`toString`
encodings, long hex-only string payloads, and computed member access on
`globalThis`/`global`/`process` are all flagged. The full schema lives in
`src/rules.ts`.

## 🚀 Usage

### Install

```bash
dsh plugin --profile default add dsh-security-guard
```

### Host application

```ts
import { Context } from '@deepseek-ai/cordis'
import Guard from 'dsh-security-guard'

ctx.plugin(Guard, {
  rulesDir: 'config/guard-rules',          // optional overrides
  scan: { maxFiles: 5000, maxFileSize: 4 * 1024 * 1024, skipSegments: ['node_modules', '.git', 'dist', 'lib'] },
  runtime: { enabled: true, blockOnSeverity: ['block'], maxFindingsPerScan: 200 },
  allowlist: { file: 'data/guard-allowlist.json' },
  web: { enabled: true, path: '/scan' },
})
```

### Static scan

```bash
/scan ./plugin-dir                 # human-readable report
/scan ./plugin-dir --json          # machine-readable
/scan ./plugin-dir --json --out report.json
```

Or via the `plugin_scan` tool with parameters `target`, `severity`, `json`, `out`.

## 👁️ Runtime watch

Enabled by default. The guard listens on:

| Event | Action |
| --- | --- |
| `agent/pre-step` | Rejects steps matching `injection.*` or token-drain patterns |
| `tools/*` | Denies `exec`/`spawn` of destructive commands; asks on shell pipelines writing to `~/.ssh` or the token cache; blocks `write`/`edit` outside `workspaceRoots` |
| `fs/*` | Observes read/edit of sensitive paths (`~/.ssh`, `.env`, …) |
| `session/event` | Tracks `assistant/message` token usage, warns on suspicious consumption |

## 🖥️ Web panel

Served by the harness web server at the configured path (default `/scan`):
live findings, rule overview, allowlist management (trust / untrust), report download.

## 🧪 Development

```bash
pnpm install
pnpm typecheck   # tsc --noEmit
pnpm test        # vitest run (89 tests: static, rules, runtime, whitelist, plugin)
pnpm build       # tsc emit + copy bundled rules into lib/
```

The test suite runs three fixture families under `tests/fixtures/` —
`clean/`, `injected/`, `malicious/` — plus `samples/malicious-demo`, a
deliberately malicious sample plugin that the scanner **never executes**
(scan it with `/scan samples/malicious-demo` to see it reported).

## 🔒 Design constraints

- The scanner is **purely static**: only `ts.createSourceFile` / `ts.createScanner`
  are used; scanned source is never imported, evaluated or executed.
- No unvetted AI-signature or hashing mechanisms; verdicts come from auditable,
  id-overridable JSON rules.
- Runtime gate decisions use the host's native `PreToolDecision` /
  `PostToolDecision` / `PreStepDecision` contracts.

## ⚠️ Known limits

- **Obfuscation is an arms race.** Rule patterns reliably catch naive malware,
  copy-paste samples, and — most importantly — install-time lifecycle scripts
  in `package.json` (unhideable: npm requires the literal key). But a
  determined attacker can still hide payloads behind runtime decoding or
  encryption. The scanner is a risk-reduction layer, not a security proof.
- **False positives exist.** Legitimate code can trip heuristic rules (e.g. a
  hex hash constant); verdicts default to `warn`, and the allowlist and
  `ruleSeverity` overrides handle the rest.
- **Scan before install.** A malicious `postinstall` runs the moment the
  package is installed — scan the package first (`/scan`), then `dsh plugin add`.

## 📄 License

[MIT](LICENSE)