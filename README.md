# dsh-guard

**English** | [中文](README.zh.md)

A security guard plugin for the [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (`dsh`).
It protects the harness host from untrusted plugins, workspaces and agent prompts in three layers:

1. **Static scan** — rule-based analysis of source files that **never executes** them.
2. **Runtime watch** — interception of dangerous tool calls, prompt steps and file operations.
3. **Surfaces** — a `/scan` command, a `plugin_scan` tool, a web panel and a user-managed allowlist.

Every finding is classified `block | warn | clean` and written to JSON or human-readable reports.

---

## Threat model

| Class | Examples | Default severity |
| --- | --- | --- |
| **Malicious code** | `eval`/`new Function`, `child_process`, `require("node:...")`, `postinstall` hooks, `process.env` exfiltration, hidden base64 payloads | `block` |
| **Context injection** | "ignore previous instructions" / `忽略之前的指令` prompt-override phrases, unvetted URL hosts | `block` / `warn` |
| **Token waste** | oversized files, base64-dominant blobs, repeated words/characters, filler comments | `warn` |
| **Sensitive paths** | `~/.ssh`, `.env`, credential stores touched by code | `warn` |

## Detector families

- **AST pass** (`src/static/ast.ts`) — parses TS/JS with the TypeScript compiler API
  (`ts.createSourceFile`), walks the tree, and matches rule patterns
  (`ast-call`, `ast-member`, `ast-import`). Text is never executed.
- **Content pass** (`src/static/content.ts`) — regex/phrase/url/file rules over
  text, code strings, image alt attributes and markdown.
- **Token pass** — size, base64 ratio, repetition and comment-padding heuristics
  (`src/static/content.ts` heuristics, `src/rules/token.json` tuning).
- **Runtime watch** (`src/runtime/watcher.ts`) — pre-step / pre-tool / post-tool
  gates, shell-pipe and destructive-shell patterns, SSH-write and
  token-drain telemetry, and `session` usage monitoring.
- **Whitelist** (`src/whitelist.ts`) — user-managed allowlist persisted to disk;
  trust/untrust via CLI or panel.

## Rules

Rules are plain JSON bundled under `src/rules/` (`code.json`, `injection.json`,
`token.json`, `allowlist.json`). A `rulesDir` option can override or extend them
by id. Example:

```json
{ "id": "code.eval", "kind": "ast-call", "severity": "block", "callee": ["eval"] }
```

See `src/rules.ts` for the full rule schema.

## Usage

```bash
dsh plugin --profile default add dsh-guard
```

```ts
// host application
import { Context } from '@deepseek-ai/cordis'
import Guard from 'dsh-guard'

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

### Runtime watch

Enabled by default. The guard listens on:

- `agent/pre-step` — rejects steps that match `injection.*` or token-drain patterns.
- `tools/*` — denies `exec`/`spawn` of destructive commands; asks on shell
  pipelines that write to `~/.ssh` or the token cache; blocks `write`/`edit`
  outside configured `workspaceRoots`.
- `fs/*` — observes read/edit of sensitive paths (`~/.ssh`, `.env`, …).
- `session/event` — tracks `assistant/message` token usage and warns on
  suspicious consumption.

### Web panel

Served by the harness web server at the configured path (default `/scan`):
live findings, rule overview, allowlist management (trust/untrust), and report download.

## Development

```bash
pnpm install
pnpm typecheck   # tsc --noEmit
pnpm test        # vitest run (82 tests: static, rules, runtime, whitelist, plugin)
pnpm build       # tsc emit + copy bundled rules into lib/
```

The test suite runs three fixture families under `tests/fixtures/`:
`clean/`, `injected/`, `malicious/` — plus `samples/malicious-demo`, a
deliberately malicious sample plugin that is **never executed** by the scanner
(scan it with `/scan samples/malicious-demo` to see it reported).

## Design constraints

- The scanner is **purely static**: only `ts.createSourceFile` / `ts.createScanner`
  are used; scanned source is never imported, evaluated or executed.
- No unvetted AI-signature or hashing mechanisms; verdicts come from auditable,
  id-overridable JSON rules.
- The runtime gate decisions use the host's native `PreToolDecision` /
  `PostToolDecision` / `PreStepDecision` contracts.

## License

MIT