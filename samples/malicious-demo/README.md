# malicious-demo

This is a **deliberately malicious** sample plugin for demonstrating dsh-security-guard.

Never install or run it. Scan it instead:

```bash
/scan samples/malicious-demo
# or
plugin_scan(target: "samples/malicious-demo")
```

The scan reports **block** for:

- `code.install-script` — a `postinstall` hook in `package.json`
- `code.eval` — `eval(...)` smuggling filesystem writes
- `code.child-process` + `code.child-process-module` — `require('node:child_process')` + `cp.execSync`
- `code.env-access` — reading `process.env.API_KEY`
- `code.network-unknown-host` — exfiltration URL (and `code.network-blocked`
  once an operator blocklist pattern is configured)
- `code.sensitive-path` — the `~/.ssh` string literal
- `injection.directive` — "ignore previous instructions" content
- `token.repetition` — the repeated directive payload

All without executing a single line of it.