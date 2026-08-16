/**
 * The dsh-security-guard web panel: a zero-dependency status page and JSON endpoint
 * served through the host's webServer service (when present).
 *
 * Routes (all exact):
 * - `GET  /scan`          — JSON: runtime snapshot + last report.
 * - `GET  /scan/panel`    — the self-contained HTML panel.
 * - `POST /scan/trust`    — body `{ "name": string }` whitelists a plugin.
 * - `POST /scan/untrust`  — body `{ "name": string }` un-whitelists a plugin.
 * @module dsh-security-guard/panel
 */

import type { IncomingMessage, ServerResponse } from 'node:http'
import type { ScanDeps } from '../command.ts'
import { renderReport } from '../report.ts'
import type { GuardStateSnapshot } from '../types.ts'

/** The structural shape of the dsh `webServer` service. */
export interface WebServerService {
  register(route: {
    readonly kind: 'exact'
    readonly path: string
    readonly handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>
  }): () => void
}

/** The maximum request body accepted (defense in depth). */
const MAX_BODY_BYTES = 64 * 1024

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body)
  res.statusCode = status
  res.setHeader('content-type', 'application/json; charset=utf-8')
  res.setHeader('content-length', Buffer.byteLength(payload))
  res.end(payload)
}

function sendHtml(res: ServerResponse, status: number, html: string): void {
  res.statusCode = status
  res.setHeader('content-type', 'text/html; charset=utf-8')
  res.setHeader('content-length', Buffer.byteLength(html))
  res.end(html)
}

/** Collect a small JSON request body. */
async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []
  let total = 0
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    total += buffer.length
    if (total > MAX_BODY_BYTES) {
      throw new Error('request body too large')
    }
    chunks.push(buffer)
  }
  const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'))
  if (typeof parsed !== 'object' || parsed === null) throw new Error('expected a JSON object')
  return parsed as Record<string, unknown>
}

function panelHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>dsh-security-guard</title>
<style>
  body { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #0f1117; color: #d7dae0; margin: 0; padding: 2rem; }
  h1 { font-size: 1.4rem; } h2 { font-size: 1.05rem; margin-top: 2rem; color: #9aa4b2; }
  table { border-collapse: collapse; width: 100%; }
  td, th { border: 1px solid #262b36; padding: .35rem .6rem; text-align: left; font-size: .85rem; vertical-align: top; }
  th { background: #161a23; color: #9aa4b2; }
  .block { color: #ff6b6b; } .warn { color: #ffd93d; } .clean { color: #6bcb77; }
  pre { white-space: pre-wrap; background: #161a23; padding: 1rem; border-radius: .4rem; font-size: .8rem; max-height: 28rem; overflow: auto; }
  button { background: #262b36; color: #d7dae0; border: 1px solid #3a4150; border-radius: .3rem; padding: .2rem .6rem; cursor: pointer; }
  button:hover { background: #323a4a; }
  .muted { color: #6b7280; }
</style>
</head>
<body>
<h1>dsh-security-guard</h1>
<div class="muted" id="meta"></div>
<h2>Last scan</h2>
<pre id="report">(no scan yet)</pre>
<h2>Trusted plugins</h2>
<table><thead><tr><th>name</th><th></th></tr></thead><tbody id="trusted"></tbody></table>
<h2>Runtime events (latest first)</h2>
<table><thead><tr><th>time</th><th>sev</th><th>source</th><th>agent</th><th>message</th></tr></thead><tbody id="events"></tbody></table>
<script>
async function refresh() {
  const res = await fetch('/scan')
  const data = await res.json()
  const s = data.snapshot
  document.getElementById('meta').textContent = 'rules: ' + s.ruleCount + ' · events kept: ' + s.events.length + ' · state: ' + JSON.stringify(data.state)
  const report = data.report
  document.getElementById('report').textContent = report ? report.text : '(no scan yet)'
  const trusted = document.getElementById('trusted')
  trusted.textContent = ''
  for (const name of s.trusted) {
    const row = document.createElement('tr')
    const cell = document.createElement('td'); cell.textContent = name
    const act = document.createElement('td')
    const btn = document.createElement('button'); btn.textContent = 'untrust'; btn.onclick = () => post('/scan/untrust', { name }).then(refresh)
    act.appendChild(btn)
    row.appendChild(cell); row.appendChild(act); trusted.appendChild(row)
  }
  const events = document.getElementById('events')
  events.textContent = ''
  for (const ev of s.events.slice().reverse()) {
    const row = document.createElement('tr')
    for (const value of [new Date(ev.time).toISOString(), ev.severity, ev.source, ev.agentId ?? '', ev.message]) {
      const cell = document.createElement('td')
      if (ev.severity === 'block') cell.className = 'block'
      else if (ev.severity === 'warn') cell.className = 'warn'
      cell.textContent = value
      row.appendChild(cell)
    }
    events.appendChild(row)
  }
}
async function post(path, body) {
  await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
}
refresh()
setInterval(refresh, 5000)
</script>
</body>
</html>`
}

/** Register the panel routes. Returns a disposer. */
export function registerPanel(webServer: WebServerService, deps: ScanDeps): () => void {
  const disposers: (() => void)[] = []

  disposers.push(webServer.register({
    kind: 'exact',
    path: '/scan',
    handler: (_req, res) => {
      const snapshot = deps.snapshot()
      sendJson(res, 200, {
        snapshot,
        state: { whitelisted: snapshot.trusted.length, rules: snapshot.ruleCount },
        report: snapshot.lastScan === undefined ? null : { text: renderReport(snapshot.lastScan), report: snapshot.lastScan },
      })
    },
  }))

  disposers.push(webServer.register({
    kind: 'exact',
    path: '/scan/panel',
    handler: (_req, res) => {
      sendHtml(res, 200, panelHtml())
    },
  }))

  const trustHandler = (trust: boolean) => async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    try {
      const body = await readJsonBody(req)
      const name = body['name']
      if (typeof name !== 'string' || name.trim().length === 0) {
        sendJson(res, 400, { error: 'body must be a JSON object with a non-empty string "name"' })
        return
      }
      const changed = trust ? deps.trust(name.trim()) : deps.untrust(name.trim())
      deps.record('web', 'warn', `${trust ? 'trusted' : 'untrusted'} plugin ${name.trim()}`)
      sendJson(res, 200, { name: name.trim(), changed })
    } catch (error: unknown) {
      sendJson(res, 400, { error: error instanceof Error ? error.message : String(error) })
    }
  }

  disposers.push(webServer.register({ kind: 'exact', path: '/scan/trust', handler: trustHandler(true) }))
  disposers.push(webServer.register({ kind: 'exact', path: '/scan/untrust', handler: trustHandler(false) }))

  return () => {
    for (const dispose of disposers) dispose()
  }
}

/** The runtime state the panel reads. */
export interface PanelState {
  readonly snapshot: GuardStateSnapshot
  readonly reportText: string | undefined
}