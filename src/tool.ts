/**
 * The `plugin_scan` model-facing tool: lets the agent itself request a static
 * scan of a plugin before loading or trusting it.
 * @module dsh-guard/tool
 */

import { defineTool } from '@deepseek-ai/dsh-tools'
import type { ScanDeps } from './command.ts'

/** The structural shape of the dsh `tools` service. */
export interface ToolService {
  register(definition: ReturnType<typeof defineTool>): () => void
}

/** Register the `plugin_scan` tool. Returns a disposer. */
export function registerScanTool(tools: ToolService, deps: ScanDeps): () => void {
  return tools.register(defineTool({
    name: 'plugin_scan',
    description: 'Run a static security scan of a plugin directory (or a single file) before installing, loading, or trusting it. Reports a verdict: block (malicious or unsafe), warn (suspicious), or clean.',
    parameters: {
      target: {
        type: 'string',
        required: true,
        description: 'Plugin name resolved under the configured scanRoots, or a file/directory path.',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          verdict: { type: 'string', required: true, enum: ['block', 'warn', 'clean'] },
          findings: { type: 'integer', required: true },
          files: { type: 'integer', required: true },
        },
      },
      render: (_args, value) => [{
        type: 'text',
        text: `scan verdict: ${value.verdict}; findings: ${value.findings}; files scanned: ${value.files}`,
      }],
    },
    async execute(args: { target: string }, _exec) {
      const outcome = deps.runScan(args.target)
      if (outcome.kind === 'error') {
        throw new Error(outcome.message)
      }
      deps.record('command', outcome.report.verdict === 'block' ? 'block' : 'warn', `plugin_scan ${outcome.report.target}: ${outcome.report.verdict}`)
      return {
        verdict: outcome.report.verdict,
        findings: outcome.report.findings.length,
        files: outcome.report.filesScanned,
      }
    },
  }))
}