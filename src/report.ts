/**
 * Human-readable rendering of scan reports, plus the JSON projection.
 * @module dsh-security-guard/report
 */

import type { ScanFinding, ScanReport, ScanVerdict } from './types.ts'

const VERDICT_LABEL: Record<ScanVerdict, string> = {
  block: 'BLOCK',
  warn: 'WARN',
  clean: 'CLEAN',
}

/** Render one finding as a single line. */
export function renderFinding(finding: ScanFinding): string {
  const location = finding.line !== undefined ? `${finding.file}:${finding.line}${finding.column !== undefined ? `:${finding.column}` : ''}` : finding.file
  const excerpt = finding.excerpt !== undefined ? ` — ${finding.excerpt}` : ''
  return `[${finding.severity.toUpperCase()}] ${finding.ruleId} ${location} ${finding.message}${excerpt}`
}

/** Render the complete human-readable report. */
export function renderReport(report: ScanReport): string {
  const lines: string[] = []
  lines.push(`dsh-security-guard scan: ${report.target}`)
  lines.push(`verdict: ${VERDICT_LABEL[report.verdict]} (${report.summary.block} block, ${report.summary.warn} warn)`)
  lines.push(`scanned ${report.filesScanned} files (${report.filesSkipped} skipped), ${report.bytesRead} bytes, ${report.ruleIds.length} rules`)
  lines.push('')
  for (const finding of report.findings) {
    lines.push(renderFinding(finding))
  }
  if (report.findings.length === 0) {
    lines.push('No findings.')
  }
  lines.push('')
  lines.push(`scanned at ${report.scannedAt}`)
  return lines.join('\n')
}

/** The JSON projection stored/emitted by the scanner (report itself is JSON-safe). */
export function reportToJson(report: ScanReport): string {
  return JSON.stringify(report, null, 2)
}