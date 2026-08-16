/**
 * Shared vocabulary for the dsh-security-guard security scanner: findings, reports,
 * rule definitions, plugin configuration, and runtime monitoring events.
 * @module dsh-security-guard/types
 */

/** A finding's impact class. */
export type ScanSeverity = 'block' | 'warn'

/** The threat family a rule belongs to. */
export type ScanCategory = 'code' | 'injection' | 'token'

/** The aggregated conclusion of a static scan. */
export type ScanVerdict = 'block' | 'warn' | 'clean'

/** One rule hit: which rule matched, where, and what it saw. */
export interface ScanFinding {
  /** Rule id, e.g. `code.eval` or `injection.directive`. */
  readonly ruleId: string
  /** Severity as configured for this rule (rule default, possibly overridden). */
  readonly severity: ScanSeverity
  /** The threat family. */
  readonly category: ScanCategory
  /** File path relative to the scanned root (or the absolute path when scanning a single file). */
  readonly file: string
  /** 1-based line of the hit when known. */
  readonly line?: number
  /** 1-based column of the hit when known. */
  readonly column?: number
  /** A short excerpt of the offending text (trimmed). */
  readonly excerpt?: string
  /** Human-readable explanation composed from the rule and the matched content. */
  readonly message: string
}

/** Per-category finding counts. */
export interface ScanSummary {
  readonly block: number
  readonly warn: number
  readonly clean: number
}

/** The structured outcome of one static scan. */
export interface ScanReport {
  /** The target as requested (plugin name or path). */
  readonly target: string
  /** The absolute path actually scanned. */
  readonly root: string
  /** Aggregated verdict: any block ⇒ block, else any warn ⇒ warn, else clean. */
  readonly verdict: ScanVerdict
  readonly findings: ScanFinding[]
  readonly filesScanned: number
  readonly filesSkipped: number
  readonly bytesRead: number
  readonly scannedAt: string
  readonly ruleIds: string[]
  readonly summary: ScanSummary
}

/** A threat spotted by the runtime watchers (not a static scan). */
export interface RuntimeEvent {
  /** Monotonic event counter. */
  readonly id: number
  /** Unix epoch milliseconds. */
  readonly time: number
  /** The watcher that produced the event. */
  readonly source: 'pre-step' | 'tool-call' | 'tool-result' | 'token' | 'command' | 'web' | 'install'
  readonly severity: ScanSeverity
  /** Human-readable description. */
  readonly message: string
  /** Agent id involved, when available. */
  readonly agentId?: string
  /** Tool name involved, when available. */
  readonly tool?: string
  /** Free-form details (rule ids, excerpts). */
  readonly details?: Record<string, unknown>
}

/** Where a rule may match inside a source file. */
export type MatchScope = 'all' | 'string' | 'comment'

/**
 * A compiled AST matching pattern.
 *
 * - `ast-call` matches call/new expressions: `eval(...)`, `new Function(...)`,
 *   `cp.exec(...)`, `require('node:child_process')`. Matching fields:
 *   - `callee` — bare identifier names (`eval`, `import`, `Function`).
 *   - `object`/`property` — dotted calls (`object.property(...)`, also
 *     `object["property"](...)`).
 *   - `module` — require()/import() of a module whose specifier equals one of
 *     these string literals.
 * - `ast-member` matches property access: `process.env`, `os.homedir()`.
 * - `ast-computed` matches computed member access on a named object:
 *   `globalThis['en'+'v']`, `process['env']` — indirection on globals is an
 *   obfuscation signal.
 * - `ast-import` matches static import/export-from declarations whose module
 *   specifier equals one of the strings.
 */
export interface AstCallRulePattern {
  readonly callee?: string[]
  readonly object?: string[]
  readonly property?: string[]
  readonly module?: string[]
}

export interface AstMemberRulePattern {
  readonly object: string[]
  readonly property: string[]
}

export interface AstComputedRulePattern {
  readonly object: string[]
}

export interface AstImportRulePattern {
  readonly specifier: string[]
}

/** One rule from a rule file. The `kind` selects the matcher that consumes it. */
export type RuleDefinition =
  | {
    readonly id: string
    readonly category: ScanCategory
    readonly severity: ScanSeverity
    readonly description: string
    readonly kind: 'ast-call'
    readonly pattern: AstCallRulePattern
  }
  | {
    readonly id: string
    readonly category: ScanCategory
    readonly severity: ScanSeverity
    readonly description: string
    readonly kind: 'ast-member'
    readonly pattern: AstMemberRulePattern
  }
  | {
    readonly id: string
    readonly category: ScanCategory
    readonly severity: ScanSeverity
    readonly description: string
    readonly kind: 'ast-computed'
    readonly pattern: AstComputedRulePattern
  }
  | {
    readonly id: string
    readonly category: ScanCategory
    readonly severity: ScanSeverity
    readonly description: string
    readonly kind: 'ast-import'
    readonly pattern: AstImportRulePattern
  }
  | {
    readonly id: string
    readonly category: ScanCategory
    readonly severity: ScanSeverity
    readonly description: string
    readonly kind: 'regex'
    /** The regular expression source (never compiled against scanned code). */
    readonly regex: string
    readonly flags?: string
    /** Where to search: whole file, string literals only, or comments only. */
    readonly scope?: MatchScope
    /** Optional file filter: exact relative path or `/`-suffixed path suffix. */
    readonly files?: string[]
  }
  | {
    readonly id: string
    readonly category: ScanCategory
    readonly severity: ScanSeverity
    readonly description: string
    readonly kind: 'phrase'
    /** Phrases matched anywhere in the text (case-insensitive unless `caseSensitive`). */
    readonly phrases: string[]
    readonly caseSensitive?: boolean
  }
  | {
    readonly id: string
    readonly category: ScanCategory
    readonly severity: ScanSeverity
    readonly description: string
    readonly kind: 'url'
    /**
     * `unknown-host`: any http(s) URL whose host is absent from the
     * allowlist. `blocked-pattern`: any URL containing one of the configured
     * `blocklistUrlPatterns` substrings.
     */
    readonly match: 'unknown-host' | 'blocked-pattern'
  }
  | {
    readonly id: string
    readonly category: ScanCategory
    readonly severity: ScanSeverity
    readonly description: string
    readonly kind: 'file'
    readonly check: FileCheckKind
    /** Thresholds, optional; rule defaults apply. */
    readonly params?: FileCheckParams
  }

/** File-level checks for token waste and hidden injection. */
export type FileCheckKind =
  /** Text file larger than `maxBytes` (default 10 MiB). */
  | 'oversize'
  /** A run of the same character or the same word repeated ≥ thresholds. */
  | 'repetition'
  /** Long base64-looking content dominating the file. */
  | 'base64-ratio'
  /** Zero-width / bidi control characters present. */
  | 'zero-width'
  /** base64 blobs whose decoded text contains injection phrases. */
  | 'base64-hidden'
  /** A comment longer than `minCommentChars`, mostly filler characters. */
  | 'comment-padding'

export interface FileCheckParams {
  /** Oversize threshold in bytes. */
  readonly maxBytes?: number
  /** Minimum run length of one repeated character. */
  readonly maxCharRun?: number
  /** Minimum run length of one repeated word. */
  readonly maxWordRun?: number
  /** Minimum decoded length before a base64 blob is examined. */
  readonly minBase64Length?: number
  /** Files at or above this byte size count as binary-ish when computing ratios. */
  readonly base64RatioMinBytes?: number
  /** Fraction of base64-looking content (0..1) above which the file is flagged. */
  readonly base64RatioThreshold?: number
  /** Minimum length of a comment before it is examined for filler. */
  readonly minCommentChars?: number
  /** Fraction of filler characters inside a long comment (0..1). */
  readonly fillerRatio?: number
}

/** Which file kinds receive which analyses. */
export interface ScanTargets {
  /** Extensions analyzed with the AST + source-text passes (default ts/tsx/js/jsx/mjs/cjs). */
  readonly code: string[]
  /** Extensions analyzed as documentation/skill text (default md/markdown/mdx/txt). */
  readonly text: string[]
  /** Extensions analyzed for token-waste and hidden-injection content checks (default the code ∪ text sets plus json/yaml/yml). */
  readonly content: string[]
}

/** Plugin configuration (validated by the schemastery schema in `index.ts`). */
export interface GuardConfig {
  /** Directories searched by name for `/scan <plugin-name>` (resolved under cwd when relative). */
  readonly scanRoots: string[]
  /** Default rule-severity overrides: `{ [ruleId]: 'block' | 'warn' }`. */
  readonly ruleSeverity: Record<string, ScanSeverity>
  /** Domains treated as trusted network targets (extends the bundled allowlist). */
  readonly allowlistDomains: string[]
  /** Substring matchers: URLs containing any of these are always a finding. */
  readonly blocklistUrlPatterns: string[]
  /** Directory of community rule files (*.json); merged over the bundled rules. */
  readonly rulesDir: string
  /** Workspace roots; fs write/edit tool calls resolving outside every root are denied. */
  readonly workspaceRoots: string[]
  /** Path of the state file (whitelist + last scan); empty disables persistence. */
  readonly stateFile: string
  /** Hard cap on bytes read per file. */
  readonly maxFileBytes: number
  /** Maximum files scanned per run. */
  readonly maxFiles: number
  /** Skip these path segments (node_modules, .git, lib, dist, build, .next). */
  readonly skipSegments: string[]
  /** Per-step context size (characters) beyond which `agent/pre-step` warns. */
  readonly maxStepChars: number
  /** Single-step token usage beyond which `session/event` warns. */
  readonly maxStepTokens: number
  /** Ring-buffer size for runtime events. */
  readonly eventBuffer: number
  /** Deny (not just record) dangerous tool-call argument patterns. */
  readonly denyDangerousToolCalls: boolean
  /** Serve the web panel (requires the webServer service to be present). */
  readonly webPanel: boolean
  /** Auto-scan freshly installed plugins: watches the profile manifest. */
  readonly installHook: {
    /** Enable the profile-manifest watcher. */
    readonly enabled: boolean
    /** Poll interval for the profile manifest. */
    readonly intervalMs: number
  }
}

/** The runtime state shared by the command, tool, web panel, and watchers. */
export interface GuardStateSnapshot {
  readonly trusted: string[]
  readonly lastScan: ScanReport | undefined
  readonly events: RuntimeEvent[]
  readonly ruleCount: number
}