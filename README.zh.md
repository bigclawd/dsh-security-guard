# dsh-guard

[English](README.md) | **中文**

[DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（`dsh`）的安全防护插件，
从三个层面保护宿主免受不可信插件、工作区和智能体提示词的侵害：

1. **静态扫描** — 基于规则的源码分析，**绝不执行**被扫描的代码。
2. **运行时监控** — 拦截危险工具调用、提示词步骤和文件操作。
3. **交互界面** — `/scan` 命令、`plugin_scan` 工具、Web 面板和用户可管理的白名单。

每个发现项都会被归类为 `block | warn | clean`，并写入 JSON 或人类可读的报告。

---

## 威胁模型

| 类别 | 示例 | 默认严重级别 |
| --- | --- | --- |
| **恶意代码** | `eval`/`new Function`、`child_process`、`require("node:...")`、`postinstall` 钩子、`process.env` 数据外泄、隐藏 base64 载荷 | `block` |
| **上下文注入** | “忽略之前的指令”等提示词覆盖短语、未经验证的 URL 主机 | `block` / `warn` |
| **令牌浪费** | 超大文件、base64 占主体的内容、重复单词/字符、填充性注释 | `warn` |
| **敏感路径** | 代码触及 `~/.ssh`、`.env`、凭据存储 | `warn` |

## 检测器家族

- **AST 传递**（`src/static/ast.ts`）— 用 TypeScript 编译器 API（`ts.createSourceFile`）
  解析 TS/JS，遍历语法树并匹配规则模式（`ast-call`、`ast-member`、`ast-import`）。
  文本从不被执行。
- **内容传递**（`src/static/content.ts`）— 对文本、代码字符串、图片 alt 属性和
  markdown 运行 regex/phrase/url/file 规则。
- **令牌传递** — 体积、base64 占比、重复和注释填充启发式
  （`src/static/content.ts` 启发式，`src/rules/token.json` 调参）。
- **运行时监控**（`src/runtime/watcher.ts`）— 步骤前 / 工具前 / 工具后三道闸门、
  管道与破坏性 shell 模式、SSH 写入与令牌消耗遥测，以及 `session` 用量监控。
- **白名单**（`src/whitelist.ts`）— 持久化到磁盘的用户白名单；可通过 CLI 或面板信任/取消信任。

## 规则

规则是打包在 `src/rules/` 下的纯 JSON（`code.json`、`injection.json`、
`token.json`、`allowlist.json`）。`rulesDir` 选项可以按 id 覆盖或扩展它们。示例：

```json
{ "id": "code.eval", "kind": "ast-call", "severity": "block", "callee": ["eval"] }
```

完整的规则 schema 见 `src/rules.ts`。

## 用法

```bash
dsh plugin --profile default add dsh-guard
```

```ts
// 宿主应用
import { Context } from '@deepseek-ai/cordis'
import Guard from 'dsh-guard'

ctx.plugin(Guard, {
  rulesDir: 'config/guard-rules',          // 可选覆盖
  scan: { maxFiles: 5000, maxFileSize: 4 * 1024 * 1024, skipSegments: ['node_modules', '.git', 'dist', 'lib'] },
  runtime: { enabled: true, blockOnSeverity: ['block'], maxFindingsPerScan: 200 },
  allowlist: { file: 'data/guard-allowlist.json' },
  web: { enabled: true, path: '/scan' },
})
```

### 静态扫描

```bash
/scan ./plugin-dir                 # 人类可读报告
/scan ./plugin-dir --json          # 机器可读
/scan ./plugin-dir --json --out report.json
```

也可以使用 `plugin_scan` 工具，参数为 `target`、`severity`、`json`、`out`。

### 运行时监控

默认开启。守卫监听以下事件：

- `agent/pre-step` — 拒绝匹配 `injection.*` 或令牌消耗模式的步骤。
- `tools/*` — 拒绝 `exec`/`spawn` 运行破坏性命令；对写入 `~/.ssh` 或令牌缓存的
  shell 管道请求确认；阻止在配置的 `workspaceRoots` 之外执行 `write`/`edit`。
- `fs/*` — 观察敏感路径（`~/.ssh`、`.env`、……）的读取/编辑。
- `session/event` — 跟踪 `assistant/message` 的令牌用量，对可疑消耗发出警告。

### Web 面板

由 harness 的 Web 服务器在配置的路径（默认 `/scan`）提供：
实时发现项、规则概览、白名单管理（信任/取消信任）和报告下载。

## 开发

```bash
pnpm install
pnpm typecheck   # tsc --noEmit
pnpm test        # vitest run（82 个测试：static、rules、runtime、whitelist、plugin）
pnpm build       # tsc 输出 + 将打包规则复制到 lib/
```

测试套件在 `tests/fixtures/` 下运行三组样例：`clean/`、`injected/`、`malicious/`，
外加 `samples/malicious-demo` —— 一个故意恶意的示例插件，**绝不会被扫描器执行**
（用 `/scan samples/malicious-demo` 扫描即可看到它被报告）。

## 设计约束

- 扫描器是**纯静态**的：只使用 `ts.createSourceFile` / `ts.createScanner`；
  被扫描的源码从不被 import、求值或执行。
- 不使用未经审查的 AI 签名或哈希机制；判定来自可审计、可按 id 覆盖的 JSON 规则。
- 运行时闸门决策使用宿主原生的 `PreToolDecision` / `PostToolDecision` /
  `PreStepDecision` 契约。

## License / 许可证

MIT