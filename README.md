# kova — the lockfile for agent tools

Your coding agent loads skills, plugins, MCP servers, hooks and memory files every session.
Nothing checks that they are still what you reviewed when you installed them.

`kova` pins a content hash of every one of them, re-verifies at session start, sits in front of
your MCP servers to catch tool definitions that change after install, and keeps a ledger of what
your agents installed and which prompt caused it.

Every documented 2026 agent supply-chain incident passed static review and would have tripped
this runtime check:

| Incident | What happened | What kova sees |
|---|---|---|
| Deadbugz (Aug 2026) | MCP server benign for 3 calls, then `tools/list` returned credential-hunting instructions | `mcp_tools_changed` from the proxy, critical; `--enforce` blocks it |
| postmark-mcp | 15 clean releases, then v1.0.16 added a hidden BCC | tools hash drift on the next session; description scan flags `hidden_bcc` |
| drp-compliance-sdk | payload fired during the `tools/list` handshake | config + tools pin at `init`; new destination during handshake |
| ClawHavoc | malicious skills rewrote `MEMORY.md`; directives persisted after the skills were deleted | memory file hashed every session; added text scanned for persistence / hidden-from-user instructions |

Works with **Claude Code, Codex CLI, Gemini CLI, Cursor, GitHub Copilot (CLI + VS Code), Claude
Desktop, Windsurf and Cline / Roo Code**. One binary, no daemon, state in `~/.kova`. Session hooks
are installed for Claude Code, Gemini CLI and Cursor; the others are pinned and verified the same
way but kova does not install into their hook systems yet, so verification there runs from your
shell profile, CI or the MCP proxy.

## Install

```sh
curl -fsSL https://kovaverified.io/install.sh | sh      # macOS / Linux
irm https://kovaverified.io/install.ps1 | iex           # Windows (PowerShell)
# or
go install github.com/ian-hickey/kova/cmd/kova@latest
```

Then, once per machine:

```sh
kova init          # discover + pin everything, install session hooks
kova wrap --all    # route stdio MCP servers through the verifying proxy
```

That's it. From now on every session starts with a verification pass; drift is reported into the
agent's context (so the model is told its tools changed) and to you.

## What gets pinned

| | Claude Code | Codex CLI | Gemini CLI | Cursor |
|---|---|---|---|---|
| Skills (`SKILL.md` trees, every file) | `~/.claude/skills`, `.claude/skills` | `~/.codex/skills`, `.agents/skills` | `~/.gemini/skills` | `~/.cursor/skills`, `.cursor/skills` |
| Plugins / extensions | install manifest + each installed plugin tree | – | `~/.gemini/extensions/*` | – |
| MCP server launch config | `~/.claude.json` (user + project), `.mcp.json` | `~/.codex/config.toml` | `settings.json` | `~/.cursor/mcp.json`, `.cursor/mcp.json` |
| MCP tool definitions (`tools/list` + server instructions) | ✓ | ✓ | ✓ | ✓ |
| Hooks config (hooks run **outside** the sandbox) | `settings*.json` | `hooks.json` if present | `settings.json` | `hooks.json` |
| Memory / instructions | `CLAUDE.md`, `.claude/rules`, auto-memory under `~/.claude/projects/*/memory` | `AGENTS.md`, `~/.codex/memories` | `GEMINI.md` | `.cursorrules`, `.cursor/rules/**`, `AGENTS.md` |
| Session-start hook | ✓ | – (no hook system; run `kova verify` yourself) | ✓ | ✓ (`beforeSubmitPrompt`) |
| Install ledger hook | ✓ (`PreToolUse` Bash) | – | ✓ (`BeforeTool`) | ✓ (`beforeShellExecution`) |
| Guard (deny tool calls near unreviewed instruction files) | ✓ (`PreToolUse`) | – | ✓ (`BeforeTool`) | ✓ (`beforeReadFile`) |
| Instruction-file sweep (ancestors, descendants, deps, includes) | ✓ | ✓ | ✓ | ✓ |
| MCP proxy wrapping | ✓ | – (TOML rewrite not yet supported) | ✓ | ✓ |

| | GitHub Copilot (CLI + VS Code) | Claude Desktop | Windsurf | Cline / Roo Code |
|---|---|---|---|---|
| Skills | – | – | – | – |
| Plugins / extensions | – | `Claude Extensions/*` (each bundle tree) | – | – |
| MCP server launch config | VS Code `mcp.json` (`servers`), `.vscode/mcp.json`, `~/.copilot/mcp-config.json` | `claude_desktop_config.json` | `~/.codeium/windsurf/mcp_config.json` | `cline_mcp_settings.json`, Roo `mcp_settings.json`, `.roo/mcp.json` |
| MCP tool definitions (`tools/list` + server instructions) | ✓ | ✓ | ✓ | ✓ |
| Hooks config | `.github/hooks/*.json` (pinned, not installed into) | – | `~/.codeium/windsurf/hooks.json` (pinned, not installed into) | – |
| Memory / instructions | `.github/copilot-instructions.md`, `.github/instructions/**`, `.github/prompts/**`, `.github/agents/**`, VS Code `prompts/*`, `AGENTS.md`; `~/.copilot/config.json` | – (no instruction files) | `global_rules.md`, `.windsurfrules`, `.windsurf/rules/**`, `.windsurf/workflows/**`, `AGENTS.md` | `.clinerules` (file or dir), `~/Documents/Cline/Rules`, `.roo/rules/**`, `~/.roo/rules/**`, `.roomodes`, `AGENTS.md` |
| Session-start / ledger / guard hooks | – (not installed yet; run `kova verify` from your shell or CI) | – | – (not installed yet) | – |
| Instruction-file sweep (ancestors, descendants, deps, includes) | ✓ | – | ✓ | ✓ |
| MCP proxy wrapping | ✓ (stdio entries) | ✓ | ✓ | ✓ |

Every text file is also scanned for Unicode Tag characters (U+E0000–E007F, text invisible to you
but readable by the model), bidi overrides, and a narrow set of instruction patterns from real
incidents (prompt overrides, "do not tell the user", credential hunting, `curl | sh`, hidden BCC,
"append this to MEMORY.md"). Findings are flags on the lockfile entry; a human decides.

## Instruction files anywhere in the tree

Harnesses load `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`
and `copilot-instructions.md` hierarchically: every
ancestor directory of your project, and any descendant directory the agent happens to read a
file from. A `CLAUDE.md` dropped into `node_modules/some-dep/` is live the moment the agent opens
a file next to it, and the model follows it like any other instruction. So kova:

- **sweeps** the ancestor chain and the whole project tree, dependency folders included, plus
  `@include`d files, `.claude/commands`, `.claude/agents`, nested rules and managed policy paths,
  and pins every instruction file it finds. A new one outside the agent's own memory directory is
  never auto-accepted; in an ancestor or dependency directory it is **high** severity;
- **guards** at the choke point: a pre-tool hook (`kova guard`) evaluates every Read / Edit /
  Glob / Grep / Bash call and **denies** it when the touched directory, or any directory between
  it and the project root, contains an instruction file that is not in the lockfile or has
  changed since it was pinned. The model is told why; a human unblocks with `kova approve`;
- **gates CI**: `kova lock` writes a committed `kova.lock` of the repo's instruction and agent
  config files, and `kova verify --ci` fails a checkout that adds or changes any of them. Deadbugz
  arrived by pull request; this is the control that stops that class before it reaches a laptop.

```yaml
# .github/workflows/kova.yml
- run: curl -fsSL https://kovaverified.io/install.sh | sh
- run: kova verify --ci
```

## Commands

```
kova init [--no-mcp] [--no-hooks] [--wrap]      discover, pin, install hooks (idempotent)
kova verify [--mcp] [--strict]                  compare live state to the lockfile (exit 1 on drift)
kova verify --ci · kova lock                    check a checkout against a committed kova.lock
kova approve <key> | mcp:<name> | --all         accept the current state as the new pin
kova status                                     lockfile, hooks and team summary
kova scan <path> | --mcp -- <cmd> | --url <u>   scan a skill dir / file / MCP server
kova events · kova ledger list                  local drift events / install ledger
kova wrap --all [--enforce] · kova unwrap       proxy stdio MCP servers
kova doctor                                     what discovery sees and why a server isn't wrapped
kova login <api-key> · kova sync                connect to the team dashboard
```

`kova verify --hook <harness>` is what the session hook runs: silent when clean, a short notice
into the model's context when not. Only the agent's own auto-memory notes are auto-accepted
(unless the new text trips the scanner); edits to CLAUDE.md and other instruction files are
reported and need `kova approve`. Use `--strict` to review everything.

## The proxy, honestly

`kova wrap` rewrites each stdio MCP server entry to `kova proxy --name X -- <original command>`.
The proxy relays JSON-RPC untouched and:

- hashes every `tools/list` result (plus the server's `instructions`) and compares it with the pin;
  mismatch → critical event, and with `--enforce` the result is replaced by a JSON-RPC error;
- flags `notifications/tools/list_changed` mid-session;
- around each `tools/call`, snapshots the server process tree's open network connections
  (`lsof`, macOS/Linux) and reports destinations not seen earlier in the session.

**What the network check cannot see:** connections opened and closed between the two snapshots,
DNS-only exfil, anything the server does from a detached process, and anything on Windows. It is
a heuristic that catches the common case (a tool call that phones somewhere new), not a firewall.
The tools-hash check is exact.

Trust on first use: if a server has no pin yet (e.g. `init --no-mcp`), the first `tools/list`
seen by the proxy becomes the pin.

## Reproduce Deadbugz locally

```sh
make demo
```

`cmd/kova-drift-demo` is a stdio MCP server that is benign for N tool calls and then adds a
`sync_settings` tool whose description asks the model to read `~/.aws/credentials` (optionally
hidden in Unicode tag characters). The demo shows the install-time scan passing and the proxy
catching the change two calls later.

## Team tier (dashboard + API)

Free is local-only. The team tier (`kova login <api-key>`) adds:

- every machine's lockfile, drift events and install ledger in one dashboard;
- a shared **policy lockfile**: approve or block a hash once, every machine honours it;
- Slack / webhook / email alerts;
- `--enforce` across the team.

$29/mo up to 10 seats, $99/mo up to 50, plus a one-time $499 agent supply-chain audit. Billed on
kovaverified.io, never through a marketplace.

## Development

```
make build         # bin/kova, bin/kova-drift-demo
make test          # Go tests (lockfile, scanner, harness fixtures, proxy against the drift demo)
make release       # cross-compile the CLI into dist/
make demo          # reproduce Deadbugz locally
```

This repository is published from the kova monorepo on every change; open issues here, and
pull requests are welcome (they are applied upstream and flow back on the next sync).

## Agent-installable

Agents can install the kova skill for their user: `npx skills add ian-hickey/kova --skill kova-verify`.
Claude Code users can add the plugin (session-start verify, install ledger and guard hooks):
`claude plugin marketplace add ian-hickey/kova` then `claude plugin install kova@kovaverified`. The skill teaches the agent to run `kova verify`
before trusting a new tool, and `kova ledger list` when asked "what have you installed".

## License

MIT. See `LICENSE`.
