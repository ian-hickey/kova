// Package cli implements the `kova` command.
package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ian-hickey/kova/internal/cloud"
	"github.com/ian-hickey/kova/internal/harness"
	"github.com/ian-hickey/kova/internal/lockfile"
	"github.com/ian-hickey/kova/internal/store"
)

// Version is set at build time with -ldflags "-X github.com/ian-hickey/kova/internal/cli.Version=x.y.z".
var Version = "0.1.0-dev"

// Exit codes.
const (
	ExitOK    = 0
	ExitDrift = 1
	ExitError = 2
)

// App carries IO and shared state for a command invocation.
type App struct {
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader
	Home   string
	CWD    string
	JSON   bool
	Quiet  bool
}

const usage = `kova — the lockfile for agent tools

Pins every skill, plugin, MCP server, hook and memory file your coding agents load,
re-verifies them at session start, proxies MCP servers to catch tool definitions that
change after install, and keeps a ledger of what your agents installed and why.

Usage:
  kova init [--no-mcp] [--no-hooks] [--wrap] [--connectors]  discover, pin, install hooks (idempotent)
  kova verify [--mcp] [--strict] [--hook <harness>] compare live state to the lockfile
  kova verify --ci                                 check a checkout against ./kova.lock (for CI)
  kova lock                                        write ./kova.lock for this repo (commit it)
  kova guard --harness <h>                         (hook entrypoint; denies tool calls that would load unreviewed instruction files)
  kova approve <key|mcp:name>... | --all          accept current state as the new pin
  kova status                                      lockfile, hooks and cloud summary
  kova doctor                                      what discovery sees: harnesses, MCP config files, why a server is or is not wrapped
  kova connectors [--enable|--disable|--refresh]   inventory claude.ai account connectors (via claude mcp list) and pin them
  kova upgrade [--version vX.Y.Z]                  replace this binary with the latest GitHub release (checksum verified)
  kova triage status|enable [--key K]|disable      optional AI second opinion on changed instruction files, hooks, installs
  kova scan <path> | --mcp -- <cmd> [args]         scan a skill dir / file / MCP server
  kova events [--limit N]                          local drift events
  kova ledger list [--limit N]                     what your agents installed
  kova ledger record --harness <h>                 (hook entrypoint; reads hook JSON on stdin)
  kova proxy --name <n> [--enforce] -- <cmd>...    (MCP stdio proxy entrypoint)
  kova wrap [--all | <name>...] [--harness h]      route stdio MCP servers through the proxy
  kova unwrap [--all | <name>...]                  restore original MCP configs
  kova hooks install|uninstall|status [--harness h]
  kova login <api-key> [--api-url URL]             connect this machine to your team
  kova logout | kova sync                          team sync (lockfile, events, ledger, policy)
  kova version

Global flags: --json  --cwd <dir>  --quiet
Harnesses: claude-code, codex, gemini-cli, cursor, github-copilot, claude-desktop, windsurf, cline.
Hooks are installed for claude-code, gemini-cli and cursor.  State lives in ~/.kova (or $KOVA_HOME).
`

// Main is the entrypoint used by cmd/kova.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	app := &App{Stdout: stdout, Stderr: stderr, Stdin: stdin}
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(stderr, "kova: cannot determine home directory:", err)
		return ExitError
	}
	app.Home = home
	if cwd, err := os.Getwd(); err == nil {
		app.CWD = cwd
	}

	// Pull out global flags wherever they appear.
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json":
			app.JSON = true
		case a == "--quiet" || a == "-q":
			app.Quiet = true
		case a == "--cwd" && i+1 < len(args):
			app.CWD = args[i+1]
			i++
		case strings.HasPrefix(a, "--cwd="):
			app.CWD = strings.TrimPrefix(a, "--cwd=")
		case a == "--":
			rest = append(rest, args[i:]...)
			i = len(args)
		default:
			rest = append(rest, a)
		}
	}
	if abs, err := filepath.Abs(app.CWD); err == nil {
		app.CWD = abs
	}
	if len(rest) == 0 {
		fmt.Fprint(stdout, usage)
		return ExitOK
	}
	cmd, cmdArgs := rest[0], rest[1:]
	var code int
	switch cmd {
	case "init":
		code = app.cmdInit(cmdArgs)
	case "verify", "check":
		code = app.cmdVerify(cmdArgs)
	case "lock":
		code = app.cmdLock(cmdArgs)
	case "guard":
		code = app.cmdGuard(cmdArgs)
	case "approve", "accept", "update":
		code = app.cmdApprove(cmdArgs)
	case "status":
		code = app.cmdStatus(cmdArgs)
	case "doctor":
		code = app.cmdDoctor(cmdArgs)
	case "connectors":
		code = app.cmdConnectors(cmdArgs)
	case "upgrade", "update-self", "self-update":
		code = app.cmdUpgrade(cmdArgs)
	case "triage":
		code = app.cmdTriage(cmdArgs)
	case "scan":
		code = app.cmdScan(cmdArgs)
	case "events":
		code = app.cmdEvents(cmdArgs)
	case "ledger":
		code = app.cmdLedger(cmdArgs)
	case "proxy":
		code = app.cmdProxy(cmdArgs)
	case "wrap":
		code = app.cmdWrap(cmdArgs, true)
	case "unwrap":
		code = app.cmdWrap(cmdArgs, false)
	case "hooks":
		code = app.cmdHooks(cmdArgs)
	case "login":
		code = app.cmdLogin(cmdArgs)
	case "logout":
		code = app.cmdLogout(cmdArgs)
	case "sync":
		code = app.cmdSync(cmdArgs)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "kova %s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "kova: unknown command %q\n\n%s", cmd, usage)
		code = ExitError
	}
	return code
}

// ───────────────────────────── shared helpers ─────────────────────────────

func (a *App) errorf(format string, args ...any) int {
	fmt.Fprintf(a.Stderr, "kova: "+format+"\n", args...)
	return ExitError
}

func (a *App) printf(format string, args ...any) {
	if a.Quiet {
		return
	}
	fmt.Fprintf(a.Stdout, format, args...)
}

func (a *App) json(v any) {
	enc := json.NewEncoder(a.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// kovaBin returns the absolute path of the running binary for use in hooks and wrapped configs.
func kovaBin() string {
	if v := os.Getenv("KOVA_BIN"); v != "" {
		return v
	}
	exe, err := os.Executable()
	if err != nil {
		return "kova"
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	return exe
}

func (a *App) discover() (*harness.Result, error) {
	return harness.Discover(harness.Options{Home: a.Home, CWD: a.CWD, KovaBinary: kovaBin()})
}

func (a *App) loadLockfile() (*lockfile.Lockfile, error) {
	lf, err := lockfile.Load(store.LockfilePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, lockfile.ErrNoLockfile
		}
		return nil, err
	}
	return lf, nil
}

func generator() string { return "kova " + Version }

func machineInfo(lf *lockfile.Lockfile, harnesses []string, status string) cloud.MachineInfo {
	host, _ := os.Hostname()
	uname := ""
	if u, err := user.Current(); err == nil {
		uname = u.Username
	}
	return cloud.MachineInfo{
		MachineID: lf.MachineID, Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH, Username: uname,
		CLIVersion: Version, Harnesses: harnesses, EntryCount: len(lf.Entries), LastVerifyStatus: status,
	}
}

// bestEffortSync registers the machine and uploads logs, bounded by timeout. Errors are reported
// to stderr only; sync must never make a hook fail.
func (a *App) bestEffortSync(lf *lockfile.Lockfile, harnesses []string, status string, uploadLockfile bool, timeout time.Duration) {
	cfg := cloud.LoadConfig()
	client := cloud.NewClient(cfg)
	if client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := client.RegisterMachine(ctx, machineInfo(lf, harnesses, status)); err != nil {
		fmt.Fprintf(a.Stderr, "kova: sync (machine): %v\n", err)
		return
	}
	if uploadLockfile {
		if err := client.UploadLockfile(ctx, lf); err != nil {
			fmt.Fprintf(a.Stderr, "kova: sync (lockfile): %v\n", err)
		}
	}
	if _, _, err := client.SyncLogs(ctx, lf.MachineID); err != nil {
		fmt.Fprintf(a.Stderr, "kova: sync (logs): %v\n", err)
	}
	if p, err := client.Policy(ctx); err == nil {
		_ = store.WriteJSON(filepath.Join(store.Dir(), "policy.json"), p)
	}
}

func loadCachedPolicy() *cloud.Policy {
	var p cloud.Policy
	if err := store.ReadJSON(filepath.Join(store.Dir(), "policy.json"), &p); err != nil {
		return nil
	}
	return &p
}

type stateFile struct {
	LastVerifyAt     time.Time `json:"last_verify_at"`
	LastVerifyStatus string    `json:"last_verify_status"`
	LastVerifyCount  int       `json:"last_verify_changes"`
	LastInitAt       time.Time `json:"last_init_at"`
}

func statePath() string { return filepath.Join(store.Dir(), "state.json") }

func loadState() stateFile {
	var s stateFile
	_ = store.ReadJSON(statePath(), &s)
	return s
}

func saveState(s stateFile) { _ = store.WriteJSON(statePath(), s) }

func shortHash(h string) string {
	h = strings.TrimPrefix(h, "sha256:")
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func joinOr(xs []string, empty string) string {
	if len(xs) == 0 {
		return empty
	}
	return strings.Join(xs, ", ")
}

func saveCachedPolicy(p *cloud.Policy) error {
	return store.WriteJSON(filepath.Join(store.Dir(), "policy.json"), p)
}
