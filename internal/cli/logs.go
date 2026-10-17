package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ian-hickey/kova/internal/cloud"
	"github.com/ian-hickey/kova/internal/ledger"
	"github.com/ian-hickey/kova/internal/lockfile"
)

func (a *App) cmdEvents(args []string) int {
	fs := newFlags("events")
	limit := fs.Int("limit", 30, "number of most recent events")
	minSev := fs.String("min-severity", "info", "info|low|medium|high|critical")
	if err := fs.Parse(args); err != nil {
		return a.errorf("%v", err)
	}
	evs, err := cloud.Events()
	if err != nil {
		return a.errorf("%v", err)
	}
	min := lockfile.Severity(*minSev)
	var filtered []cloud.EventRecord
	for _, e := range evs {
		if e.Severity.AtLeast(min) {
			filtered = append(filtered, e)
		}
	}
	if len(filtered) > *limit {
		filtered = filtered[len(filtered)-*limit:]
	}
	if a.JSON {
		a.json(filtered)
		return ExitOK
	}
	if len(filtered) == 0 {
		a.printf("no events recorded\n")
		return ExitOK
	}
	for i := len(filtered) - 1; i >= 0; i-- {
		e := filtered[i]
		a.printf("%s  [%-8s] %-28s %s\n", e.At.Local().Format("2006-01-02 15:04"), e.Severity, e.Kind, e.Key)
		a.printf("                              %s\n", e.Message)
	}
	return ExitOK
}

func (a *App) cmdLedger(args []string) int {
	if len(args) == 0 {
		return a.errorf("usage: kova ledger list | kova ledger record --harness <h>")
	}
	switch args[0] {
	case "list":
		return a.ledgerList(args[1:])
	case "record":
		return a.ledgerRecord(args[1:])
	default:
		return a.errorf("unknown ledger subcommand %q", args[0])
	}
}

func (a *App) ledgerList(args []string) int {
	fs := newFlags("ledger list")
	limit := fs.Int("limit", 50, "number of most recent entries")
	if err := fs.Parse(args); err != nil {
		return a.errorf("%v", err)
	}
	rows, err := ledger.All()
	if err != nil {
		return a.errorf("%v", err)
	}
	if len(rows) > *limit {
		rows = rows[len(rows)-*limit:]
	}
	if a.JSON {
		a.json(rows)
		return ExitOK
	}
	if len(rows) == 0 {
		a.printf("ledger is empty — installs run by your agents will appear here once hooks are installed\n")
		return ExitOK
	}
	for i := len(rows) - 1; i >= 0; i-- {
		r := rows[i]
		a.printf("%s  %-11s %-13s %s\n", r.At.Local().Format("2006-01-02 15:04"), r.Harness, r.Installer, r.Package)
		a.printf("                  $ %s\n", ledger.Excerpt(r.Command, 120))
		if r.PromptExcerpt != "" {
			a.printf("                  prompt: %s\n", ledger.Excerpt(r.PromptExcerpt, 120))
		}
	}
	return ExitOK
}

// ledgerRecord is the PreToolUse / BeforeTool / beforeShellExecution hook entrypoint.
// It must be fast, must never block the agent, and must always exit 0.
func (a *App) ledgerRecord(args []string) int {
	fs := newFlags("ledger record")
	harnessName := fs.String("harness", "", "harness that invoked the hook")
	_ = fs.Parse(args)
	defer func() {
		if *harnessName == lockfile.HarnessCursor {
			fmt.Fprintln(a.Stdout, `{"permission": "allow"}`)
		}
	}()
	data, _ := io.ReadAll(io.LimitReader(a.Stdin, 8<<20))
	in := ledger.ParseHookInput(data)
	if in.Command == "" {
		return ExitOK
	}
	matches := ledger.Classify(in.Command)
	if len(matches) == 0 {
		return ExitOK
	}
	prompt := ledger.LastUserPrompt(in.TranscriptPath)
	if in.TranscriptPath == "" && in.SessionID != "" && *harnessName == lockfile.HarnessClaudeCode {
		// Claude Code transcripts live under ~/.claude/projects/<slug>/<session>.jsonl
		cwd := in.CWD
		if cwd == "" {
			cwd = a.CWD
		}
		slug := strings.NewReplacer("/", "-", "\\", "-", ":", "-", " ", "-", ".", "-").Replace(cwd)
		prompt = ledger.LastUserPrompt(filepath.Join(a.Home, ".claude", "projects", slug, in.SessionID+".jsonl"))
	}
	now := time.Now().UTC()
	for _, m := range matches {
		_ = ledger.Append(ledger.Entry{
			ID: ledger.NewID(), At: now, Harness: *harnessName, SessionID: in.SessionID, CWD: in.CWD, Command: in.Command,
			Installer: m.Installer, Package: m.Package, Severity: m.Severity, PromptExcerpt: prompt, TranscriptPath: in.TranscriptPath,
		})
	}
	// Remote-script installs also surface as a drift event so they reach the team feed.
	for _, m := range matches {
		if m.Installer == "remote-script" {
			_ = cloud.RecordEvent(cloud.EventRecord{Source: "ledger", Kind: lockfile.ChangeSuspicious, Severity: lockfile.SevHigh,
				Harness: *harnessName, Key: "ledger:remote-script", Name: ledger.Excerpt(in.Command, 80), Message: "agent piped a remote script into a shell",
				Details: map[string]any{"command": in.Command, "cwd": in.CWD, "session_id": in.SessionID, "prompt": prompt}})
		}
	}
	// Opportunistic, bounded sync so the team feed is near-real-time without slowing the agent.
	if lf, err := a.loadLockfile(); err == nil {
		a.bestEffortSync(lf, nil, "", false, 2*time.Second)
	}
	return ExitOK
}

var _ = os.Getenv
