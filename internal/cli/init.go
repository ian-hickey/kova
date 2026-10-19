package cli

import (
	"context"
	"fmt"
	"github.com/ian-hickey/kova/internal/triage"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ian-hickey/kova/internal/cloud"
	"github.com/ian-hickey/kova/internal/harness"
	"github.com/ian-hickey/kova/internal/hooks"
	"github.com/ian-hickey/kova/internal/lockfile"
	"github.com/ian-hickey/kova/internal/mcp"
	"github.com/ian-hickey/kova/internal/store"
)

func (a *App) cmdInit(args []string) int {
	fs := newFlags("init")
	noMCP := fs.Bool("no-mcp", false, "do not connect to MCP servers to pin their tool definitions")
	noHooks := fs.Bool("no-hooks", false, "do not install session hooks")
	wrap := fs.Bool("wrap", false, "also route stdio MCP servers through `kova proxy`")
	conn := fs.Bool("connectors", false, "also inventory claude.ai account connectors (`claude mcp list`) now and on every verify")
	mcpTimeout := fs.Duration("mcp-timeout", 25*time.Second, "per-server timeout when pinning tools")
	if err := fs.Parse(args); err != nil {
		return a.errorf("%v", err)
	}

	res, err := a.discover()
	if err != nil {
		return a.errorf("discover: %v", err)
	}
	if len(res.Harnesses) == 0 {
		return a.errorf("no supported agent harness found under %s (looked for ~/.claude, ~/.codex, ~/.gemini, ~/.cursor, ~/.copilot, the VS Code user dir, the Claude Desktop config dir, ~/.codeium/windsurf, Cline/Roo globalStorage)", a.Home)
	}

	lf, err := a.loadLockfile()
	fresh := false
	if err != nil {
		if err != lockfile.ErrNoLockfile {
			return a.errorf("%v", err)
		}
		lf = lockfile.New(generator())
		fresh = true
	}
	lf.Generator = generator()
	a.migrateProjectKeys(lf)
	if a.CWD != "" {
		lf.AddProject(a.CWD)
	}
	if *conn {
		cfg := cloud.LoadConfig()
		cfg.Connectors = true
		if err := cfg.Save(); err != nil {
			return a.errorf("save config: %v", err)
		}
	}
	if _, warn := a.mergeConnectors(res, lf, *conn, false); warn != "" {
		res.Warnings = append(res.Warnings, warn)
	}

	// Merge: new entries are pinned; existing entries keep their pin (verify/approve handle drift).
	added, kept, modified := 0, 0, 0
	for key, live := range res.Entries {
		if pinned, ok := lf.Entries[key]; ok {
			kept++
			if pinned.Hash != live.Hash {
				modified++
			}
			continue
		}
		lf.Entries[key] = live
		added++
	}

	// Pin MCP tool definitions.
	pinnedServers, failedServers := 0, 0
	if !*noMCP && len(res.MCP) > 0 {
		a.printf("Pinning tool definitions from %d MCP server(s)…\n", len(res.MCP))
		results := a.pinMCP(res.MCP, lf, *mcpTimeout, true)
		for _, r := range results {
			if r.err != nil {
				failedServers++
				a.printf("  ✗ %-28s %v\n", r.ref.Harness+":"+r.ref.Name, r.err)
			} else {
				pinnedServers++
				a.printf("  ✓ %-28s %d tools  %s\n", r.ref.Harness+":"+r.ref.Name, r.toolCount, shortHash(r.hash))
			}
		}
	}

	// kova's own skill text must match this binary.
	a.refreshSkill()
	if err := lf.Save(store.LockfilePath()); err != nil {
		return a.errorf("save lockfile: %v", err)
	}

	// Hooks.
	var hookResults []hooks.Status
	if !*noHooks {
		hookResults, err = hooks.Install(a.Home, kovaBin(), res.Harnesses)
		if err != nil {
			return a.errorf("install hooks: %v", err)
		}
	}

	wrapped := 0
	if *wrap {
		n, err := a.wrapServers(res, lf, nil, true, true)
		if err != nil {
			return a.errorf("wrap: %v", err)
		}
		wrapped = n
		if err := lf.Save(store.LockfilePath()); err != nil {
			return a.errorf("save lockfile: %v", err)
		}
	}

	st := loadState()
	st.LastInitAt = time.Now().UTC()
	saveState(st)
	a.bestEffortSync(lf, res.Harnesses, "", true, 6*time.Second)

	if a.JSON {
		a.json(map[string]any{
			"lockfile": store.LockfilePath(), "machine_id": lf.MachineID, "harnesses": res.Harnesses,
			"entries": len(lf.Entries), "added": added, "kept": kept, "modified_since_pin": modified,
			"mcp_pinned": pinnedServers, "mcp_failed": failedServers, "hooks": hookResults, "wrapped": wrapped,
			"warnings": res.Warnings, "flagged": flaggedKeys(res),
		})
		return ExitOK
	}

	a.printf("\n")
	if fresh {
		a.printf("Created %s\n", store.LockfilePath())
	} else {
		a.printf("Updated %s\n", store.LockfilePath())
	}
	a.printf("  harnesses:  %s\n", joinOr(res.Harnesses, "none"))
	a.printf("  pinned:     %d artifacts (%d new, %d already pinned)\n", len(lf.Entries), added, kept)
	a.printSummaryByType(lf)
	if modified > 0 {
		a.printf("  ⚠ %d previously pinned artifact(s) have changed — run `kova verify` to review\n", modified)
	}
	if flagged := flaggedKeys(res); len(flagged) > 0 {
		a.printInitFindings(res, flagged)
	}
	if len(hookResults) > 0 {
		a.printf("\nHooks:\n")
		for _, h := range hookResults {
			switch {
			case h.Installed:
				a.printf("  ✓ %-15s %s\n", h.Harness, h.File)
			case !h.Supported:
				a.printf("  – %-15s %s\n", h.Harness, h.Note)
			default:
				a.printf("  – %-15s %s\n", h.Harness, h.Note)
			}
		}
	}
	if wrapped > 0 {
		a.printf("\nWrapped %d stdio MCP server(s) with `kova proxy`. Restart open agent sessions to pick up the change.\n", wrapped)
	} else if !*wrap && countWrappable(res) > 0 {
		a.printf("\nTip: `kova wrap --all` routes your %d stdio MCP server(s) through the verifying proxy,\n     which catches tool definitions that change mid-session (the Deadbugz pattern).\n", countWrappable(res))
	}
	for _, w := range res.Warnings {
		fmt.Fprintf(a.Stderr, "warning: %s\n", w)
	}
	a.printf("\nNext: `kova status` · `kova verify` · `kova login <api-key>` to share with your team\n")
	return ExitOK
}

func excerptSuffix(e string) string {
	if e == "" {
		return ""
	}
	return " — " + e
}

func flaggedKeys(res *harness.Result) []string {
	var out []string
	for k, e := range res.Entries {
		if len(e.Flags) > 0 {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func countWrappable(res *harness.Result) int {
	n := 0
	for _, r := range res.MCP {
		if r.Wrappable && !r.Wrapped {
			n++
		}
	}
	return n
}

func (a *App) printSummaryByType(lf *lockfile.Lockfile) {
	counts := map[lockfile.ArtifactType]int{}
	for _, e := range lf.Entries {
		counts[e.Type]++
	}
	order := []lockfile.ArtifactType{lockfile.TypeSkill, lockfile.TypePlugin, lockfile.TypeMCPServer, lockfile.TypeHooks, lockfile.TypeMemory, lockfile.TypeRules, lockfile.TypeExtension}
	var parts []string
	for _, t := range order {
		if counts[t] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[t], t))
		}
	}
	if len(parts) > 0 {
		a.printf("              %s\n", joinOr(parts, ""))
	}
}

type pinResult struct {
	ref       harness.MCPRef
	hash      string
	toolCount int
	err       error
}

// pinMCP connects to each server (bounded parallelism) and records tools hashes in lf.
// When onlyUnpinned is true, servers that already have a ToolsHash with unchanged config are skipped.
func (a *App) pinMCP(refs []harness.MCPRef, lf *lockfile.Lockfile, timeout time.Duration, onlyUnpinned bool) []pinResult {
	results := make([]pinResult, len(refs))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, ref := range refs {
		e := lf.Entries[ref.Key]
		if e == nil {
			results[i] = pinResult{ref: ref, err: fmt.Errorf("not in lockfile")}
			continue
		}
		if onlyUnpinned && e.ToolsHash != "" && e.ConfigHash == lockfile.HashJSON(ref.Config) {
			results[i] = pinResult{ref: ref, hash: e.ToolsHash, toolCount: len(e.Tools)}
			continue
		}
		wg.Add(1)
		go func(i int, ref harness.MCPRef, e *lockfile.Entry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			snap, err := mcp.Connect(context.Background(), ref.Config, timeout)
			if err != nil {
				results[i] = pinResult{ref: ref, err: err}
				return
			}
			now := time.Now().UTC()
			e.ToolsHash = snap.ToolsHash
			e.Tools = snap.Pinned
			e.ToolsPinnedAt = &now
			results[i] = pinResult{ref: ref, hash: snap.ToolsHash, toolCount: len(snap.Tools)}
		}(i, ref, e)
	}
	wg.Wait()
	return results
}

var _ = os.Getenv

// printInitFindings reports keyword matches in content that was just pinned. Day one must not
// hand a developer a to-do list: these are informational (the content is pinned as it is and
// only NEW findings are ever reported later), hidden Unicode is the one thing called out loudly,
// and when a classifier is available the excerpts are scored so documentation that merely
// mentions an attack pattern is labelled as such.
func (a *App) printInitFindings(res *harness.Result, flagged []string) {
	var invisible, keyword []string
	for _, k := range flagged {
		if lockfile.HasFlag(res.Entries[k], "unicode_tags") || lockfile.HasFlag(res.Entries[k], "bidi_override") || lockfile.HasFlag(res.Entries[k], "zero_width") {
			invisible = append(invisible, k)
		} else {
			keyword = append(keyword, k)
		}
	}
	if len(invisible) > 0 {
		a.printf("\n  ✗ hidden characters in %d artifact(s) — review before using them:\n", len(invisible))
		for _, k := range invisible {
			a.printf("    - %s\n", k)
			for _, f := range res.Findings[k] {
				a.printf("        %s:%d %s%s\n", f.File, f.Line, f.Detail, excerptSuffix(f.Excerpt))
			}
		}
	}
	if len(keyword) == 0 {
		return
	}
	verdicts := map[string]triage.Verdict{}
	if sc, _ := a.triageScorer(cloud.LoadConfig()); sc != nil {
		var items []triage.Item
		for _, k := range keyword {
			var sb strings.Builder
			for _, f := range res.Findings[k] {
				sb.WriteString(f.File + ":" + fmt.Sprint(f.Line) + " " + f.Excerpt + "\n")
			}
			items = append(items, triage.Item{ID: k, Kind: triage.KindInstruction, Name: k, Content: sb.String()})
		}
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		verdicts, _ = sc.Score(ctx, items)
		cancel()
	}
	benign := 0
	a.printf("\n  keyword matches in %d pinned artifact(s) (informational; pinned as-is, nothing to approve):\n", len(keyword))
	for _, k := range keyword {
		line := "    - " + k + "  [" + joinOr(res.Entries[k].Flags, "") + "]"
		if v, ok := verdicts[k]; ok {
			line += "  AI triage: " + v.Level() + fmt.Sprintf(" (%.2f)", v.Malicious)
			if v.Malicious <= triage.ClearBelow {
				benign++
			}
		}
		a.printf("%s\n", line)
		for _, f := range res.Findings[k] {
			a.printf("        %s:%d %s%s\n", f.File, f.Line, f.Detail, excerptSuffix(f.Excerpt))
		}
	}
	switch {
	case len(verdicts) == 0:
		a.printf("    These are usually docs or tooling that talk about such patterns. `kova scan <path>` shows them in context; `kova triage enable` scores them automatically.\n")
	case benign == len(keyword):
		a.printf("    All judged benign in context: nothing to do.\n")
	default:
		a.printf("    Look at the ones not judged benign; `kova scan <path>` shows them in context.\n")
	}
}
