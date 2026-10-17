package cli

import (
	"sort"
	"time"

	"github.com/ian-hickey/kova/internal/cloud"
	"github.com/ian-hickey/kova/internal/harness"
	"github.com/ian-hickey/kova/internal/hooks"
	"github.com/ian-hickey/kova/internal/lockfile"
	"github.com/ian-hickey/kova/internal/store"
)

func (a *App) cmdStatus(args []string) int {
	lf, err := a.loadLockfile()
	if err != nil {
		if err == lockfile.ErrNoLockfile {
			a.printf("No lockfile at %s. Run `kova init`.\n", store.LockfilePath())
			return ExitOK
		}
		return a.errorf("%v", err)
	}
	present := harness.Present(a.Home)
	hk := hooks.Check(a.Home, kovaBin())
	cfg := cloud.LoadConfig()
	st := loadState()
	events, _ := cloud.Events()

	byHarness := map[string]map[lockfile.ArtifactType]int{}
	wrapped, mcpPinned, mcpTotal, flagged := 0, 0, 0, 0
	for _, e := range lf.Entries {
		if byHarness[e.Harness] == nil {
			byHarness[e.Harness] = map[lockfile.ArtifactType]int{}
		}
		byHarness[e.Harness][e.Type]++
		if e.Type == lockfile.TypeMCPServer {
			mcpTotal++
			if e.ToolsHash != "" {
				mcpPinned++
			}
			if e.Wrapped != nil {
				wrapped++
			}
		}
		if len(e.Flags) > 0 {
			flagged++
		}
	}

	if a.JSON {
		a.json(map[string]any{
			"lockfile": store.LockfilePath(), "machine_id": lf.MachineID, "generated_at": lf.GeneratedAt, "updated_at": lf.UpdatedAt,
			"entries": len(lf.Entries), "projects": lf.Projects, "harnesses_present": present, "by_harness": byHarness,
			"mcp_servers": mcpTotal, "mcp_pinned": mcpPinned, "mcp_wrapped": wrapped, "flagged": flagged,
			"hooks": hk, "cloud": map[string]any{"connected": cfg.APIKey != "", "api_url": cfg.APIURL, "enforce": cfg.Enforce, "net_watch": cfg.NetWatch},
			"last_verify": st, "events": len(events),
		})
		return ExitOK
	}

	a.printf("kova %s\n\n", Version)
	a.printf("Lockfile   %s\n", store.LockfilePath())
	a.printf("Machine    %s\n", lf.MachineID)
	a.printf("Pinned     %d artifacts, updated %s\n", len(lf.Entries), ago(lf.UpdatedAt))
	hs := make([]string, 0, len(byHarness))
	for h := range byHarness {
		hs = append(hs, h)
	}
	sort.Strings(hs)
	for _, h := range hs {
		counts := byHarness[h]
		a.printf("  %-12s", h)
		for _, t := range []lockfile.ArtifactType{lockfile.TypeSkill, lockfile.TypePlugin, lockfile.TypeMCPServer, lockfile.TypeHooks, lockfile.TypeMemory, lockfile.TypeRules, lockfile.TypeExtension} {
			if counts[t] > 0 {
				a.printf(" %d %s", counts[t], t)
			}
		}
		a.printf("\n")
	}
	a.printf("MCP        %d servers, %d with pinned tool definitions, %d routed through proxy\n", mcpTotal, mcpPinned, wrapped)
	if flagged > 0 {
		a.printf("Flagged    %d artifact(s) carry content-scan flags (see `kova verify`)\n", flagged)
	}
	a.printf("Projects   %d inited\n", len(lf.Projects))

	a.printf("\nHooks\n")
	for _, h := range hk {
		switch {
		case h.Installed:
			a.printf("  ✓ %-12s installed (%s)\n", h.Harness, h.File)
		case !h.Supported:
			a.printf("  – %-12s not supported by harness\n", h.Harness)
		case !contains(present, h.Harness):
			a.printf("  – %-12s harness not present\n", h.Harness)
		default:
			a.printf("  ✗ %-12s not installed — `kova hooks install --harness %s`\n", h.Harness, h.Harness)
		}
	}

	a.printf("\nLast verify  ")
	if st.LastVerifyAt.IsZero() {
		a.printf("never\n")
	} else {
		a.printf("%s — %s (%d change(s))\n", ago(st.LastVerifyAt), st.LastVerifyStatus, st.LastVerifyCount)
	}
	a.printf("Events       %d recorded locally (`kova events`)\n", len(events))
	a.printf("\nTeam         ")
	if cfg.APIKey == "" {
		a.printf("not connected — `kova login <api-key>` to sync with your team dashboard\n")
	} else {
		a.printf("connected to %s (enforce=%v, net-watch=%v)\n", cfg.APIURL, cfg.Enforce, cfg.NetWatch)
	}
	return ExitOK
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return time.Duration(d.Minutes()).String() + "m ago"
	case d < 48*time.Hour:
		return time.Duration(d.Hours()).String() + "h ago"
	default:
		return t.Format("2006-01-02")
	}
}
