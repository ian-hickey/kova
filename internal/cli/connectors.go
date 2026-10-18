package cli

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/ian-hickey/kova/internal/cloud"
	"github.com/ian-hickey/kova/internal/connectors"
	"github.com/ian-hickey/kova/internal/harness"
	"github.com/ian-hickey/kova/internal/lockfile"
	"github.com/ian-hickey/kova/internal/store"
)

// How long a session-start hook may trust the cached connector list before re-running
// `claude mcp list` (which probes every server and takes seconds).
const connectorMaxAge = 6 * time.Hour

func loadConnectorCache() connectors.Cache {
	var c connectors.Cache
	_ = store.ReadJSON(store.ConnectorsPath(), &c)
	return c
}

// mergeConnectors adds the claude.ai account-connector inventory to a discovery result when it is
// enabled (config) or forced. In hook mode a cache younger than connectorMaxAge is used so session
// start is not slowed down. Whenever the list cannot be refreshed, pinned connectors are carried
// into the live set so they are not reported as removed. Returns whether a fresh list was fetched
// and a warning for the user when it was not.
func (a *App) mergeConnectors(disc *harness.Result, lf *lockfile.Lockfile, force, hookMode bool) (bool, string) {
	carry := func() {
		if lf == nil {
			return
		}
		for k, e := range lf.Entries {
			if e.Type == lockfile.TypeConnector {
				if _, ok := disc.Entries[k]; !ok {
					disc.Entries[k] = e
				}
			}
		}
	}
	if !cloud.LoadConfig().Connectors && !force {
		carry()
		return false, ""
	}
	cache := loadConnectorCache()
	maxAge := time.Duration(0)
	if hookMode {
		maxAge = connectorMaxAge
	}
	refreshed, warn := false, ""
	if cache.RefreshedAt.IsZero() || time.Since(cache.RefreshedAt) >= maxAge || cache.Error != "" {
		timeout := 30 * time.Second
		if hookMode {
			timeout = 15 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		list, src, err := connectors.List(ctx)
		cancel()
		if err != nil {
			warn = "account connectors not refreshed: " + err.Error()
			if cache.RefreshedAt.IsZero() {
				carry()
				return false, warn
			}
			warn += fmt.Sprintf(" (using the list from %s)", cache.RefreshedAt.Local().Format("2006-01-02 15:04"))
		} else {
			cache = connectors.Cache{RefreshedAt: time.Now().UTC(), Source: src, Connectors: list}
			_ = store.WriteJSON(store.ConnectorsPath(), cache)
			refreshed = true
		}
	}
	now := time.Now().UTC()
	for k, e := range connectors.Entries(cache.Connectors, now) {
		if prev, ok := lf.Entries[k]; ok && lf != nil {
			e.FirstSeen, e.Approved = prev.FirstSeen, prev.Approved
		}
		disc.Entries[k] = e
	}
	return refreshed, warn
}

// cmdConnectors shows, enables, disables or refreshes the account-connector inventory.
func (a *App) cmdConnectors(args []string) int {
	fs := newFlags("connectors")
	enable := fs.Bool("enable", false, "inventory account connectors on every verify and pin the current ones")
	disable := fs.Bool("disable", false, "stop inventorying account connectors (existing pins stay until removed with kova approve)")
	refresh := fs.Bool("refresh", false, "re-run `claude mcp list` now")
	if err := fs.Parse(args); err != nil {
		return a.errorf("%v", err)
	}
	cfg := cloud.LoadConfig()
	if *enable || *disable {
		cfg.Connectors = *enable
		if err := cfg.Save(); err != nil {
			return a.errorf("save config: %v", err)
		}
	}
	lf, err := a.loadLockfile()
	if err != nil && err != lockfile.ErrNoLockfile {
		return a.errorf("%v", err)
	}
	if lf == nil {
		lf = lockfile.New(generator())
	}

	cache := loadConnectorCache()
	warn := ""
	if *enable || *refresh || (cfg.Connectors && cache.RefreshedAt.IsZero()) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		list, src, lerr := connectors.List(ctx)
		cancel()
		if lerr != nil {
			warn = lerr.Error()
		} else {
			cache = connectors.Cache{RefreshedAt: time.Now().UTC(), Source: src, Connectors: list}
			_ = store.WriteJSON(store.ConnectorsPath(), cache)
		}
	}

	// Pin on enable: new connectors become part of the lockfile without a separate approve.
	pinnedNow := 0
	if *enable && len(cache.Connectors) > 0 {
		for k, e := range connectors.Entries(cache.Connectors, time.Now().UTC()) {
			if _, ok := lf.Entries[k]; !ok {
				lf.Entries[k] = e
				pinnedNow++
			}
		}
		if pinnedNow > 0 {
			if err := lf.Save(store.LockfilePath()); err != nil {
				return a.errorf("save lockfile: %v", err)
			}
		}
	}

	type row struct {
		Name, URL, Status string
		Pinned            bool
		Hash              string
	}
	var rows []row
	for _, c := range cache.Connectors {
		e := lf.Entries[connectors.Key(c.Name)]
		r := row{Name: c.Name, URL: c.URL, Status: c.Status, Pinned: e != nil}
		if e != nil {
			r.Hash = e.Hash
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })

	if a.JSON {
		a.json(map[string]any{"enabled": cfg.Connectors, "refreshed_at": cache.RefreshedAt, "connectors": rows, "pinned_now": pinnedNow, "warning": warn})
		return ExitOK
	}
	state := "disabled"
	if cfg.Connectors {
		state = "enabled (inventoried on every verify; session hooks reuse a list younger than 6h)"
	}
	a.printf("Account connectors: %s\n", state)
	if warn != "" {
		a.printf("  ! %s\n", warn)
	}
	if cache.RefreshedAt.IsZero() {
		a.printf("  no inventory yet; run `kova connectors --enable` (needs the `claude` CLI on PATH)\n")
		return ExitOK
	}
	a.printf("  listed %s via %s\n\n", cache.RefreshedAt.Local().Format("2006-01-02 15:04"), cache.Source)
	for _, r := range rows {
		mark := "–"
		if r.Pinned {
			mark = "✓"
		}
		a.printf("  %s %-22s %-11s %s\n", mark, r.Name, r.Status, r.URL)
	}
	if pinnedNow > 0 {
		a.printf("\n%d connector(s) pinned. A new, removed or re-pointed connector now shows up in `kova verify` as connector_added / connector_removed / connector_changed.\n", pinnedNow)
	} else if !cfg.Connectors {
		a.printf("\nRun `kova connectors --enable` to pin these and watch for changes.\n")
	}
	a.printf("\nConnectors are account-level and remote: kova can pin which ones exist and where they point, not their tool definitions (those need the account's OAuth token).\n")
	return ExitOK
}
