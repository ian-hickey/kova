package cli

import (
	"context"
	"strings"
	"time"

	"github.com/ian-hickey/kova/internal/cloud"
	"github.com/ian-hickey/kova/internal/harness"
)

func (a *App) cmdLogin(args []string) int {
	// Flags may appear before or after the key: `kova login <key> --api-url URL`.
	var key, apiURL string
	enforce := false
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--api-url" && i+1 < len(args):
			apiURL = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--api-url="):
			apiURL = strings.TrimPrefix(args[i], "--api-url=")
		case args[i] == "--enforce":
			enforce = true
		case strings.HasPrefix(args[i], "-"):
			return a.errorf("unknown flag %s", args[i])
		case key == "":
			key = strings.TrimSpace(args[i])
		default:
			return a.errorf("usage: kova login <api-key> [--api-url URL]")
		}
	}
	if key == "" {
		return a.errorf("usage: kova login <api-key> [--api-url URL]  (create a key under API Keys in the dashboard)")
	}
	cfg := cloud.LoadConfig()
	cfg.APIKey = key
	if apiURL != "" {
		cfg.APIURL = strings.TrimRight(apiURL, "/")
	}
	if enforce {
		cfg.Enforce = true
	}
	client := cloud.NewClient(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, err := client.Whoami(ctx)
	if err != nil {
		return a.errorf("key rejected by %s: %v", cfg.APIURL, err)
	}
	if err := cfg.Save(); err != nil {
		return a.errorf("save config: %v", err)
	}
	if lf, err := a.loadLockfile(); err == nil {
		a.bestEffortSync(lf, harness.Present(a.Home), "", true, 8*time.Second)
	}
	if a.JSON {
		a.json(map[string]any{"org": p.Org, "plan": p.Plan, "api_url": cfg.APIURL})
		return ExitOK
	}
	a.printf("✓ Connected to %s (plan: %s) via %s\n", p.Org, p.Plan, cfg.APIURL)
	a.printf("  This machine will now report its lockfile, drift events and install ledger to your team dashboard.\n")
	return ExitOK
}

func (a *App) cmdLogout(args []string) int {
	cfg := cloud.LoadConfig()
	cfg.APIKey = ""
	if err := cfg.Save(); err != nil {
		return a.errorf("%v", err)
	}
	a.printf("Disconnected. Local lockfile, events and ledger are kept.\n")
	return ExitOK
}

func (a *App) cmdSync(args []string) int {
	cfg := cloud.LoadConfig()
	client := cloud.NewClient(cfg)
	if client == nil {
		return a.errorf("not connected — run `kova login <api-key>` first")
	}
	lf, err := a.loadLockfile()
	if err != nil {
		return a.errorf("%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st := loadState()
	if err := client.RegisterMachine(ctx, machineInfo(lf, harness.Present(a.Home), st.LastVerifyStatus)); err != nil {
		return a.errorf("%v", err)
	}
	if err := client.UploadLockfile(ctx, lf); err != nil {
		return a.errorf("%v", err)
	}
	ev, led, err := client.SyncLogs(ctx, lf.MachineID)
	if err != nil {
		return a.errorf("%v", err)
	}
	p, err := client.Policy(ctx)
	if err == nil {
		_ = saveCachedPolicy(p)
	}
	if a.JSON {
		a.json(map[string]any{"events_uploaded": ev, "ledger_uploaded": led, "policy": p})
		return ExitOK
	}
	a.printf("✓ synced: lockfile (%d entries), %d new event(s), %d new ledger row(s)", len(lf.Entries), ev, led)
	if p != nil {
		a.printf("; policy: %d approved, %d blocked", len(p.Approved), len(p.Blocked))
	}
	a.printf("\n")
	return ExitOK
}
