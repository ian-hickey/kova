package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ian-hickey/kova/internal/cloud"
	"github.com/ian-hickey/kova/internal/lockfile"
	"github.com/ian-hickey/kova/internal/store"
	"github.com/ian-hickey/kova/internal/textdiff"
	"github.com/ian-hickey/kova/internal/triage"
)

// Diff payload caps: what verify prints and ships in an event. Blobs hold the full text.
const (
	diffEventBytes = 3 << 10
	diffPrintLines = 40
)

// cmdTriage: `kova triage status|enable [--key K]|disable`.
func (a *App) cmdTriage(args []string) int {
	fs := newFlags("triage")
	key := fs.String("key", "", "bring-your-own TypeSafe API key (otherwise the team server scores on the org's behalf)")
	if err := fs.Parse(args); err != nil {
		return a.errorf("%v", err)
	}
	rest := fs.Args()
	sub := "status"
	if len(rest) > 0 {
		sub = rest[0]
	}
	cfg := cloud.LoadConfig()
	switch sub {
	case "enable", "on":
		cfg.Triage = "on"
		if *key != "" {
			cfg.TriageKey = *key
		}
		if err := cfg.Save(); err != nil {
			return a.errorf("%v", err)
		}
	case "disable", "off":
		cfg.Triage = "off"
		if err := cfg.Save(); err != nil {
			return a.errorf("%v", err)
		}
	case "status":
	default:
		return a.errorf("usage: kova triage status | enable [--key <typesafe key>] | disable")
	}
	sc, how := a.triageScorer(cfg)
	if a.JSON {
		a.json(map[string]any{"setting": cfg.Triage, "byo_key": cfg.TriageKey != "", "active": sc != nil, "provider": how})
		return ExitOK
	}
	if sc != nil {
		a.printf("AI triage: ON (%s)\n", how)
	} else {
		a.printf("AI triage: OFF (%s)\n", how)
	}
	a.printf("  What it does: after kova's own checks, new or changed instruction files, hook commands and unknown\n" +
		"  install commands are scored by a calibrated classifier (TypeSafe Jev). A confident \"malicious\" raises\n" +
		"  the change to high; a confident \"benign\" on a keyword match drops the keyword escalation. It never\n" +
		"  approves anything by itself.\n" +
		"  What leaves this machine: the diff of the changed file (or the new file / hook command / shell command),\n" +
		"  sent to kovaverified.io and scored there for Team orgs, or straight to api.typesafe.ai with --key.\n")
	if sc == nil {
		a.printf("  Turn on: `kova triage enable` (Team org with triage enabled in the dashboard) or\n            `kova triage enable --key <typesafe key>` for a personal key.\n")
	}
	return ExitOK
}

// triageScorer resolves the provider: an explicit off wins; a bring-your-own key scores directly;
// otherwise a Team org whose admin turned triage on scores through the kova API (no TypeSafe
// account needed). The string explains the choice for `kova triage status`.
func (a *App) triageScorer(cfg cloud.Config) (triage.Scorer, string) {
	if cfg.Triage == "off" {
		return nil, "disabled with `kova triage disable`"
	}
	cache := triage.OpenCache(filepath.Join(store.Dir(), "triage.json"))
	if cfg.Triage == "on" && cfg.TriageKey != "" {
		return triage.Cached{Scorer: triage.NewTypeSafe(cfg.TriageKey), Cache: cache}, "your own TypeSafe key, scored directly by api.typesafe.ai"
	}
	pol := loadCachedPolicy()
	if pol != nil && pol.Triage.Enabled && cfg.APIKey != "" {
		if client := cloud.NewClient(cfg); client != nil {
			return triage.Cached{Scorer: client, Cache: cache}, "enabled for " + pol.Org + ", scored by the kova team server"
		}
	}
	if cfg.Triage == "on" {
		if cfg.APIKey == "" {
			return nil, "enabled here, but there is no key: pass --key or `kova login` to a Team org with triage on"
		}
		return nil, "enabled here, but the org has not turned it on (dashboard → Team → AI triage) and no --key was given"
	}
	return nil, "not enabled"
}

// instructionType reports the single-file instruction artifacts kova keeps blobs for.
func instructionType(t lockfile.ArtifactType) bool {
	switch t {
	case lockfile.TypeMemory, lockfile.TypeRules, lockfile.TypeCommand, lockfile.TypeAgent:
		return true
	}
	return false
}

// attachDiffs adds a unified diff to every modified instruction-file change whose previous content
// is in the blob store, so the report (and the event) says what changed.
func (a *App) attachDiffs(changes []lockfile.Change, pinned, live map[string]*lockfile.Entry) {
	dir := lockfile.BlobsDirFor(store.LockfilePath())
	for i := range changes {
		c := &changes[i]
		p, l := pinned[c.Key], live[c.Key]
		if p == nil || l == nil || !instructionType(l.Type) || len(l.Content) == 0 || p.Hash == l.Hash {
			continue
		}
		prev, ok := lockfile.GetBlob(dir, p.Hash)
		if !ok {
			continue
		}
		d := textdiff.Unified(filepath.Base(l.Path), string(prev), string(l.Content))
		if d == "" {
			continue
		}
		if c.Details == nil {
			c.Details = map[string]any{}
		}
		c.Details["diff"] = textdiff.Truncate(d, diffEventBytes)
	}
}

// triageItems picks the changes the classifier can help with and builds their inputs.
func triageItems(changes []lockfile.Change, pinned, live map[string]*lockfile.Entry) []triage.Item {
	var items []triage.Item
	for i, c := range changes {
		l := live[c.Key]
		if l == nil {
			continue
		}
		id := fmt.Sprintf("%d", i)
		switch c.Kind {
		case lockfile.ChangeAdded, lockfile.ChangeInstructionAdded, lockfile.ChangeModified, lockfile.ChangeMemory, lockfile.ChangeSuspicious:
			if !instructionType(l.Type) || len(l.Content) == 0 {
				continue
			}
			if d, ok := c.Details["diff"].(string); ok && d != "" && pinned[c.Key] != nil {
				items = append(items, triage.Item{ID: id, Kind: triage.KindChange, Name: filepath.Base(l.Path), Diff: d})
			} else {
				items = append(items, triage.Item{ID: id, Kind: triage.KindInstruction, Name: filepath.Base(l.Path), Content: string(l.Content)})
			}
		case lockfile.ChangeHooks:
			if len(l.Hooks) == 0 {
				continue
			}
			content := string(l.Hooks)
			if added, ok := c.Details["added_commands"].([]string); ok && len(added) > 0 {
				content = strings.Join(added, "\n")
			}
			items = append(items, triage.Item{ID: id, Kind: triage.KindHook, Name: filepath.Base(l.Path), Content: content})
		}
	}
	return items
}

// applyTriage scores the candidate changes and moves severities. Returns the changes to keep and
// any that became informational (and were pinned). Never fails verify: no scorer or a timeout
// simply leaves the deterministic result alone.
func (a *App) applyTriage(changes []lockfile.Change, pinned, live map[string]*lockfile.Entry, lf *lockfile.Lockfile, hookMode bool) (kept, accepted []lockfile.Change) {
	sc, _ := a.triageScorer(cloud.LoadConfig())
	if sc == nil || len(changes) == 0 {
		return changes, nil
	}
	items := triageItems(changes, pinned, live)
	if len(items) == 0 {
		return changes, nil
	}
	budget := 12 * time.Second
	if hookMode {
		budget = 4 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	verdicts, err := sc.Score(ctx, items)
	if err != nil && len(verdicts) == 0 {
		fmt.Fprintf(a.Stderr, "kova: triage unavailable: %v\n", err)
		return changes, nil
	}
	byIdx := map[int]triage.Verdict{}
	for _, it := range items {
		if v, ok := verdicts[it.ID]; ok {
			var idx int
			fmt.Sscanf(it.ID, "%d", &idx)
			byIdx[idx] = v
		}
	}
	for i, c := range changes {
		v, ok := byIdx[i]
		if !ok {
			kept = append(kept, c)
			continue
		}
		c, downgraded := decideTriage(c, v, pinned[c.Key], live[c.Key])
		if downgraded && c.Severity == lockfile.SevInfo {
			l := live[c.Key]
			if p := pinned[c.Key]; p != nil {
				l.FirstSeen, l.Approved = p.FirstSeen, p.Approved
			}
			lf.Entries[c.Key] = l
			accepted = append(accepted, c)
			continue
		}
		kept = append(kept, c)
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].Severity.Rank() > kept[j].Severity.Rank() })
	return kept, accepted
}

// decideTriage applies a verdict to one change. Pure, so it is unit-tested.
//   - confident malicious: raise to high (critical stays critical) and label the change suspicious;
//   - confident benign on a keyword escalation: fall back to the deterministic base change
//     (the keyword matched documentation, not an instruction); hidden-Unicode findings are never cleared;
//   - anything else: attach the scores and leave the severity alone.
func decideTriage(c lockfile.Change, v triage.Verdict, p, l *lockfile.Entry) (lockfile.Change, bool) {
	if c.Details == nil {
		c.Details = map[string]any{}
	}
	switch {
	case v.Malicious >= triage.HighAt:
		if c.Severity.Rank() < lockfile.SevHigh.Rank() {
			c.Severity = lockfile.SevHigh
		}
		switch c.Kind {
		case lockfile.ChangeAdded, lockfile.ChangeInstructionAdded, lockfile.ChangeModified, lockfile.ChangeMemory:
			c.Kind = lockfile.ChangeSuspicious
		}
		c.Message += " — " + v.Summary()
		c.Details["triage"] = v.Map()
		return c, false
	case v.Malicious <= triage.ClearBelow && c.Kind == lockfile.ChangeSuspicious && l != nil && !lockfile.HasFlag(l, "unicode_tags"):
		base, ok := lockfile.BaseChange(c.Key, p, l)
		if !ok {
			return c, false
		}
		for k, val := range c.Details {
			if base.Details == nil {
				base.Details = map[string]any{}
			}
			if _, exists := base.Details[k]; !exists && k != "findings" {
				base.Details[k] = val
			}
		}
		base.Message += " (keyword match judged benign in context: " + v.Summary() + ")"
		base.Details["triage"] = v.Map()
		return base, true
	default:
		c.Details["triage"] = v.Map()
		return c, false
	}
}
