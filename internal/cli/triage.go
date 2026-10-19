package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ian-hickey/kova/internal/cloud"
	"github.com/ian-hickey/kova/internal/harness"
	"github.com/ian-hickey/kova/internal/lockfile"
	"github.com/ian-hickey/kova/internal/observed"
	"github.com/ian-hickey/kova/internal/redact"
	"github.com/ian-hickey/kova/internal/scan"
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

// diffDetail returns the capped unified diff between a pinned entry's stored text and the live
// entry's content, or "" when either side is missing.
func (a *App) diffDetail(p, l *lockfile.Entry) string {
	if p == nil || l == nil || !instructionType(l.Type) || len(l.Content) == 0 || p.Hash == l.Hash {
		return ""
	}
	prev, ok := lockfile.GetBlob(lockfile.BlobsDirFor(store.LockfilePath()), p.Hash)
	if !ok {
		return ""
	}
	d := textdiff.Unified(filepath.Base(l.Path), string(prev), string(l.Content))
	if d == "" {
		return ""
	}
	return redact.Text(textdiff.Truncate(d, diffEventBytes))
}

// attachDiffs adds a unified diff to every modified instruction-file change whose previous content
// is in the blob store, so the report (and the event) says what changed.
func (a *App) attachDiffs(changes []lockfile.Change, pinned, live map[string]*lockfile.Entry) {
	for i := range changes {
		c := &changes[i]
		if d := a.diffDetail(pinned[c.Key], live[c.Key]); d != "" {
			if c.Details == nil {
				c.Details = map[string]any{}
			}
			c.Details["diff"] = d
		}
	}
}

// observedClean is the guard's escape hatch: a file whose current content was produced by a tool
// call kova watched is not held against the agent, provided the scanner is quiet about it or a
// cached triage verdict already called it benign. Hidden Unicode always blocks.
func (a *App) observedClean(lf *lockfile.Lockfile) func(path, hash string) bool {
	obs := observed.Open(observed.FilePath())
	quiet := a.textClean(lf)
	return func(path, hash string) bool {
		if _, ok := obs.Match(path, hash); !ok {
			return false
		}
		return quiet(path)
	}
}

// textClean is the content half of the guard's escape hatches: the scanner has nothing to say
// about the file, or only keyword matches that a cached triage verdict already called benign.
// Hidden Unicode always fails it.
func (a *App) textClean(lf *lockfile.Lockfile) func(path string) bool {
	var cache *triage.Cache
	return func(path string) bool {
		findings, err := scan.File(path)
		if err != nil {
			return false
		}
		if len(findings) == 0 {
			return true
		}
		for _, f := range findings {
			if f.Rule != "suspicious_content" {
				return false // unicode_tags / bidi / zero_width: never waved through
			}
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		if cache == nil {
			cache = triage.OpenCache(filepath.Join(store.Dir(), "triage.json"))
		}
		// The verdict verify cached: for a modified pin it judged the diff, for a new file the text.
		var items []triage.Item
		for _, e := range lf.Entries {
			if e.Path != "" && filepath.Clean(e.Path) == filepath.Clean(path) {
				if prev, ok := lockfile.GetBlob(lockfile.BlobsDirFor(store.LockfilePath()), e.Hash); ok {
					if d := textdiff.Unified(filepath.Base(path), string(prev), string(data)); d != "" {
						items = append(items, triage.Item{Kind: triage.KindChange, Diff: textdiff.Truncate(d, diffEventBytes)})
					}
				}
			}
		}
		items = append(items, triage.Item{Kind: triage.KindInstruction, Content: string(data)})
		for _, it := range items {
			if v, ok := cache.Get(it.Hash()); ok && v.Malicious <= triage.ClearBelow {
				return true
			}
		}
		return false
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
		case lockfile.ChangeMCPTools:
			descs, _ := c.Details["tool_descriptions"].(map[string]string)
			if len(descs) == 0 {
				continue
			}
			var sb strings.Builder
			for name, d := range descs {
				sb.WriteString("tool " + name + ": " + d + "\n")
			}
			items = append(items, triage.Item{ID: id, Kind: triage.KindMCPTool, Name: l.Name, Content: sb.String()})
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
	pinObserved := func(c lockfile.Change, msg string) {
		c.Kind, c.Severity, c.Message = lockfile.ChangeObservedEdit, lockfile.SevInfo, msg
		delete(c.Details, "observed_clean")
		l := live[c.Key]
		if p := pinned[c.Key]; p != nil {
			l.FirstSeen, l.Approved = p.FirstSeen, p.Approved
		}
		lf.Entries[c.Key] = l
		accepted = append(accepted, c)
	}
	// pinGit accepts content that arrived through git once the classifier has had its look.
	pinGit := func(c lockfile.Change, summary string) {
		sev, _ := c.Details["git_severity"].(string)
		msg, _ := c.Details["git_message"].(string)
		if summary != "" {
			msg = strings.TrimSuffix(msg, "; pinned") + "; " + summary + "; pinned"
		}
		c.Kind, c.Severity, c.Message = lockfile.ChangeGitUpdate, lockfile.Severity(sev), msg
		delete(c.Details, "git_accept")
		delete(c.Details, "git_severity")
		delete(c.Details, "git_message")
		l := live[c.Key]
		if p := pinned[c.Key]; p != nil {
			l.FirstSeen, l.Approved = p.FirstSeen, p.Approved
			lf.MarkSeen(p.Hash, c.Key)
		}
		lf.Entries[c.Key] = l
		lf.MarkSeen(l.Hash, c.Key)
		accepted = append(accepted, c)
	}
	for i, c := range changes {
		observedEdit := c.Details["observed"] == true
		observedClean := c.Details["observed_clean"] == true
		gitAccept := c.Details["git_accept"] == true
		v, ok := byIdx[i]
		if !ok {
			if observedClean {
				// Scanner-clean observed edit the classifier did not get to (timeout): pin it.
				pinObserved(c, "edited by the agent through a tool call kova observed; pinned")
				continue
			}
			if gitAccept {
				pinGit(c, "")
				continue
			}
			kept = append(kept, c)
			continue
		}
		c, downgraded := decideTriage(c, v, pinned[c.Key], live[c.Key])
		if observedClean {
			if v.Malicious >= triage.HighAt {
				kept = append(kept, c) // scored every observed edit: this one is not routine
				continue
			}
			pinObserved(c, "edited by the agent through a tool call kova observed; "+v.Summary()+"; pinned")
			continue
		}
		if gitAccept {
			if v.Malicious >= triage.HighAt {
				delete(c.Details, "git_accept")
				delete(c.Details, "git_severity")
				delete(c.Details, "git_message")
				kept = append(kept, c) // on the remote, but the classifier is confident: a human looks
				continue
			}
			pinGit(c, v.Summary())
			continue
		}
		// The agent's own auto-memory notes carrying an old keyword flag: a benign verdict on the
		// edit settles it the same way an unflagged note would have been (accepted, info).
		if l := live[c.Key]; !downgraded && l != nil && l.Scope == harness.ScopeAutoMemory && v.Malicious <= triage.ClearBelow &&
			(c.Kind == lockfile.ChangeMemory || c.Kind == lockfile.ChangeAdded) {
			downgraded = true
			c.Severity = lockfile.SevInfo
			c.Message += " (auto-memory note; " + v.Summary() + ")"
		}
		if downgraded && (c.Severity == lockfile.SevInfo || observedEdit) {
			// Benign in context: an observed edit is just the agent's work; pin it.
			if observedEdit {
				c.Kind, c.Severity = lockfile.ChangeObservedEdit, lockfile.SevInfo
				c.Message = "edited by the agent through a tool call kova observed; keyword match judged benign (" + v.Summary() + "); pinned"
			}
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

// observedWithoutTriage settles the case the classifier could not: an observed edit that trips a
// keyword rule is a question for a human, not an incident, so it is medium rather than high.
func observedWithoutTriage(changes []lockfile.Change) {
	for i := range changes {
		c := &changes[i]
		if c.Details["observed"] == true && c.Kind == lockfile.ChangeSuspicious && c.Severity == lockfile.SevHigh && c.Details["triage"] == nil {
			c.Severity = lockfile.SevMedium
			c.Message += " (the agent made this edit in a session kova observed; a keyword rule matched: review the diff, or enable `kova triage` to settle these automatically)"
		}
	}
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
		// Uncertain. A keyword escalation is no longer "high" once a calibrated model is unsure;
		// it stays in the needs-review bucket.
		if c.Kind == lockfile.ChangeSuspicious && c.Severity == lockfile.SevHigh {
			c.Severity = lockfile.SevMedium
			c.Message += " — " + v.Summary()
		}
		c.Details["triage"] = v.Map()
		return c, false
	}
}
