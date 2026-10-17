package lockfile

import "testing"

func e(t ArtifactType, name, hash string, flags ...string) *Entry {
	return &Entry{Type: t, Harness: HarnessClaudeCode, Name: name, Hash: hash, Scope: "user", Flags: flags}
}

func TestDiffClassifiesChanges(t *testing.T) {
	pinned := map[string]*Entry{
		"claude-code:skill:a":      e(TypeSkill, "a", "sha256:1"),
		"claude-code:skill:gone":   e(TypeSkill, "gone", "sha256:2"),
		"claude-code:memory:~/m":   e(TypeMemory, "~/m", "sha256:3"),
		"claude-code:hooks:~/s":    e(TypeHooks, "~/s", "sha256:4"),
		"claude-code:mcp_server:x": {Type: TypeMCPServer, Harness: HarnessClaudeCode, Name: "x", Hash: "sha256:c", ConfigHash: "sha256:c", ToolsHash: "sha256:t1", Tools: []Tool{{Name: "a", DescriptionHash: "d", SchemaHash: "s"}}},
	}
	live := map[string]*Entry{
		"claude-code:skill:a":      e(TypeSkill, "a", "sha256:1changed"),
		"claude-code:skill:new":    e(TypeSkill, "new", "sha256:9"),
		"claude-code:skill:evil":   e(TypeSkill, "evil", "sha256:8", "unicode_tags"),
		"claude-code:memory:~/m":   e(TypeMemory, "~/m", "sha256:3b"),
		"claude-code:hooks:~/s":    e(TypeHooks, "~/s", "sha256:4b"),
		"claude-code:mcp_server:x": {Type: TypeMCPServer, Harness: HarnessClaudeCode, Name: "x", Hash: "sha256:c", ConfigHash: "sha256:c", ToolsHash: "sha256:t2", Tools: []Tool{{Name: "a", DescriptionHash: "d", SchemaHash: "s"}, {Name: "sync_settings", DescriptionHash: "z", SchemaHash: "z"}}},
	}
	changes := Diff(pinned, live, nil)
	got := map[string]Change{}
	for _, c := range changes {
		got[c.Key] = c
	}
	want := map[string]struct {
		kind ChangeKind
		sev  Severity
	}{
		"claude-code:skill:a":      {ChangeModified, SevMedium},
		"claude-code:skill:gone":   {ChangeRemoved, SevInfo},
		"claude-code:skill:new":    {ChangeAdded, SevMedium},
		"claude-code:skill:evil":   {ChangeUnicodeTags, SevCritical},
		"claude-code:memory:~/m":   {ChangeMemory, SevLow},
		"claude-code:hooks:~/s":    {ChangeHooks, SevHigh},
		"claude-code:mcp_server:x": {ChangeMCPTools, SevCritical},
	}
	if len(changes) != len(want) {
		t.Fatalf("got %d changes, want %d: %+v", len(changes), len(want), changes)
	}
	for k, w := range want {
		c, ok := got[k]
		if !ok {
			t.Errorf("missing change for %s", k)
			continue
		}
		if c.Kind != w.kind || c.Severity != w.sev {
			t.Errorf("%s: got %s/%s want %s/%s", k, c.Kind, c.Severity, w.kind, w.sev)
		}
	}
	if added, _ := got["claude-code:mcp_server:x"].Details["added_tools"].([]string); len(added) != 1 || added[0] != "sync_settings" {
		t.Errorf("expected sync_settings in added_tools, got %v", got["claude-code:mcp_server:x"].Details)
	}
	// critical first
	if changes[0].Severity != SevCritical {
		t.Errorf("expected critical first, got %s", changes[0].Severity)
	}
}

func TestDiffSkipsInactiveProjects(t *testing.T) {
	pinned := map[string]*Entry{"claude-code:memory:./CLAUDE.md": {Type: TypeMemory, Harness: HarnessClaudeCode, Name: "./CLAUDE.md", Scope: "project", Project: "/p1", Hash: "sha256:1"}}
	if ch := Diff(pinned, map[string]*Entry{}, map[string]bool{"/p2": true}); len(ch) != 0 {
		t.Fatalf("expected no changes for inactive project, got %+v", ch)
	}
	if ch := Diff(pinned, map[string]*Entry{}, map[string]bool{"/p1": true}); len(ch) != 1 || ch[0].Kind != ChangeRemoved {
		t.Fatalf("expected removal for active project, got %+v", ch)
	}
}

func TestCanonicalJSONIsOrderIndependent(t *testing.T) {
	a := HashJSON(map[string]any{"b": 1, "a": []any{map[string]any{"y": 2, "x": 1}}})
	b := HashJSON(map[string]any{"a": []any{map[string]any{"x": 1, "y": 2}}, "b": 1})
	if a != b {
		t.Fatal("canonical hash differs for equivalent objects")
	}
}
