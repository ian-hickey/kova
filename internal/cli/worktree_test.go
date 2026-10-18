package cli

import (
	"testing"
	"time"

	"github.com/ian-hickey/kova/internal/lockfile"
)

func TestMigrateProjectKeysMergesWindowsSpelling(t *testing.T) {
	home := "/Users/ian"
	a := &App{Home: home}
	old := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	lf := &lockfile.Lockfile{Entries: map[string]*lockfile.Entry{
		// Windows-era spelling of a file that a later version re-pinned under the slash spelling.
		`claude-code:hooks:~\ws\ETR\.claude\settings.json`: {Type: lockfile.TypeHooks, Harness: "claude-code",
			Name: `~\ws\ETR\.claude\settings.json`, Path: home + "/ws/ETR/.claude/settings.json", Hash: "sha256:1", FirstSeen: old},
		"claude-code:hooks:~/ws/ETR/.claude/settings.json": {Type: lockfile.TypeHooks, Harness: "claude-code",
			Name: "~/ws/ETR/.claude/settings.json", Path: home + "/ws/ETR/.claude/settings.json", Hash: "sha256:1", FirstSeen: newer},
		// Windows-era spelling with no modern twin: renamed in place.
		`claude-code:memory:~\ws\ETR\CLAUDE.md`: {Type: lockfile.TypeMemory, Harness: "claude-code",
			Name: `~\ws\ETR\CLAUDE.md`, Path: home + "/ws/ETR/CLAUDE.md", Hash: "sha256:2", FirstSeen: old},
		// pre-v0.1.4 "./" spelling.
		"claude-code:memory:./AGENTS.md": {Type: lockfile.TypeMemory, Harness: "claude-code",
			Name: "./AGENTS.md", Path: home + "/ws/ETR/AGENTS.md", Hash: "sha256:3"},
		// Already modern: untouched. An MCP server name is never a path and is untouched too.
		"claude-code:memory:~/ws/ETR/README.md": {Type: lockfile.TypeMemory, Harness: "claude-code",
			Name: "~/ws/ETR/README.md", Path: home + "/ws/ETR/README.md", Hash: "sha256:4"},
		"claude-code:mcp_server:linear": {Type: lockfile.TypeMCPServer, Harness: "claude-code", Name: "linear"},
	}}
	if !a.migrateProjectKeys(lf) {
		t.Fatal("expected a migration")
	}
	want := []string{
		"claude-code:hooks:~/ws/ETR/.claude/settings.json",
		"claude-code:memory:~/ws/ETR/CLAUDE.md",
		"claude-code:memory:~/ws/ETR/AGENTS.md",
		"claude-code:memory:~/ws/ETR/README.md",
		"claude-code:mcp_server:linear",
	}
	if len(lf.Entries) != len(want) {
		t.Fatalf("expected %d entries, got %v", len(want), keysOf(lf.Entries))
	}
	for _, k := range want {
		if lf.Entries[k] == nil {
			t.Fatalf("missing %s in %v", k, keysOf(lf.Entries))
		}
	}
	if got := lf.Entries["claude-code:hooks:~/ws/ETR/.claude/settings.json"].FirstSeen; !got.Equal(old) {
		t.Fatalf("merged entry should keep the older first-seen, got %v", got)
	}
	if lf.Entries["claude-code:memory:~/ws/ETR/CLAUDE.md"].Name != "~/ws/ETR/CLAUDE.md" {
		t.Fatal("renamed entry should carry the new name")
	}
	if a.migrateProjectKeys(lf) {
		t.Fatal("second run must be a no-op")
	}
}

func keysOf(m map[string]*lockfile.Entry) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
