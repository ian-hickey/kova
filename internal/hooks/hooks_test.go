package hooks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ian-hickey/kova/internal/lockfile"
)

func TestInstallUninstallRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KOVA_HOME", filepath.Join(home, "state"))
	for _, d := range []string{".claude", ".gemini", ".cursor", ".codex"} {
		_ = os.MkdirAll(filepath.Join(home, d), 0o755)
	}
	orig := `{"permissions":{"allow":["Bash(ls)"]},"hooks":{"PreToolUse":[{"matcher":"Edit","hooks":[{"type":"command","command":"echo edit"}]}]}}`
	_ = os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(orig), 0o644)

	bin := "/opt/kova/kova"
	res, err := Install(home, bin, lockfile.AllHarnesses)
	if err != nil {
		t.Fatal(err)
	}
	installed := map[string]bool{}
	for _, r := range res {
		installed[r.Harness] = r.Installed
	}
	if !installed[lockfile.HarnessClaudeCode] || !installed[lockfile.HarnessGeminiCLI] || !installed[lockfile.HarnessCursor] || installed[lockfile.HarnessCodex] {
		t.Fatalf("unexpected install results: %+v", res)
	}
	// Idempotent: a second install does not duplicate.
	if _, err := Install(home, bin, lockfile.AllHarnesses); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	b, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	_ = json.Unmarshal(b, &m)
	hooks := m["hooks"].(map[string]any)
	if len(hooks["SessionStart"].([]any)) != 1 || len(hooks["PreToolUse"].([]any)) != 3 || len(hooks["PostToolUse"].([]any)) != 1 {
		t.Fatalf("expected 1 SessionStart, 3 PreToolUse and 1 PostToolUse group, got %v", hooks)
	}
	if _, ok := m["permissions"]; !ok {
		t.Fatal("unrelated settings were lost")
	}
	for _, st := range Check(home, bin) {
		if st.Supported && st.Harness != lockfile.HarnessCodex && !st.Installed {
			t.Errorf("%s should report installed", st.Harness)
		}
	}

	if _, err := Uninstall(home, bin, lockfile.AllHarnesses); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	var after map[string]any
	_ = json.Unmarshal(b, &after)
	var want map[string]any
	_ = json.Unmarshal([]byte(orig), &want)
	ab, _ := json.Marshal(after)
	wb, _ := json.Marshal(want)
	if string(ab) != string(wb) {
		t.Fatalf("uninstall did not restore original settings:\n%s\nwant\n%s", ab, wb)
	}
	if _, err := os.Stat(filepath.Join(home, ".cursor", "hooks.json")); !os.IsNotExist(err) {
		t.Fatal("cursor hooks.json should be removed when kova was its only content")
	}
	if _, err := os.Stat(filepath.Join(home, ".gemini", "settings.json")); err != nil {
		t.Fatal("gemini settings.json should remain")
	}
}
