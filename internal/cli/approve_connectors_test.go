package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ian-hickey/kova/internal/lockfile"
	"github.com/ian-hickey/kova/internal/store"
)

// `kova approve --all` must not drop account-connector pins just because approve's discovery
// cannot see them on disk (regression from v0.1.11: approving a key with no live entry deletes it).
func TestApproveAllKeepsConnectorPins(t *testing.T) {
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
	_ = os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers":{}}`), 0o600)
	_ = os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(`{}`), 0o600)
	t.Setenv("KOVA_HOME", filepath.Join(home, ".kova"))
	t.Setenv("HOME", home)
	t.Setenv("KOVA_ALLOW_AGENT_APPROVE", "1")
	t.Setenv("PATH", home) // no `claude` binary: the connector list cannot be refreshed
	var out, errb bytes.Buffer
	a := &App{Stdout: &out, Stderr: &errb, Home: home, CWD: home}
	if code := a.cmdInit([]string{"--no-hooks", "--no-mcp"}); code != ExitOK {
		t.Fatalf("init: %s %s", out.String(), errb.String())
	}
	lf, _ := a.loadLockfile()
	lf.Entries["claude-code:connector:Gmail"] = &lockfile.Entry{Type: lockfile.TypeConnector, Harness: "claude-code", Name: "Gmail",
		Scope: "account", Hash: "sha256:abc", FirstSeen: time.Now(), UpdatedAt: time.Now(), Approved: true}
	if err := lf.Save(store.LockfilePath()); err != nil {
		t.Fatal(err)
	}
	// Create a reason to approve something, then approve everything.
	_ = os.WriteFile(filepath.Join(home, "CLAUDE.md"), []byte("# rules\n"), 0o600)
	if code := a.cmdApprove([]string{"--all"}); code != ExitOK {
		t.Fatalf("approve: %s %s", out.String(), errb.String())
	}
	lf, _ = a.loadLockfile()
	if lf.Entries["claude-code:connector:Gmail"] == nil {
		t.Fatalf("approve --all dropped the connector pin; entries: %v", keysOf(lf.Entries))
	}
}
