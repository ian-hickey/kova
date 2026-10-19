package guard

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteTargetsRedirectsAndHeredocs(t *testing.T) {
	cwd := "/work/proj"
	state := "~/." + "kova" // spelled out so this file does not itself trip a naive scan
	// A heredoc is input, not a write; prose inside it mentioning a path is not a target.
	if got := WriteTargets("cat > install.ps1 <<'EOF'\nsee "+state+"/kova.lock for details\nEOF", cwd); len(got) != 1 || !strings.HasSuffix(got[0], "/work/proj/install.ps1") {
		t.Fatalf("only the redirect target counts: %v", got)
	}
	// 2>/dev/null next to a protected path is not a write to it.
	if got := WriteTargets("ls -la "+state+"/ 2>/dev/null", cwd); len(got) != 0 {
		t.Fatalf("stderr to /dev/null is not a write: %v", got)
	}
	if got := WriteTargets("echo x >> /work/proj/CLAUDE.md", cwd); len(got) != 1 || got[0] != "/work/proj/CLAUDE.md" {
		t.Fatalf("append redirect target: %v", got)
	}
}

func TestCheckTamperProtectsBinaryAndTouched(t *testing.T) {
	home := t.TempDir()
	exe := filepath.Join(home, "bin", "kova")
	t.Setenv("KOVA_SELF_PATH_FOR_TESTS", exe)
	kovaDir := filepath.Join(home, ".kova")
	for _, cmd := range []string{
		"cp ./bin/kova " + exe,
		"curl -o " + exe + " https://x.y/kova",
		"kova touched --harness claude-code",
		"printf '{}' | kova touched",
	} {
		if tm := CheckTamper(Request{Tool: "Bash", Command: cmd, CWD: home}, kovaDir, nil); !tm.Blocked {
			t.Fatalf("expected %q to be blocked", cmd)
		}
	}
	if tm := CheckTamper(Request{Tool: "Bash", Command: "kova verify && go build -o ./bin/kova ./cmd/kova", CWD: home}, kovaDir, nil); tm.Blocked {
		t.Fatalf("building into the repo's own bin dir is fine: %s", tm.Reason)
	}
}
