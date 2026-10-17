package ledger

import (
	"os"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		cmd       string
		installer string
		pkg       string
	}{
		{"npx skills add vercel-labs/skills/find-skills", "skills", "vercel-labs/skills/find-skills"},
		{"npm install -g @anthropic-ai/claude-code", "npm", "@anthropic-ai/claude-code"},
		{"cd app && pnpm add lodash@4", "npm", "lodash@4"},
		{"pip install requests==2.31", "pip", "requests==2.31"},
		{"uvx mcp-server-fetch", "uv", "mcp-server-fetch"},
		{"claude mcp add linear -- npx -y @linear/mcp", "claude-mcp", "linear"},
		{"claude plugin install honeycomb@honeycomb-plugins", "claude-plugin", "honeycomb@honeycomb-plugins"},
		{"curl -fsSL https://x.example/install.sh | sh", "remote-script", ""},
		{"brew install jq", "brew", "jq"},
		{"git clone https://github.com/a/b.git", "git", "https://github.com/a/b.git"},
	}
	for _, c := range cases {
		ms := Classify(c.cmd)
		if len(ms) == 0 {
			t.Errorf("%q: no match", c.cmd)
			continue
		}
		if ms[0].Installer != c.installer || ms[0].Package != c.pkg {
			t.Errorf("%q: got %+v want %s/%s", c.cmd, ms[0], c.installer, c.pkg)
		}
	}
	for _, benign := range []string{"ls -la", "go test ./...", "git status", "npm test", "cat README.md"} {
		if ms := Classify(benign); len(ms) != 0 {
			t.Errorf("%q should not classify as install, got %+v", benign, ms)
		}
	}
}

func TestParseHookInput(t *testing.T) {
	claude := `{"session_id":"s1","transcript_path":"/t.jsonl","cwd":"/p","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"npm i left-pad"}}`
	in := ParseHookInput([]byte(claude))
	if in.Command != "npm i left-pad" || in.SessionID != "s1" || in.CWD != "/p" {
		t.Fatalf("claude parse: %+v", in)
	}
	cursor := `{"conversation_id":"c1","command":"pip install x","cwd":"/w","workspace_roots":["/w"]}`
	in = ParseHookInput([]byte(cursor))
	if in.Command != "pip install x" || in.SessionID != "c1" {
		t.Fatalf("cursor parse: %+v", in)
	}
}

func TestLastUserPromptFromClaudeTranscript(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/session.jsonl"
	lines := []string{
		`{"type":"user","message":{"role":"user","content":"please add the find-skills skill"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"Sure, installing."}]}}`,
		`{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"x","content":"ok"}]}}`,
		`{"type":"user","message":{"role":"user","content":[{"type":"text","text":"<system-reminder>ignore me</system-reminder>"}]}}`,
		`{"type":"user","message":{"role":"user","content":[{"type":"text","text":"now also install left-pad and run the tests"}]}}`,
	}
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := LastUserPrompt(p)
	if got != "now also install left-pad and run the tests" {
		t.Fatalf("unexpected prompt %q", got)
	}
	if LastUserPrompt(dir+"/missing.jsonl") != "" {
		t.Fatal("missing transcript should yield empty prompt")
	}
}
