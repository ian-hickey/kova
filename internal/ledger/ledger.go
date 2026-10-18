// Package ledger records which agent session installed what, when, and the prompt that caused it.
// It runs as a pre-tool hook on shell commands and never blocks: it observes.
package ledger

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ian-hickey/kova/internal/lockfile"
	"github.com/ian-hickey/kova/internal/store"
)

// Entry is one recorded install.
type Entry struct {
	ID             string            `json:"id"`
	At             time.Time         `json:"at"`
	Harness        string            `json:"harness"`
	SessionID      string            `json:"session_id,omitempty"`
	CWD            string            `json:"cwd,omitempty"`
	Command        string            `json:"command"`
	Installer      string            `json:"installer"`
	Package        string            `json:"package,omitempty"`
	Severity       lockfile.Severity `json:"severity"`
	PromptExcerpt  string            `json:"prompt_excerpt,omitempty"`
	TranscriptPath string            `json:"transcript_path,omitempty"`
}

// HookInput is the subset of hook stdin JSON we care about, across harnesses.
type HookInput struct {
	SessionID      string
	TranscriptPath string
	CWD            string
	HookEvent      string
	ToolName       string
	Command        string
}

// ParseHookInput accepts Claude Code, Gemini CLI and Cursor hook payloads.
func ParseHookInput(data []byte) HookInput {
	var raw map[string]any
	_ = json.Unmarshal(data, &raw)
	in := HookInput{}
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := raw[k].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}
	in.SessionID = str("session_id", "conversation_id")
	in.TranscriptPath = str("transcript_path")
	in.CWD = str("cwd", "workspace_root")
	if in.CWD == "" {
		if roots, ok := raw["workspace_roots"].([]any); ok && len(roots) > 0 {
			in.CWD, _ = roots[0].(string)
		}
	}
	in.HookEvent = str("hook_event_name")
	in.ToolName = str("tool_name")
	in.Command = str("command")
	if ti, ok := raw["tool_input"].(map[string]any); ok {
		if c, ok := ti["command"].(string); ok {
			in.Command = c
		}
	}
	return in
}

// Match is one install-like segment found in a command.
type Match struct {
	Installer string
	Package   string
	Severity  lockfile.Severity
}

var rules = []struct {
	installer string
	sev       lockfile.Severity
	re        *regexp.Regexp
}{
	{"skills", lockfile.SevMedium, regexp.MustCompile(`(?:^|\s)(?:npx\s+(?:-y\s+|--yes\s+)?)?skills\s+add\s+(\S+)`)},
	{"claude-plugin", lockfile.SevMedium, regexp.MustCompile(`(?:^|\s)claude\s+plugin\s+(?:install|add)\s+(\S+)`)},
	{"claude-mcp", lockfile.SevHigh, regexp.MustCompile(`(?:^|\s)claude\s+mcp\s+add(?:-json)?\s+(?:-[-\w]+\s+\S+\s+)*(\S+)`)},
	{"gemini", lockfile.SevHigh, regexp.MustCompile(`(?:^|\s)gemini\s+(?:mcp\s+add|extensions\s+install)\s+(\S+)`)},
	{"codex", lockfile.SevHigh, regexp.MustCompile(`(?:^|\s)codex\s+mcp\s+add\s+(\S+)`)},
	{"remote-script", lockfile.SevHigh, regexp.MustCompile(`(?:(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\b(?:ba|z|da)?sh\s+<\(\s*(?:curl|wget)\b)`)},
	{"npm", lockfile.SevLow, regexp.MustCompile(`(?:^|\s)(?:npm|pnpm|yarn|bun)\s+(?:i|install|add)(?:\s+-[-\w]+)*\s+((?:@?[\w.-]+/)?[\w.-]+(?:@[\w.^~<>=-]+)?)`)},
	{"npx", lockfile.SevLow, regexp.MustCompile(`(?:^|\s)npx\s+(?:-y\s+|--yes\s+)?((?:@[\w.-]+/)?[\w.-]+(?:@[\w.^~<>=-]+)?)`)},
	{"uv", lockfile.SevLow, regexp.MustCompile(`(?:^|\s)uvx?\s+(?:pip\s+install|add|tool\s+install)?\s*(?:-[-\w]+\s+)*([\w][\w.-]*)`)},
	{"pip", lockfile.SevLow, regexp.MustCompile(`(?:^|\s)(?:pip3?|pipx)\s+install(?:\s+-[-\w]+)*\s+([\w][\w.\[\]=<>~!-]*)`)},
	{"brew", lockfile.SevLow, regexp.MustCompile(`(?:^|\s)brew\s+install\s+(?:--\w+\s+)*(\S+)`)},
	{"cargo", lockfile.SevLow, regexp.MustCompile(`(?:^|\s)cargo\s+install\s+(\S+)`)},
	{"go", lockfile.SevLow, regexp.MustCompile(`(?:^|\s)go\s+install\s+(\S+)`)},
	{"gem", lockfile.SevLow, regexp.MustCompile(`(?:^|\s)gem\s+install\s+(\S+)`)},
	{"git", lockfile.SevInfo, regexp.MustCompile(`(?:^|\s)git\s+clone\s+(?:-[-\w]+\s+)*(\S+)`)},
}

var splitRe = regexp.MustCompile(`\s*(?:&&|\|\||;|\n)\s*`)

// Classify finds install-like actions in a shell command. Returns nil when it is not an install.
func Classify(cmd string) []Match {
	var out []Match
	seen := map[string]bool{}
	for _, seg := range splitRe.Split(cmd, -1) {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		for _, r := range rules {
			m := r.re.FindStringSubmatch(seg)
			if m == nil {
				continue
			}
			pkg := ""
			if len(m) > 1 {
				pkg = strings.Trim(m[1], `"'`)
			}
			if r.installer == "npx" && strings.HasPrefix(pkg, "skills") {
				continue // handled by the skills rule
			}
			k := r.installer + ":" + pkg
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, Match{Installer: r.installer, Package: pkg, Severity: r.sev})
			break
		}
	}
	return out
}

// LastUserPrompt extracts the most recent human message from a Claude Code / Gemini transcript
// (JSONL with {"type":"user","message":{"content":...}} lines). Returns "" when unavailable.
func LastUserPrompt(path string) string {
	if path == "" {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	last := ""
	for sc.Scan() {
		var line struct {
			Type    string `json:"type"`
			Role    string `json:"role"`
			Message struct {
				Role    string          `json:"role"`
				Content json.RawMessage `json:"content"`
			} `json:"message"`
			Content json.RawMessage `json:"content"`
		}
		if json.Unmarshal(sc.Bytes(), &line) != nil {
			continue
		}
		role := line.Type
		if line.Message.Role != "" {
			role = line.Message.Role
		} else if line.Role != "" {
			role = line.Role
		}
		if role != "user" {
			continue
		}
		content := line.Message.Content
		if len(content) == 0 {
			content = line.Content
		}
		if t := textOf(content); t != "" && !strings.HasPrefix(t, "<") { // skip tool_result / system-reminder-only turns
			last = t
		}
	}
	return Excerpt(last, 300)
}

func textOf(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) == nil {
		var sb strings.Builder
		for _, p := range parts {
			if p.Type == "text" {
				sb.WriteString(p.Text)
				sb.WriteString(" ")
			}
		}
		return strings.TrimSpace(sb.String())
	}
	return ""
}

// Excerpt truncates to n runes.
func Excerpt(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

// NewID returns a random hex id.
func NewID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Append writes an entry to the local ledger.
func Append(e Entry) error { return store.AppendJSONL(store.LedgerPath(), e) }

// All reads the local ledger.
func All() ([]Entry, error) { return store.ReadJSONL[Entry](store.LedgerPath()) }
