// Package scan inspects text artifacts (SKILL.md, CLAUDE.md, rules, tool descriptions) for
// content that should never appear in something an agent is about to load: hidden Unicode
// tag characters, bidi overrides, zero-width text, and a small set of high-signal instruction
// patterns seen in documented 2026 supply-chain incidents.
package scan

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Finding is one problem found in a file.
type Finding struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Rule    string `json:"rule"` // unicode_tags | bidi_override | zero_width | suspicious_content
	Detail  string `json:"detail"`
	Excerpt string `json:"excerpt,omitempty"`
}

// Text file extensions we scan inside skills/plugins/extensions.
var textExt = map[string]bool{
	".md": true, ".mdc": true, ".txt": true, ".json": true, ".yaml": true, ".yml": true, ".toml": true,
	".sh": true, ".bash": true, ".zsh": true, ".py": true, ".js": true, ".mjs": true, ".cjs": true,
	".ts": true, ".tsx": true, ".jsx": true, ".rb": true, ".go": true, ".rs": true, "": true,
}

var ignoredDirs = map[string]bool{
	".git": true, "node_modules": true, "__pycache__": true, ".venv": true, "venv": true, "dist": true, "build": true,
	// Test fixtures legitimately contain the very things we look for (bidi chars, "ignore previous instructions").
	"test": true, "tests": true, "__tests__": true, "testdata": true, "fixtures": true, "spec": true,
}

// Patterns are deliberately narrow: each one is something that has appeared in a real malicious
// skill/MCP description, or is unambiguous (piping a remote script to a shell inside an instruction
// file). They produce a flag, not a block; a human decides via `kova approve`.
var suspicious = []struct {
	name string
	re   *regexp.Regexp
}{
	{"prompt_override", regexp.MustCompile(`(?i)\b(ignore|disregard|forget)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|guidance|prompts?)`)},
	{"hidden_from_user", regexp.MustCompile(`(?i)\b(do\s+not|don'?t|never)\s+(tell|inform|mention|show|reveal|disclose)\s+(this\s+)?(to\s+)?(the\s+)?(user|human|operator)`)},
	{"silent_action", regexp.MustCompile(`(?i)\b(without|w/o)\s+(telling|informing|notifying|asking)\s+(the\s+)?(user|human)`)},
	{"secret_file_access", regexp.MustCompile(`(?i)\b(cat|read|open|load|include|collect|copy|send|upload|exfiltrate)\b[^.\n]{0,50}(~?/?\.aws/credentials|~?/?\.ssh/id_[a-z0-9]+|~?/?\.netrc|~?/?\.pypirc|~?/?\.npmrc|~?/?\.git-credentials|~?/?\.kube/config|~?/?\.docker/config\.json)`)},
	{"credential_collect", regexp.MustCompile(`(?i)\b(collect|gather|harvest|exfiltrate|send|upload|transmit|include|embed)\b[^.\n]{0,40}\b(api[_ -]?keys?|secrets?|access\s+tokens?|auth\s+tokens?|passwords?|credentials?|private\s+keys?)\b[^.\n]{0,60}\b(to|in|into|as|with|via)\b`)},
	{"exfil_hint", regexp.MustCompile(`(?i)\b(send|post|upload|transmit|exfiltrate|forward)\b[^.\n]{0,80}\b(to|at)\b[^.\n]{0,20}(https?://|webhook|pastebin|ngrok|requestbin|burpcollaborator|interact\.sh|oast\.)`)},
	{"remote_script_exec", regexp.MustCompile(`(?i)\b(curl|wget)\b[^|\n]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b`)},
	{"base64_exec", regexp.MustCompile(`(?i)\b(echo|printf)\b[^|\n]{0,300}\|\s*base64\s+(-d|--decode)[^|\n]{0,40}\|\s*(sudo\s+)?(ba|z)?sh\b`)},
	{"hidden_bcc", regexp.MustCompile(`(?i)\b(bcc|blind\s+copy)\b[^.\n]{0,60}@`)},
	{"memory_write_instruction", regexp.MustCompile(`(?i)\b(append|add|write|insert)\b[^.\n]{0,60}\b(to|into)\b[^.\n]{0,30}\b(MEMORY\.md|CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|memory\s+file)`)},
	{"persistence_instruction", regexp.MustCompile(`(?i)\b(every|each|all)\s+(future\s+)?(session|conversation|time)s?\b[^.\n]{0,80}\b(always|must|should)\s+(run|execute|call|invoke|load)\b`)},
}

// IsInstructionSurface reports whether a file is something an agent harness loads as instructions
// (as opposed to code, docs for humans, or test fixtures). Only these get the instruction-pattern
// rules; every text file gets the invisible-character rules.
func IsInstructionSurface(name string) bool {
	base := strings.ToLower(filepath.Base(name))
	switch base {
	case "skill.md", "claude.md", "claude.local.md", "agents.md", "agents.override.md", "gemini.md", "memory.md", ".cursorrules", "instructions.md", "plugin.json", "hooks.json", "marketplace.json":
		return true
	}
	if strings.HasSuffix(base, ".mdc") {
		return true
	}
	dir := strings.ToLower(filepath.ToSlash(filepath.Dir(name)))
	for _, seg := range []string{"commands", "agents", "skills", "rules", "memory", "memories", "hooks", "prompts"} {
		if dir == seg || strings.HasSuffix(dir, "/"+seg) || strings.Contains(dir, "/"+seg+"/") || strings.HasPrefix(dir, seg+"/") {
			return strings.HasSuffix(base, ".md") || strings.HasSuffix(base, ".json") || strings.HasSuffix(base, ".txt") || strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml")
		}
	}
	// Server-side tool descriptions and instructions passed in by the MCP scanner.
	return strings.HasPrefix(name, "tool:") || name == "instructions" || strings.Contains(name, "#")
}

var consentRe = regexp.MustCompile(`(?i)\b(ask|would you like|if yes|if the user agrees|with permission|confirm|offer to|propose)\b`)

// quotedMention reports whether the match starts inside a quotation or an example list
// ("…", '…', `…`, (…), or after like / such as / e.g.), i.e. the text is talking ABOUT the
// pattern rather than issuing it. Security tooling docs do this constantly.
func quotedMention(s string, start int) bool {
	prefix := s[:start]
	trimmed := strings.TrimRight(prefix, " ")
	if len(trimmed) > 0 {
		switch trimmed[len(trimmed)-1] {
		case '"', '\'', '`', '(', '[', '*', '_':
			return true
		}
	}
	low := strings.ToLower(prefix)
	for _, cue := range []string{"like ", "such as ", "e.g. ", "e.g., ", "for example ", "phrases ", "pattern", "detect", "flag", "match", "reject", "never follow", "ignore attempts", "e.g.,"} {
		if idx := strings.LastIndex(low, cue); idx >= 0 && start-idx < 80 {
			return true
		}
	}
	return false
}

// Text scans a single buffer and returns findings.
func Text(name string, data []byte) []Finding {
	var out []Finding
	if !utf8.Valid(data) {
		return out // binary or broken encoding; nothing meaningful to say about text
	}
	instr := IsInstructionSurface(name)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		s := sc.Text()
		if f, ok := invisible(name, line, s); ok {
			out = append(out, f...)
		}
		if !instr {
			continue
		}
		for _, p := range suspicious {
			loc := p.re.FindStringIndex(s)
			if loc == nil {
				continue
			}
			if p.name == "prompt_override" || p.name == "hidden_from_user" || p.name == "silent_action" {
				if quotedMention(s, loc[0]) {
					continue
				}
			}
			if p.name == "memory_write_instruction" && consentRe.MatchString(s) {
				continue
			}
			out = append(out, Finding{
				File: name, Line: line, Rule: "suspicious_content", Detail: p.name,
				Excerpt: excerpt(s, loc[0], loc[1]),
			})
		}
	}
	return out
}

func invisible(name string, line int, s string) ([]Finding, bool) {
	var out []Finding
	tags, bidi, zw := 0, 0, 0
	for _, r := range s {
		switch {
		case r >= 0xE0000 && r <= 0xE007F:
			tags++
		case r == 0x202A || r == 0x202B || r == 0x202D || r == 0x202E || r == 0x2066 || r == 0x2067 || r == 0x2068:
			bidi++
		case r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060 || r == 0xFEFF:
			zw++
		}
	}
	if tags > 0 {
		out = append(out, Finding{File: name, Line: line, Rule: "unicode_tags",
			Detail: "Unicode Tag characters (U+E0000–U+E007F) encode text invisible to humans but readable by models", Excerpt: decodeTags(s)})
	}
	if bidi > 0 {
		out = append(out, Finding{File: name, Line: line, Rule: "bidi_override", Detail: "bidirectional override/isolate control characters"})
	}
	// A few zero-width joiners are normal in emoji sequences; flag only clusters.
	if zw >= 8 {
		out = append(out, Finding{File: name, Line: line, Rule: "zero_width", Detail: "cluster of zero-width characters (possible hidden payload)"})
	}
	return out, len(out) > 0
}

// decodeTags renders the hidden ASCII a tag-character sequence spells out, so the report shows
// the actual smuggled instruction rather than an empty-looking line.
func decodeTags(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r >= 0xE0020 && r <= 0xE007E {
			sb.WriteRune(r - 0xE0000)
		}
	}
	d := sb.String()
	if len(d) > 160 {
		d = d[:160] + "…"
	}
	return "hidden text: " + d
}

func excerpt(s string, a, b int) string {
	start := a - 30
	if start < 0 {
		start = 0
	}
	end := b + 30
	if end > len(s) {
		end = len(s)
	}
	e := strings.TrimSpace(s[start:end])
	if len(e) > 200 {
		e = e[:200] + "…"
	}
	return e
}

// File scans one file.
func File(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Text(path, data), nil
}

// Tree scans every text file under root. Findings use paths relative to root.
func Tree(root string) ([]Finding, error) {
	var out []Finding
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are reported by the hasher, not the scanner
		}
		if d.IsDir() {
			if p != root && ignoredDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if !textExt[strings.ToLower(filepath.Ext(p))] {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 2*1024*1024 {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		out = append(out, Text(filepath.ToSlash(rel), data)...)
		return nil
	})
	return out, err
}

// Flags collapses findings to the lockfile flag vocabulary.
func Flags(fs []Finding) []string {
	seen := map[string]bool{}
	var flags []string
	for _, f := range fs {
		var flag string
		switch f.Rule {
		case "unicode_tags", "bidi_override", "zero_width":
			flag = "unicode_tags"
		default:
			flag = "suspicious_content"
		}
		if !seen[flag] {
			seen[flag] = true
			flags = append(flags, flag)
		}
	}
	return flags
}
