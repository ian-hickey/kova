package harness

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/ian-hickey/kova/internal/lockfile"
)

// Instruction files are loaded hierarchically by the harnesses: every ancestor directory of
// the working directory, and any descendant directory the agent happens to read a file from.
// A CLAUDE.md dropped into node_modules/some-dep/ is therefore live the moment the agent
// opens a file next to it. The sweep finds them wherever they are.

// Scope values used by the sweep in addition to user/project.
const (
	ScopeAncestor   = "ancestor"    // parent dirs of the project
	ScopeDescendant = "descendant"  // nested inside the project tree
	ScopeSystem     = "system"      // managed policy paths
	ScopeAutoMemory = "auto-memory" // files the agent itself writes
)

// instructionFile maps a basename to the harness that loads it.
var instructionFiles = map[string]string{
	"CLAUDE.md":          lockfile.HarnessClaudeCode,
	"CLAUDE.local.md":    lockfile.HarnessClaudeCode,
	"AGENTS.md":          lockfile.HarnessCodex, // also read by Cursor; attributed to Codex when both present
	"AGENTS.override.md": lockfile.HarnessCodex,
	"GEMINI.md":          lockfile.HarnessGeminiCLI,
	".cursorrules":       lockfile.HarnessCursor,
}

// MaxSweepEntries bounds the descendant walk so a pathological tree cannot stall a session hook.
var MaxSweepEntries = 400000

// IsInstructionFile reports whether a path is one a harness would load as instructions.
func IsInstructionFile(path string) bool {
	base := filepath.Base(path)
	if _, ok := instructionFiles[base]; ok {
		return true
	}
	dir := filepath.ToSlash(filepath.Dir(path))
	if strings.HasSuffix(dir, "/.claude/rules") || strings.HasSuffix(dir, "/.claude/commands") || strings.Contains(dir, "/.claude/commands/") || strings.HasSuffix(dir, "/.claude/agents") {
		return strings.HasSuffix(base, ".md")
	}
	if strings.Contains(dir+"/", "/.cursor/rules/") {
		return strings.HasSuffix(base, ".mdc") || strings.HasSuffix(base, ".md")
	}
	if strings.HasSuffix(dir, "/.claude") && base == "CLAUDE.md" {
		return true
	}
	return false
}

// harnessFor returns the harness that loads a given instruction path, or "" if none present.
func (c *ctx) harnessFor(path string, present map[string]bool) string {
	base := filepath.Base(path)
	dir := filepath.ToSlash(filepath.Dir(path))
	switch {
	case strings.Contains(dir+"/", "/.claude/") || base == "CLAUDE.md" || base == "CLAUDE.local.md":
		if present[lockfile.HarnessClaudeCode] {
			return lockfile.HarnessClaudeCode
		}
	case strings.Contains(dir+"/", "/.cursor/") || base == ".cursorrules":
		if present[lockfile.HarnessCursor] {
			return lockfile.HarnessCursor
		}
	case base == "GEMINI.md":
		if present[lockfile.HarnessGeminiCLI] {
			return lockfile.HarnessGeminiCLI
		}
	case strings.HasPrefix(base, "AGENTS"):
		if present[lockfile.HarnessCodex] {
			return lockfile.HarnessCodex
		}
		if present[lockfile.HarnessCursor] {
			return lockfile.HarnessCursor
		}
	}
	return ""
}

func (c *ctx) addInstruction(path, scope string, present map[string]bool) {
	h := c.harnessFor(path, present)
	if h == "" {
		return
	}
	t := lockfile.TypeMemory
	dir := filepath.ToSlash(filepath.Dir(path))
	switch {
	case strings.HasSuffix(dir, "/.claude/rules") || strings.Contains(dir+"/", "/.cursor/rules/"):
		t = lockfile.TypeRules
	case strings.HasSuffix(dir, "/.claude/commands") || strings.Contains(dir, "/.claude/commands/"):
		t = lockfile.TypeCommand
	case strings.HasSuffix(dir, "/.claude/agents"):
		t = lockfile.TypeAgent
	}
	key := lockfile.Key(h, t, c.display(path))
	if _, exists := c.res.Entries[key]; exists {
		return
	}
	c.addFile(h, t, path, scope)
	// Includes: `@path` references pull more files into context.
	if t == lockfile.TypeMemory {
		for _, inc := range includesOf(path) {
			if _, exists := c.res.Entries[lockfile.Key(h, lockfile.TypeMemory, c.display(inc))]; !exists && exists_(inc) {
				c.addFile(h, lockfile.TypeMemory, inc, scope)
			}
		}
	}
}

func exists_(p string) bool { st, err := os.Stat(p); return err == nil && !st.IsDir() }

var includeRe = regexp.MustCompile(`(?m)(?:^|\s)@((?:~|\.{1,2})?/[^\s)\]"']+|[A-Za-z0-9_.-]+/[^\s)\]"']+)`)

// includesOf returns absolute paths referenced with Claude Code's @include syntax.
func includesOf(file string) []string {
	f, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer f.Close()
	home, _ := os.UserHomeDir()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			continue
		}
		for _, m := range includeRe.FindAllStringSubmatch(line, -1) {
			p := m[1]
			switch {
			case strings.HasPrefix(p, "~/"):
				p = filepath.Join(home, p[2:])
			case filepath.IsAbs(p):
			default:
				p = filepath.Join(filepath.Dir(file), p)
			}
			if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Size() < 4*1024*1024 {
				out = append(out, p)
			}
		}
	}
	return out
}

// sweep pins ancestor, descendant and system instruction files for the present harnesses.
func (c *ctx) sweep() {
	present := map[string]bool{}
	for _, h := range c.res.Harnesses {
		present[h] = true
	}
	if c.AllHarnesses {
		for _, h := range lockfile.AllHarnesses {
			present[h] = true
		}
	}

	// Managed / system policy files.
	var sys []string
	if runtime.GOOS == "darwin" {
		sys = []string{"/Library/Application Support/ClaudeCode/CLAUDE.md", "/Library/Application Support/ClaudeCode/managed-settings.json"}
	} else {
		sys = []string{"/etc/claude-code/CLAUDE.md", "/etc/claude-code/managed-settings.json"}
	}
	if present[lockfile.HarnessClaudeCode] {
		for _, p := range sys {
			if exists_(p) {
				if strings.HasSuffix(p, ".json") {
					c.addFile(lockfile.HarnessClaudeCode, lockfile.TypeHooks, p, ScopeSystem)
				} else {
					c.addFile(lockfile.HarnessClaudeCode, lockfile.TypeMemory, p, ScopeSystem)
				}
			}
		}
	}

	// @includes referenced from any memory file pinned so far (root CLAUDE.md, ~/.claude/CLAUDE.md, …).
	c.pinIncludes()

	if c.CWD == "" {
		return
	}

	// Ancestors: every directory from the project's parent up to the root (excluding $HOME's
	// own files, which the per-harness discoverers already pin as user scope).
	for dir := filepath.Dir(c.CWD); ; dir = filepath.Dir(dir) {
		if dir != c.Home {
			for base := range instructionFiles {
				p := filepath.Join(dir, base)
				if exists_(p) {
					c.addInstruction(p, ScopeAncestor, present)
				}
			}
			if exists_(filepath.Join(dir, ".claude", "CLAUDE.md")) {
				c.addInstruction(filepath.Join(dir, ".claude", "CLAUDE.md"), ScopeAncestor, present)
			}
		}
		if dir == filepath.Dir(dir) {
			break
		}
	}

	// Descendants: the whole project tree, dependency folders included. Only names are
	// inspected, so this is a directory walk, not a content hash of the tree.
	count := 0
	_ = filepath.WalkDir(c.CWD, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		count++
		if count > MaxSweepEntries {
			c.warn("sweep stopped after %d entries under %s; set KOVA_SWEEP_MAX to raise", MaxSweepEntries, c.CWD)
			return filepath.SkipAll
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if p == c.CWD || filepath.Dir(p) == c.CWD {
			return nil // project root files are pinned by the per-harness discoverers
		}
		if IsInstructionFile(p) {
			c.addInstruction(p, ScopeDescendant, present)
		}
		return nil
	})
	c.pinIncludes()
}

// pinIncludes follows @path references in every pinned memory file (one level, then repeats
// until no new files appear, bounded).
func (c *ctx) pinIncludes() {
	for round := 0; round < 4; round++ {
		added := 0
		for key, e := range c.res.Entries {
			if e.Type != lockfile.TypeMemory || e.Path == "" {
				continue
			}
			for _, inc := range includesOf(e.Path) {
				k := lockfile.Key(e.Harness, lockfile.TypeMemory, c.display(inc))
				if _, exists := c.res.Entries[k]; exists || k == key {
					continue
				}
				c.addFile(e.Harness, lockfile.TypeMemory, inc, e.Scope)
				added++
			}
		}
		if added == 0 {
			return
		}
	}
}
