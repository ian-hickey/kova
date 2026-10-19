// Package harness discovers everything an agent harness (Claude Code, Codex CLI, Gemini CLI,
// Cursor, GitHub Copilot, Claude Desktop, Windsurf, Cline/Roo Code) will load at session start:
// skills, plugins, MCP server configs, hooks and memory / instruction files. It produces lockfile
// entries with content hashes and content-scan flags.
package harness

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/ian-hickey/kova/internal/lockfile"
	"github.com/ian-hickey/kova/internal/scan"
)

// MCPRef points at a configured MCP server and where its config lives, so it can be re-pinned
// (tools/list) and wrapped with the kova proxy.
type MCPRef struct {
	Key        string
	Name       string
	Harness    string
	Scope      string
	Config     lockfile.MCPConfig // normalised: if already wrapped by kova, this is the ORIGINAL
	Wrapped    bool               // currently routed through `kova proxy`
	ConfigFile string             // file holding the definition
	JSONPath   []string           // path to the server object inside the JSON file (empty for TOML)
	Wrappable  bool
}

// Result of a discovery pass.
type Result struct {
	Harnesses []string
	Entries   map[string]*lockfile.Entry
	MCP       []MCPRef
	Findings  map[string][]scan.Finding // entry key -> scan findings
	Warnings  []string
	// SweepTruncated is set when the descendant walk hit MaxSweepEntries: the result is partial.
	SweepTruncated bool
}

// Options control discovery.
type Options struct {
	Home string
	CWD  string // project directory; "" to skip project-scoped artifacts
	// Trace, when set, is called with a label after each discovery phase (for KOVA_TRACE timing).
	Trace func(phase string)
	Now   time.Time
	// KovaBinary is used to recognise already-wrapped MCP configs. Defaults to "kova".
	KovaBinary string
	// AllHarnesses runs every discoverer even when the harness is not installed (CI mode).
	AllHarnesses bool
	// NoSweep skips the ancestor/descendant instruction-file sweep.
	NoSweep bool
	// ProjectRelative names files under CWD as "./x" (the committed project lockfile and CI mode,
	// where the checkout location is irrelevant). The machine lockfile instead names them by
	// home-relative or absolute path so two projects, or two worktrees, never share a key.
	ProjectRelative bool
}

type ctx struct {
	Options
	res *Result
}

// Discover runs discovery for every harness present on the machine.
func Discover(opts Options) (*Result, error) {
	if opts.Home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		opts.Home = h
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.CWD != "" {
		if abs, err := filepath.Abs(opts.CWD); err == nil {
			opts.CWD = abs
		}
	}
	if opts.KovaBinary == "" {
		opts.KovaBinary = "kova"
	}
	c := &ctx{Options: opts, res: &Result{Entries: map[string]*lockfile.Entry{}, Findings: map[string][]scan.Finding{}}}
	for _, h := range []struct {
		name    string
		present func(*ctx) bool
		run     func(*ctx)
	}{
		{lockfile.HarnessClaudeCode, claudePresent, claudeDiscover},
		{lockfile.HarnessCodex, codexPresent, codexDiscover},
		{lockfile.HarnessGeminiCLI, geminiPresent, geminiDiscover},
		{lockfile.HarnessCursor, cursorPresent, cursorDiscover},
		{lockfile.HarnessGitHubCopilot, copilotPresent, copilotDiscover},
		{lockfile.HarnessClaudeDesktop, claudeDesktopPresent, claudeDesktopDiscover},
		{lockfile.HarnessWindsurf, windsurfPresent, windsurfDiscover},
		{lockfile.HarnessCline, clinePresent, clineDiscover},
	} {
		if h.present(c) || opts.AllHarnesses {
			c.res.Harnesses = append(c.res.Harnesses, h.name)
			h.run(c)
			if opts.Trace != nil {
				opts.Trace(h.name)
			}
		}
	}
	if !opts.NoSweep {
		if v := os.Getenv("KOVA_SWEEP_MAX"); v != "" {
			var n int
			if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
				MaxSweepEntries = n
			}
		}
		c.sweep()
		if opts.Trace != nil {
			opts.Trace("sweep")
		}
	}
	sort.Slice(c.res.MCP, func(i, j int) bool { return c.res.MCP[i].Key < c.res.MCP[j].Key })
	return c.res, nil
}

// Present reports which harnesses exist on this machine without running discovery.
func Present(home string) []string {
	c := &ctx{Options: Options{Home: home}}
	var out []string
	if claudePresent(c) {
		out = append(out, lockfile.HarnessClaudeCode)
	}
	if codexPresent(c) {
		out = append(out, lockfile.HarnessCodex)
	}
	if geminiPresent(c) {
		out = append(out, lockfile.HarnessGeminiCLI)
	}
	if cursorPresent(c) {
		out = append(out, lockfile.HarnessCursor)
	}
	if copilotPresent(c) {
		out = append(out, lockfile.HarnessGitHubCopilot)
	}
	if claudeDesktopPresent(c) {
		out = append(out, lockfile.HarnessClaudeDesktop)
	}
	if windsurfPresent(c) {
		out = append(out, lockfile.HarnessWindsurf)
	}
	if clinePresent(c) {
		out = append(out, lockfile.HarnessCline)
	}
	return out
}

// vscodeUserDirs returns the VS Code (and Insiders) user-settings directories that exist under
// home. Every platform layout is probed so fixtures built with the macOS layout work everywhere;
// on Windows %APPDATA% is consulted as well.
func vscodeUserDirs(home string) []string {
	var candidates []string
	for _, edition := range []string{"Code", "Code - Insiders"} {
		candidates = append(candidates,
			filepath.Join(home, "Library", "Application Support", edition, "User"), // macOS
			filepath.Join(home, ".config", edition, "User"),                        // Linux
		)
		if runtime.GOOS == "windows" {
			if appdata := os.Getenv("APPDATA"); appdata != "" {
				candidates = append(candidates, filepath.Join(appdata, edition, "User"))
			}
		}
	}
	var out []string
	for _, p := range candidates {
		if isDir(p) {
			out = append(out, p)
		}
	}
	return out
}

// ───────────────────────────── helpers ─────────────────────────────

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func (c *ctx) warn(format string, args ...any) {
	c.res.Warnings = append(c.res.Warnings, fmt.Sprintf(format, args...))
}

func (c *ctx) proj(rel string) string {
	if c.CWD == "" {
		return ""
	}
	return filepath.Join(c.CWD, rel)
}

// display shortens a path for use as an entry name.
func (c *ctx) display(p string) string {
	if c.ProjectRelative && c.CWD != "" && strings.HasPrefix(p, c.CWD+string(filepath.Separator)) {
		return "./" + filepath.ToSlash(strings.TrimPrefix(p, c.CWD+string(filepath.Separator)))
	}
	if strings.HasPrefix(p, c.Home+string(filepath.Separator)) {
		return "~/" + filepath.ToSlash(strings.TrimPrefix(p, c.Home+string(filepath.Separator)))
	}
	return p
}

func (c *ctx) add(e *lockfile.Entry, findings []scan.Finding) {
	key := lockfile.Key(e.Harness, e.Type, e.Name)
	e.FirstSeen, e.UpdatedAt = c.Now, c.Now
	if e.Scope == "" {
		e.Scope = "user"
	}
	if e.Scope != "user" && e.Scope != ScopeSystem && e.Project == "" {
		e.Project = c.CWD
	}
	if len(findings) > 0 {
		e.Flags = scan.Flags(findings)
		c.res.Findings[key] = findings
	}
	c.res.Entries[key] = e
}

// addFile pins a single file (memory, rules, hooks file).
func (c *ctx) addFile(harness string, t lockfile.ArtifactType, path, scope string) {
	if !exists(path) {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		c.warn("read %s: %v", path, err)
		return
	}
	h, size := lockfile.HashBytes(data), int64(len(data))
	findings := scan.Text(path, data)
	for i := range findings {
		findings[i].File = c.display(path)
	}
	e := &lockfile.Entry{Type: t, Harness: harness, Name: c.display(path), Scope: scope, Path: path, Hash: h, Size: size}
	switch t {
	case lockfile.TypeMemory, lockfile.TypeRules, lockfile.TypeCommand, lockfile.TypeAgent:
		if size <= lockfile.MaxBlobSize {
			e.Content = data // kept in the blob store so verify can show diffs and triage can judge edits
		}
	}
	c.add(e, findings)
}

// addTree pins a directory (skill, plugin, extension).
func (c *ctx) addTree(harness string, t lockfile.ArtifactType, name, path, scope string) {
	resolved := path
	if st, err := os.Lstat(path); err == nil && st.Mode()&os.ModeSymlink != 0 {
		if r, err := filepath.EvalSymlinks(path); err == nil {
			resolved = r
		}
	}
	h, files, size, err := lockfile.HashTree(resolved)
	if err != nil {
		c.warn("hash %s: %v", path, err)
		return
	}
	findings, _ := scan.TreeCached(resolved, h) // unchanged tree: cached findings, no re-read
	c.add(&lockfile.Entry{Type: t, Harness: harness, Name: name, Scope: scope, Path: path, Hash: h, Files: files, Size: size}, findings)
}

// addSkillDirs pins every immediate subdirectory of root that contains a SKILL.md.
func (c *ctx) addSkillDirs(harness, root, scope string) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, d := range ents {
		p := filepath.Join(root, d.Name())
		if !isDir(p) { // handles symlinked dirs via Stat
			continue
		}
		if !exists(filepath.Join(p, "SKILL.md")) && !exists(filepath.Join(p, "skill.md")) {
			continue
		}
		c.addTree(harness, lockfile.TypeSkill, d.Name(), p, scope)
	}
}

// addWalk pins every file under root (recursively) whose name ends in one of the suffixes.
func (c *ctx) addWalk(harness string, t lockfile.ArtifactType, root, scope string, suffixes ...string) {
	if root == "" || !isDir(root) {
		return
	}
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		for _, suf := range suffixes {
			if strings.HasSuffix(p, suf) {
				c.addFile(harness, t, p, scope)
				return nil
			}
		}
		return nil
	})
}

// addGlob pins each file matching a glob pattern as a separate artifact.
func (c *ctx) addGlob(harness string, t lockfile.ArtifactType, pattern, scope string) {
	matches, _ := filepath.Glob(pattern)
	for _, m := range matches {
		if st, err := os.Stat(m); err == nil && !st.IsDir() {
			c.addFile(harness, t, m, scope)
		}
	}
}

func readJSON(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

// addHooks pins the `hooks` section of a settings file. Kova's own hook commands are filtered
// out before hashing so installing/removing kova never registers as drift.
func (c *ctx) addHooks(harness, file, scope string) {
	if !exists(file) {
		return
	}
	m, err := readJSON(file)
	if err != nil {
		c.warn("%v", err)
		return
	}
	hooks, ok := m["hooks"]
	if !ok {
		return
	}
	filtered := stripKovaHooks(hooks, c.KovaBinary)
	if filtered == nil {
		return
	}
	canon, _ := lockfile.CanonicalJSON(filtered)
	findings := scan.Text(c.display(file), canon)
	c.add(&lockfile.Entry{Type: lockfile.TypeHooks, Harness: harness, Name: c.display(file), Scope: scope, Path: file, Hash: lockfile.HashBytes(canon), Size: int64(len(canon)), Hooks: canon}, findings)
}

// stripKovaHooks removes hook commands that invoke kova; returns nil if nothing remains.
func stripKovaHooks(hooks any, kovaBin string) any {
	switch h := hooks.(type) {
	case map[string]any: // Claude Code / Gemini: {Event: [ {matcher, hooks:[{command}]} ]}
		out := map[string]any{}
		for ev, groupsAny := range h {
			groups, ok := groupsAny.([]any)
			if !ok {
				out[ev] = groupsAny
				continue
			}
			var kept []any
			for _, g := range groups {
				gm, ok := g.(map[string]any)
				if !ok {
					kept = append(kept, g)
					continue
				}
				if inner, ok := gm["hooks"].([]any); ok {
					var innerKept []any
					for _, hk := range inner {
						if !isKovaHook(hk, kovaBin) {
							innerKept = append(innerKept, hk)
						}
					}
					if len(innerKept) == 0 {
						continue
					}
					cp := map[string]any{}
					for k, v := range gm {
						cp[k] = v
					}
					cp["hooks"] = innerKept
					kept = append(kept, cp)
				} else if !isKovaHook(g, kovaBin) { // Cursor: {Event: [{command}]}
					kept = append(kept, g)
				}
			}
			if len(kept) > 0 {
				out[ev] = kept
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	default:
		return hooks
	}
}

func isKovaHook(h any, kovaBin string) bool {
	m, ok := h.(map[string]any)
	if !ok {
		return false
	}
	cmd, _ := m["command"].(string)
	base := filepath.Base(kovaBin)
	return strings.Contains(cmd, kovaBin+" ") || strings.HasPrefix(cmd, base+" ") || strings.Contains(cmd, "/"+base+" ")
}

// parseMCPConfig converts a server definition object to MCPConfig.
func parseMCPConfig(v any) (lockfile.MCPConfig, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return lockfile.MCPConfig{}, false
	}
	cfg := lockfile.MCPConfig{}
	if s, ok := m["command"].(string); ok {
		cfg.Command = s
	}
	if arr, ok := m["args"].([]any); ok {
		for _, a := range arr {
			cfg.Args = append(cfg.Args, fmt.Sprint(a))
		}
	}
	if s, ok := m["url"].(string); ok {
		cfg.URL = s
	}
	if s, ok := m["type"].(string); ok {
		cfg.Transport = strings.ToLower(s)
	} else if s, ok := m["transport"].(string); ok {
		cfg.Transport = strings.ToLower(s)
	}
	if env, ok := m["env"].(map[string]any); ok && len(env) > 0 {
		cfg.Env = map[string]string{}
		for k, v := range env {
			cfg.Env[k] = fmt.Sprint(v)
		}
	}
	if cfg.Transport == "" {
		if cfg.URL != "" {
			cfg.Transport = "http"
		} else {
			cfg.Transport = "stdio"
		}
	}
	if cfg.Transport == "streamable-http" || cfg.Transport == "streamable_http" {
		cfg.Transport = "http"
	}
	if cfg.Command == "" && cfg.URL == "" {
		return cfg, false
	}
	return cfg, true
}

// Unwrap recognises a config already routed through `kova proxy` and returns the original.
func Unwrap(cfg lockfile.MCPConfig, kovaBin string) (lockfile.MCPConfig, bool) {
	if filepath.Base(cfg.Command) != filepath.Base(kovaBin) || len(cfg.Args) == 0 || cfg.Args[0] != "proxy" {
		return cfg, false
	}
	for i, a := range cfg.Args {
		if a == "--" && i+1 < len(cfg.Args) {
			orig := cfg
			orig.Command = cfg.Args[i+1]
			orig.Args = append([]string(nil), cfg.Args[i+2:]...)
			return orig, true
		}
	}
	return cfg, false
}

// addMCPServers pins every server in a `mcpServers` map found at jsonPath within file.
// mcpOpts tunes how a block of MCP servers is registered.
type mcpOpts struct {
	rename   func(string) string       // lockfile name for a JSON key (default: identity)
	readOnly bool                      // config lives somewhere kova must not rewrite (plugin cache, managed policy)
	fix      func(*lockfile.MCPConfig) // normalise the parsed config before hashing (e.g. expand ${CLAUDE_PLUGIN_ROOT})
}

func (c *ctx) addMCPServers(harness, file, scope string, servers map[string]any, jsonPath []string) {
	c.addMCPServersOpt(harness, file, scope, servers, jsonPath, mcpOpts{})
}

func (c *ctx) addMCPServersOpt(harness, file, scope string, servers map[string]any, jsonPath []string, o mcpOpts) {
	for jsonName, def := range servers {
		cfg, ok := parseMCPConfig(def)
		if !ok {
			continue
		}
		if o.fix != nil {
			o.fix(&cfg)
		}
		name := jsonName
		if o.rename != nil {
			name = o.rename(jsonName)
		}
		orig, wrapped := Unwrap(cfg, c.KovaBinary)
		configHash := lockfile.HashJSON(orig)
		e := &lockfile.Entry{
			Type: lockfile.TypeMCPServer, Harness: harness, Name: name, Scope: scope, Path: file,
			Hash: configHash, ConfigHash: configHash, MCP: &orig,
		}
		if wrapped {
			e.Wrapped = &orig
		}
		// Scan the launch config itself (args/env can carry instructions or exfil URLs).
		canon, _ := lockfile.CanonicalJSON(orig)
		c.add(e, scan.Text(c.display(file)+"#"+name, canon))
		path := append(append([]string(nil), jsonPath...), jsonName)
		c.res.MCP = append(c.res.MCP, MCPRef{
			Key: lockfile.Key(harness, lockfile.TypeMCPServer, name), Name: name, Harness: harness, Scope: scope,
			Config: orig, Wrapped: wrapped, ConfigFile: file, JSONPath: path,
			Wrappable: orig.Transport == "stdio" && len(jsonPath) > 0 && !o.readOnly,
		})
	}
}

// addMCPFromJSON reads file and pins servers under the given key path (e.g. ["mcpServers"]).
func (c *ctx) addMCPFromJSON(harness, file, scope string, path ...string) {
	if !exists(file) {
		return
	}
	m, err := readJSON(file)
	if err != nil {
		c.warn("%v", err)
		return
	}
	var cur any = m
	for _, k := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return
		}
		cur, ok = mm[k]
		if !ok {
			return
		}
	}
	servers, ok := cur.(map[string]any)
	if !ok {
		return
	}
	c.addMCPServers(harness, file, scope, servers, path)
}

// addJSONFile pins a JSON file by its canonical content with volatile keys (timestamps, counters)
// removed, so a plugin update registers once instead of every time the harness touches the file.
func (c *ctx) addJSONFile(harness string, t lockfile.ArtifactType, path, scope string, dropKeys ...string) {
	if !exists(path) {
		return
	}
	m, err := readJSON(path)
	if err != nil {
		c.addFile(harness, t, path, scope) // unparseable: fall back to the raw bytes
		return
	}
	drop := map[string]bool{}
	for _, k := range dropKeys {
		drop[strings.ToLower(k)] = true
	}
	var strip func(v any) any
	strip = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			out := map[string]any{}
			for k, vv := range x {
				if drop[strings.ToLower(k)] {
					continue
				}
				out[k] = strip(vv)
			}
			return out
		case []any:
			for i := range x {
				x[i] = strip(x[i])
			}
			return x
		}
		return v
	}
	canon, _ := lockfile.CanonicalJSON(strip(m))
	st, _ := os.Stat(path)
	var size int64
	if st != nil {
		size = st.Size()
	}
	c.add(&lockfile.Entry{Type: t, Harness: harness, Name: c.display(path), Scope: scope, Path: path,
		Hash: lockfile.HashBytes(canon), Size: size}, scan.Text(c.display(path), canon))
}
