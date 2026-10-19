package cli

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ian-hickey/kova/internal/cloud"
	"github.com/ian-hickey/kova/internal/lockfile"
	kovaskill "github.com/ian-hickey/kova/skills/kova-verify"
)

// cmdSkills: `kova skills refresh` rewrites every installed copy of the kova-verify skill from the
// text embedded in this binary and re-pins it, so the model never runs with instructions that
// describe an older kova. `kova upgrade` runs it; `kova init` runs it too.
func (a *App) cmdSkills(args []string) int {
	sub := "refresh"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "refresh":
		updated, pluginNote := a.refreshSkill()
		if a.JSON {
			a.json(map[string]any{"updated": updated, "plugin": pluginNote})
			return ExitOK
		}
		if len(updated) == 0 && pluginNote == "" {
			a.printf("kova-verify skill: no installed copies to refresh (install with `npx skills add ian-hickey/kova --skill kova-verify`).\n")
		}
		for _, p := range updated {
			a.printf("kova-verify skill refreshed: %s\n", a.tilde(p))
		}
		if pluginNote != "" {
			a.printf("%s\n", pluginNote)
		}
		return ExitOK
	default:
		return a.errorf("usage: kova skills refresh")
	}
}

// skillRoots lists the directories agent skill installers write into.
func (a *App) skillRoots() []string {
	var roots []string
	for _, rel := range []string{".claude/skills", ".codex/skills", ".gemini/skills", ".cursor/skills", ".agents/skills", ".copilot/skills", ".windsurf/skills", ".codeium/windsurf/skills"} {
		roots = append(roots, filepath.Join(a.Home, rel))
	}
	return roots
}

// installedSkillCopies finds SKILL.md files whose frontmatter names the kova skill, up to three
// levels under each root (skills.sh nests synced skills under ids).
func (a *App) installedSkillCopies() []string {
	var out []string
	for _, root := range a.skillRoots() {
		if st, err := os.Stat(root); err != nil || !st.IsDir() {
			continue
		}
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if strings.Count(strings.TrimPrefix(p, root), string(filepath.Separator)) > 3 || d.Name() == "node_modules" || d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Name() == "SKILL.md" && skillNamed(p, kovaskill.Name) {
				out = append(out, p)
			}
			return nil
		})
	}
	return out
}

func skillNamed(path, name string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for i := 0; sc.Scan() && i < 12; i++ {
		if strings.TrimSpace(sc.Text()) == "name: "+name {
			return true
		}
	}
	return false
}

// refreshSkill rewrites stale copies, re-pins their trees, and refreshes the Claude Code plugin
// when it is installed. Returns the paths rewritten and a note about the plugin.
func (a *App) refreshSkill() (updated []string, pluginNote string) {
	for _, p := range a.installedSkillCopies() {
		cur, err := os.ReadFile(p)
		if err != nil || string(cur) == kovaskill.SkillMD {
			continue
		}
		if err := os.WriteFile(p, []byte(kovaskill.SkillMD), 0o644); err != nil {
			continue
		}
		updated = append(updated, p)
	}
	// Claude Code plugin: reinstalling from the marketplace is how an update is applied.
	pluginDir := filepath.Join(a.Home, ".claude", "plugins", "cache", "kovaverified", "kova")
	if st, err := os.Stat(pluginDir); err == nil && st.IsDir() {
		if claude, err := exec.LookPath("claude"); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, claude, "plugin", "install", "kova@kovaverified")
			if out, err := cmd.CombinedOutput(); err != nil {
				pluginNote = "kova plugin: could not refresh (" + strings.TrimSpace(string(out)) + "); run `claude plugin install kova@kovaverified`"
			} else {
				pluginNote = "kova plugin refreshed from the kovaverified marketplace"
				updated = append(updated, pluginDir)
			}
		} else {
			pluginNote = "kova plugin is installed but the `claude` CLI is not on PATH; update it from /plugin in Claude Code"
		}
	}
	if len(updated) == 0 {
		return nil, pluginNote
	}
	a.repinPaths(updated, "kova refreshed its own skill text")
	return updated, pluginNote
}

// repinPaths re-discovers and silently re-pins lockfile entries living under the given paths:
// kova changed those files itself, so the change is not drift. Records an info event per entry.
func (a *App) repinPaths(paths []string, why string) {
	lf, err := a.loadLockfile()
	if err != nil {
		return
	}
	disc, err := a.discover()
	if err != nil {
		return
	}
	under := func(p string) bool {
		p = filepath.Clean(p)
		for _, root := range paths {
			root = filepath.Clean(root)
			if strings.HasSuffix(root, string(filepath.Separator)+"SKILL.md") {
				root = filepath.Dir(root)
			}
			if p == root || strings.HasPrefix(p, root+string(filepath.Separator)) {
				return true
			}
		}
		return false
	}
	changed := false
	for key, live := range disc.Entries {
		if live.Path == "" || !under(live.Path) {
			continue
		}
		prev, ok := lf.Entries[key]
		if !ok || prev.Hash == live.Hash {
			continue
		}
		live.FirstSeen, live.Approved = prev.FirstSeen, prev.Approved
		lf.Entries[key] = live
		changed = true
		_ = cloud.RecordEvent(cloud.EventRecord{Source: "skills", Kind: lockfile.ChangeModified, Severity: lockfile.SevInfo, Harness: live.Harness,
			ArtifactType: live.Type, Key: key, Name: live.Name, Path: live.Path, ExpectedHash: prev.Hash, ActualHash: live.Hash,
			Message: why + "; re-pinned"})
	}
	if changed {
		_ = lf.Save(lockfilePath())
	}
}
