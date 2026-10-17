package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ian-hickey/kova/internal/harness"
	"github.com/ian-hickey/kova/internal/lockfile"
	"github.com/ian-hickey/kova/internal/store"
)

func (a *App) cmdWrap(args []string, wrap bool) int {
	verb := "wrap"
	if !wrap {
		verb = "unwrap"
	}
	fs := newFlags(verb)
	all := fs.Bool("all", false, "apply to every stdio MCP server")
	harnessFilter := fs.String("harness", "", "limit to one harness")
	enforce := fs.Bool("enforce", false, "wrapped servers block (not just alert on) changed tool definitions")
	if err := fs.Parse(args); err != nil {
		return a.errorf("%v", err)
	}
	names := fs.Args()
	if !*all && len(names) == 0 {
		return a.errorf("usage: kova %s --all | kova %s <server-name>... [--harness h]", verb, verb)
	}
	lf, err := a.loadLockfile()
	if err != nil {
		return a.errorf("%v", err)
	}
	disc, err := a.discover()
	if err != nil {
		return a.errorf("%v", err)
	}
	var selected []harness.MCPRef
	for _, r := range disc.MCP {
		if *harnessFilter != "" && r.Harness != *harnessFilter {
			continue
		}
		if !*all && !contains(names, r.Name) {
			continue
		}
		selected = append(selected, r)
	}
	n, err := a.wrapServers(disc, lf, selected, wrap, *enforce)
	if err != nil {
		return a.errorf("%v", err)
	}
	if err := lf.Save(store.LockfilePath()); err != nil {
		return a.errorf("%v", err)
	}
	if a.JSON {
		a.json(map[string]any{"changed": n})
		return ExitOK
	}
	if n == 0 {
		a.printf("nothing to %s (only stdio servers defined in JSON config files can be proxied; Codex's config.toml is read-only for now)\n", verb)
		return ExitOK
	}
	a.printf("%sped %d server(s). Restart open agent sessions for the change to take effect.\n", strings.Title(verb), n)
	return ExitOK
}

// wrapServers rewrites harness config files. With refs == nil every wrappable server is used.
func (a *App) wrapServers(disc *harness.Result, lf *lockfile.Lockfile, refs []harness.MCPRef, wrap, enforce bool) (int, error) {
	if refs == nil {
		refs = disc.MCP
	}
	byFile := map[string][]harness.MCPRef{}
	for _, r := range refs {
		if !r.Wrappable {
			continue
		}
		if wrap == r.Wrapped {
			continue // already in the desired state
		}
		byFile[r.ConfigFile] = append(byFile[r.ConfigFile], r)
	}
	changed := 0
	bin := kovaBin()
	for file, list := range byFile {
		raw, err := os.ReadFile(file)
		if err != nil {
			return changed, err
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return changed, fmt.Errorf("%s: %w", file, err)
		}
		for _, r := range list {
			obj, parent := navigate(doc, r.JSONPath)
			if obj == nil || parent == nil {
				continue
			}
			name := r.JSONPath[len(r.JSONPath)-1]
			if wrap {
				args := []any{"proxy", "--name", r.Name, "--harness", r.Harness}
				if enforce {
					args = append(args, "--enforce")
				}
				args = append(args, "--", r.Config.Command)
				for _, x := range r.Config.Args {
					args = append(args, x)
				}
				obj["command"] = bin
				obj["args"] = args
				if e := lf.Entries[r.Key]; e != nil {
					orig := r.Config
					e.Wrapped = &orig
				}
			} else {
				obj["command"] = r.Config.Command
				if len(r.Config.Args) > 0 {
					arr := make([]any, len(r.Config.Args))
					for i, x := range r.Config.Args {
						arr[i] = x
					}
					obj["args"] = arr
				} else {
					delete(obj, "args")
				}
				if e := lf.Entries[r.Key]; e != nil {
					e.Wrapped = nil
				}
			}
			parent[name] = obj
			changed++
		}
		backupFile(file, raw)
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return changed, err
		}
		if err := os.WriteFile(file, append(out, '\n'), 0o600); err != nil {
			return changed, err
		}
		a.printf("  %s %s (%d server(s))\n", map[bool]string{true: "wrapped", false: "unwrapped"}[wrap], file, len(list))
	}
	return changed, nil
}

// navigate returns the server object at path and its parent map.
func navigate(doc map[string]any, path []string) (map[string]any, map[string]any) {
	cur := doc
	for i, k := range path {
		next, ok := cur[k].(map[string]any)
		if !ok {
			return nil, nil
		}
		if i == len(path)-1 {
			return next, cur
		}
		cur = next
	}
	return nil, nil
}

func backupFile(file string, raw []byte) {
	name := fmt.Sprintf("%s-%s", time.Now().UTC().Format("20060102T150405Z"), strings.ReplaceAll(strings.TrimPrefix(file, string(filepath.Separator)), string(filepath.Separator), "_"))
	_ = os.WriteFile(filepath.Join(store.BackupDir(), name), raw, 0o600)
}
