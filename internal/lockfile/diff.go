package lockfile

import "sort"

// ChangeKind describes how an entry differs between the pinned lockfile and the live state.
type ChangeKind string

const (
	ChangeModified           ChangeKind = "artifact_modified"
	ChangeAdded              ChangeKind = "artifact_added"
	ChangeRemoved            ChangeKind = "artifact_removed"
	ChangeHooks              ChangeKind = "hooks_changed"
	ChangeMCPTools           ChangeKind = "mcp_tools_changed"
	ChangeMCPConfig          ChangeKind = "mcp_config_changed"
	ChangeMCPAdded           ChangeKind = "mcp_server_added"
	ChangeMCPRemoved         ChangeKind = "mcp_server_removed"
	ChangeMemory             ChangeKind = "memory_modified"
	ChangeUnicodeTags        ChangeKind = "unicode_tags_detected"
	ChangeSuspicious         ChangeKind = "suspicious_content"
	ChangeNetwork            ChangeKind = "new_network_destination"
	ChangeListChanged        ChangeKind = "mcp_list_changed_notification"
	ChangePolicyBlocked      ChangeKind = "policy_blocked"
	ChangeInstructionAdded   ChangeKind = "instruction_file_added"
	ChangeInstructionBlocked ChangeKind = "instruction_file_blocked" // guard denied access
)

// Severity levels, ordered.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

var severityRank = map[Severity]int{SevInfo: 0, SevLow: 1, SevMedium: 2, SevHigh: 3, SevCritical: 4}

// Rank returns a sortable integer for a severity.
func (s Severity) Rank() int { return severityRank[s] }

// AtLeast reports whether s >= min.
func (s Severity) AtLeast(min Severity) bool { return s.Rank() >= min.Rank() }

// Change is a single detected difference.
type Change struct {
	Kind         ChangeKind     `json:"kind"`
	Severity     Severity       `json:"severity"`
	Key          string         `json:"key"`
	Harness      string         `json:"harness"`
	Type         ArtifactType   `json:"type"`
	Name         string         `json:"name"`
	Path         string         `json:"path,omitempty"`
	ExpectedHash string         `json:"expected_hash,omitempty"`
	ActualHash   string         `json:"actual_hash,omitempty"`
	Details      map[string]any `json:"details,omitempty"`
	Message      string         `json:"message"`
}

// Diff compares pinned entries against freshly discovered ones. Entries in `pinned` that are
// project-scoped to projects not in `activeProjects` are skipped (we can't observe them).
func Diff(pinned, live map[string]*Entry, activeProjects map[string]bool) []Change {
	var changes []Change

	for key, p := range pinned {
		l, ok := live[key]
		// Project-relative entries (project, ancestor, descendant, auto-memory) are only
		// observable from their project; if we can see the file anyway, compare it.
		if p.Scope != "user" && p.Scope != "system" && !activeProjects[p.Project] && !ok {
			continue
		}
		if !ok {
			changes = append(changes, removedChange(key, p))
			continue
		}
		if c, ok := compareEntry(key, p, l); ok {
			changes = append(changes, c)
		}
	}
	for key, l := range live {
		if _, ok := pinned[key]; ok {
			continue
		}
		changes = append(changes, addedChange(key, l))
	}

	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Severity.Rank() != changes[j].Severity.Rank() {
			return changes[i].Severity.Rank() > changes[j].Severity.Rank()
		}
		return changes[i].Key < changes[j].Key
	})
	return changes
}

func base(key string, e *Entry) Change {
	return Change{Key: key, Harness: e.Harness, Type: e.Type, Name: e.Name, Path: e.Path}
}

func removedChange(key string, p *Entry) Change {
	c := base(key, p)
	c.ExpectedHash = p.Hash
	switch p.Type {
	case TypeMCPServer:
		c.Kind, c.Severity = ChangeMCPRemoved, SevLow
		c.Message = "MCP server removed from configuration"
	case TypeHooks:
		c.Kind, c.Severity = ChangeHooks, SevHigh
		c.Message = "hooks configuration removed"
	default:
		c.Kind, c.Severity = ChangeRemoved, SevInfo
		c.Message = string(p.Type) + " removed"
	}
	return c
}

func addedChange(key string, l *Entry) Change {
	c := base(key, l)
	c.ActualHash = l.Hash
	switch l.Type {
	case TypeMCPServer:
		c.Kind, c.Severity = ChangeMCPAdded, SevHigh
		c.Message = "new MCP server configured (not in lockfile)"
	case TypeHooks:
		c.Kind, c.Severity = ChangeHooks, SevHigh
		c.Message = "new hooks configuration (hooks run outside the sandbox)"
	case TypeMemory, TypeRules, TypeCommand, TypeAgent:
		if l.Scope == "auto-memory" {
			c.Kind, c.Severity = ChangeAdded, SevInfo
			c.Message = "new auto-memory file written by the agent"
		} else {
			c.Kind, c.Severity = ChangeInstructionAdded, SevMedium
			c.Message = "new " + string(l.Type) + " file not in lockfile — the agent would follow it; do not trust until reviewed"
			if l.Scope == "descendant" || l.Scope == "ancestor" {
				c.Severity = SevHigh
				c.Message = "new " + string(l.Type) + " file found in " + l.Scope + " directory (" + l.Path + ") — classic injection location; do not follow it until a human reviews"
			}
		}
	default:
		c.Kind, c.Severity = ChangeAdded, SevMedium
		c.Message = "new " + string(l.Type) + " installed (not in lockfile)"
	}
	if hasFlag(l, "unicode_tags") {
		c.Kind, c.Severity = ChangeUnicodeTags, SevCritical
		c.Message = "new " + string(l.Type) + " contains hidden Unicode tag characters"
	} else if hasFlag(l, "suspicious_content") {
		c.Kind, c.Severity = ChangeSuspicious, SevHigh
		c.Message = "new " + string(l.Type) + " contains suspicious instructions"
	}
	return c
}

func compareEntry(key string, p, l *Entry) (Change, bool) {
	c := base(key, l)
	c.ExpectedHash, c.ActualHash = p.Hash, l.Hash

	// Content flags on the live entry escalate regardless of hash state.
	if hasFlag(l, "unicode_tags") && !hasFlag(p, "unicode_tags") {
		c.Kind, c.Severity = ChangeUnicodeTags, SevCritical
		c.Message = "hidden Unicode tag characters appeared in " + string(l.Type)
		c.Details = changedFiles(p, l)
		return c, true
	}

	if p.Type == TypeMCPServer {
		if p.ConfigHash != l.ConfigHash {
			c.Kind, c.Severity = ChangeMCPConfig, SevHigh
			c.Message = "MCP server launch configuration changed (command/args/url/env)"
			c.Details = map[string]any{"pinned": p.MCP, "live": l.MCP}
			return c, true
		}
		if l.ToolsHash != "" && p.ToolsHash != "" && l.ToolsHash != p.ToolsHash {
			c.Kind, c.Severity = ChangeMCPTools, SevCritical
			c.Message = "MCP tool definitions changed since they were pinned"
			c.Details = toolDiff(p.Tools, l.Tools)
			return c, true
		}
		return c, false
	}

	if p.Hash == l.Hash {
		return c, false
	}
	c.Details = changedFiles(p, l)
	switch p.Type {
	case TypeHooks:
		c.Kind, c.Severity = ChangeHooks, SevHigh
		c.Message = "hooks configuration changed"
	case TypeMemory:
		c.Kind, c.Severity = ChangeMemory, SevLow
		c.Message = "memory/instruction file changed"
		if hasFlag(l, "suspicious_content") {
			c.Kind, c.Severity = ChangeSuspicious, SevHigh
			c.Message = "memory/instruction file changed and now contains suspicious instructions"
		}
	default:
		c.Kind, c.Severity = ChangeModified, SevMedium
		c.Message = string(p.Type) + " contents changed since pinned"
		if hasFlag(l, "suspicious_content") {
			c.Kind, c.Severity = ChangeSuspicious, SevHigh
			c.Message = string(p.Type) + " changed and now contains suspicious instructions"
		}
	}
	return c, true
}

func hasFlag(e *Entry, f string) bool {
	for _, x := range e.Flags {
		if x == f {
			return true
		}
	}
	return false
}

func changedFiles(p, l *Entry) map[string]any {
	if p.Files == nil && l.Files == nil {
		return nil
	}
	var modified, added, removed []string
	for f, h := range l.Files {
		ph, ok := p.Files[f]
		if !ok {
			added = append(added, f)
		} else if ph != h {
			modified = append(modified, f)
		}
	}
	for f := range p.Files {
		if _, ok := l.Files[f]; !ok {
			removed = append(removed, f)
		}
	}
	sort.Strings(modified)
	sort.Strings(added)
	sort.Strings(removed)
	d := map[string]any{}
	if len(modified) > 0 {
		d["modified_files"] = modified
	}
	if len(added) > 0 {
		d["added_files"] = added
	}
	if len(removed) > 0 {
		d["removed_files"] = removed
	}
	return d
}

func toolDiff(pinned, live []Tool) map[string]any {
	pm := map[string]Tool{}
	for _, t := range pinned {
		pm[t.Name] = t
	}
	lm := map[string]Tool{}
	for _, t := range live {
		lm[t.Name] = t
	}
	var added, removed, changedDesc, changedSchema []string
	for n, lt := range lm {
		pt, ok := pm[n]
		if !ok {
			added = append(added, n)
			continue
		}
		if pt.DescriptionHash != lt.DescriptionHash {
			changedDesc = append(changedDesc, n)
		}
		if pt.SchemaHash != lt.SchemaHash {
			changedSchema = append(changedSchema, n)
		}
	}
	for n := range pm {
		if _, ok := lm[n]; !ok {
			removed = append(removed, n)
		}
	}
	for _, s := range [][]string{added, removed, changedDesc, changedSchema} {
		sort.Strings(s)
	}
	return map[string]any{
		"added_tools":         added,
		"removed_tools":       removed,
		"description_changed": changedDesc,
		"schema_changed":      changedSchema,
	}
}
