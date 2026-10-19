// Package lockfile defines the kova.lock format: a content-addressed inventory of every
// skill, plugin, MCP server, hook configuration and memory file an agent harness will load.
package lockfile

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const Version = 1

// ArtifactType enumerates the things we pin.
type ArtifactType string

const (
	TypeSkill     ArtifactType = "skill"
	TypePlugin    ArtifactType = "plugin"
	TypeMCPServer ArtifactType = "mcp_server"
	TypeMemory    ArtifactType = "memory"
	TypeHooks     ArtifactType = "hooks"
	TypeRules     ArtifactType = "rules"
	TypeExtension ArtifactType = "extension"
	TypeCommand   ArtifactType = "command"   // slash commands (.claude/commands)
	TypeAgent     ArtifactType = "agent"     // subagent prompts (.claude/agents)
	TypeConfig    ArtifactType = "config"    // harness settings files with security-relevant content (e.g. ~/.copilot/config.json)
	TypeConnector ArtifactType = "connector" // claude.ai account connectors, inventoried via `claude mcp list` (never on disk)
)

// IsInstruction reports whether an artifact type is text the model follows as instructions.
func (t ArtifactType) IsInstruction() bool {
	return t == TypeMemory || t == TypeRules || t == TypeCommand || t == TypeAgent
}

// Harness identifiers.
const (
	HarnessClaudeCode    = "claude-code"
	HarnessCodex         = "codex"
	HarnessGeminiCLI     = "gemini-cli"
	HarnessCursor        = "cursor"
	HarnessGitHubCopilot = "github-copilot" // Copilot CLI + VS Code Copilot (agent mode)
	HarnessClaudeDesktop = "claude-desktop"
	HarnessWindsurf      = "windsurf"
	HarnessCline         = "cline" // Cline and Roo Code (shared config shapes)
)

var AllHarnesses = []string{
	HarnessClaudeCode, HarnessCodex, HarnessGeminiCLI, HarnessCursor,
	HarnessGitHubCopilot, HarnessClaudeDesktop, HarnessWindsurf, HarnessCline,
}

// Tool is a pinned MCP tool definition.
type Tool struct {
	Name            string `json:"name"`
	DescriptionHash string `json:"description_hash"`
	SchemaHash      string `json:"schema_hash"`
	// Description keeps the text (capped) so a tools/list change can show, and triage can judge,
	// what the new wording asks the model to do.
	Description string `json:"description,omitempty"`
}

// MaxToolDescription bounds the stored description text.
const MaxToolDescription = 4000

// MCPConfig captures how a server is launched so we can detect config drift and wrap it.
type MCPConfig struct {
	Transport string            `json:"transport"` // stdio | http | sse
	Command   string            `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	URL       string            `json:"url,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
}

// Entry is one pinned artifact.
type Entry struct {
	Type      ArtifactType      `json:"type"`
	Harness   string            `json:"harness"`
	Name      string            `json:"name"`
	Scope     string            `json:"scope"`             // user | project
	Project   string            `json:"project,omitempty"` // absolute project path for project-scoped entries
	Path      string            `json:"path,omitempty"`    // file or directory on disk
	Hash      string            `json:"hash"`              // sha256:<hex> over the canonical content
	Files     map[string]string `json:"files,omitempty"`   // relative file -> sha256:<hex>
	Size      int64             `json:"size,omitempty"`
	FirstSeen time.Time         `json:"first_seen"`
	UpdatedAt time.Time         `json:"updated_at"`
	Approved  bool              `json:"approved"` // explicitly approved by a human via `kova approve`

	// MCP-specific
	MCP           *MCPConfig `json:"mcp,omitempty"`
	ConfigHash    string     `json:"config_hash,omitempty"`
	ToolsHash     string     `json:"tools_hash,omitempty"`
	Tools         []Tool     `json:"tools,omitempty"`
	ToolsPinnedAt *time.Time `json:"tools_pinned_at,omitempty"`
	Wrapped       *MCPConfig `json:"wrapped_original,omitempty"` // original config before `kova wrap`

	// Hooks keeps the canonical (kova-stripped) hook configuration for hooks entries, so a
	// hooks_changed report can say which commands were added or removed, not just that the hash moved.
	Hooks json.RawMessage `json:"hooks,omitempty"`

	Flags []string `json:"flags,omitempty"` // e.g. unicode_tags, suspicious_content

	// Content is the file text of a single-file instruction artifact, carried from discovery to
	// Save, which stores it in the blob directory (never serialised into the lockfile itself).
	Content []byte `json:"-"`
}

// Lockfile is the on-disk document.
type Lockfile struct {
	Version     int               `json:"version"`
	MachineID   string            `json:"machine_id"`
	Generator   string            `json:"generator"`
	GeneratedAt time.Time         `json:"generated_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Projects    []string          `json:"projects"` // absolute paths of projects that have been inited
	Entries     map[string]*Entry `json:"entries"`
	// ApprovedHashes remembers every content hash a human approved on this machine (hash -> the
	// key it was first approved under). The same content appearing under another key (a worktree,
	// a second checkout, a vendored copy) is then accepted without a second decision.
	ApprovedHashes map[string]string `json:"approved_hashes,omitempty"`
	// SeenHashes remembers content kova accepted for a key without a human because it arrived
	// through git (hash -> key). Switching back to a branch already visited is then silent.
	SeenHashes map[string]string `json:"seen_hashes,omitempty"`
}

// MaxSeenHashes caps SeenHashes; beyond it, arbitrary entries are dropped (the cost of a miss is
// one more low-severity event, not a wrong decision).
const MaxSeenHashes = 2000

// MarkSeen records that content hash was accepted for key through git.
func (lf *Lockfile) MarkSeen(hash, key string) {
	if hash == "" || key == "" {
		return
	}
	if lf.SeenHashes == nil {
		lf.SeenHashes = map[string]string{}
	}
	lf.SeenHashes[hash] = key
	for h := range lf.SeenHashes {
		if len(lf.SeenHashes) <= MaxSeenHashes {
			break
		}
		if h != hash {
			delete(lf.SeenHashes, h)
		}
	}
}

// Key builds the canonical entry key.
func Key(harness string, t ArtifactType, name string) string {
	return fmt.Sprintf("%s:%s:%s", harness, t, name)
}

// New returns an empty lockfile with a fresh machine id.
func New(generator string) *Lockfile {
	now := time.Now().UTC()
	return &Lockfile{
		Version:     Version,
		MachineID:   newMachineID(),
		Generator:   generator,
		GeneratedAt: now,
		UpdatedAt:   now,
		Entries:     map[string]*Entry{},
	}
}

func newMachineID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Load reads a lockfile from disk. Returns os.ErrNotExist if absent.
func Load(path string) (*Lockfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lf Lockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if lf.Version != Version {
		return nil, fmt.Errorf("unsupported lockfile version %d (want %d)", lf.Version, Version)
	}
	if lf.Entries == nil {
		lf.Entries = map[string]*Entry{}
	}
	return &lf, nil
}

// Save writes atomically.
func (lf *Lockfile) Save(path string) error {
	lf.UpdatedAt = time.Now().UTC()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	lf.writeBlobs(BlobsDirFor(path))
	return nil
}

// SortedKeys returns entry keys in deterministic order.
func (lf *Lockfile) SortedKeys() []string {
	keys := make([]string, 0, len(lf.Entries))
	for k := range lf.Entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// AddProject records a project path (deduplicated).
func (lf *Lockfile) AddProject(p string) {
	for _, existing := range lf.Projects {
		if existing == p {
			return
		}
	}
	lf.Projects = append(lf.Projects, p)
	sort.Strings(lf.Projects)
}

// ContentHash hashes the whole lockfile's entries deterministically (used for cloud snapshots).
func (lf *Lockfile) ContentHash() string {
	parts := make([]string, 0, len(lf.Entries))
	for _, k := range lf.SortedKeys() {
		parts = append(parts, k+"="+lf.Entries[k].Hash)
	}
	return HashStrings(parts...)
}

// ErrNoLockfile is returned by commands that need an existing lockfile.
var ErrNoLockfile = errors.New("no lockfile found; run `kova init` first")
