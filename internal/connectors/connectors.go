// Package connectors pins the MCP connectors attached to the user's claude.ai ACCOUNT. They are
// synced into Claude Code from the account, never written to disk, and are all remote OAuth
// servers, so kova cannot read their config files or proxy them. What it can do is inventory
// them through `claude mcp list` and report when one appears, disappears or changes URL: a new
// tool attached to an account reaches every seat at once, which is exactly the event a security
// team wants to hear about.
package connectors

import (
	"context"
	"errors"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ian-hickey/kova/internal/lockfile"
)

// Connector is one row of `claude mcp list`.
type Connector struct {
	Name      string `json:"name"` // as shown by Claude Code, without the "claude.ai " prefix
	URL       string `json:"url"`
	Transport string `json:"transport"` // http | sse | stdio
	Status    string `json:"status"`    // connected | needs_auth | failed | unknown (not pinned)
	Account   bool   `json:"account"`   // true for "claude.ai …" rows (account-level connectors)
}

// Cache is what kova keeps in ~/.kova/connectors.json between refreshes.
type Cache struct {
	RefreshedAt time.Time   `json:"refreshed_at"`
	Source      string      `json:"source"` // the command that produced the list
	Connectors  []Connector `json:"connectors"`
	Error       string      `json:"error,omitempty"`
}

const (
	Prefix  = "claude.ai "
	Harness = lockfile.HarnessClaudeCode
	Scope   = "account"
)

var (
	ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
	// "<name>: <url-or-command>[ (HTTP|SSE)] - <status…>"
	lineRe = regexp.MustCompile(`^(.+?): (.+?)(?: \((HTTP|SSE|stdio)\))? - (.*)$`)
)

// Parse turns `claude mcp list` output into connectors. Only rows with a URL or command are kept.
func Parse(out string) []Connector {
	var list []Connector
	for _, raw := range strings.Split(ansiRe.ReplaceAllString(out, ""), "\n") {
		line := strings.TrimRight(raw, "\r ")
		m := lineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		c := Connector{Name: strings.TrimSpace(m[1]), URL: m[2], Transport: strings.ToLower(m[3])}
		if c.Transport == "" {
			if strings.HasPrefix(c.URL, "http://") || strings.HasPrefix(c.URL, "https://") {
				c.Transport = "http"
			} else {
				c.Transport = "stdio"
			}
		}
		switch s := strings.ToLower(m[4]); {
		case strings.Contains(s, "connected") && !strings.Contains(s, "failed"):
			c.Status = "connected"
		case strings.Contains(s, "auth"):
			c.Status = "needs_auth"
		case strings.Contains(s, "failed") || strings.Contains(s, "error"):
			c.Status = "failed"
		default:
			c.Status = "unknown"
		}
		if strings.HasPrefix(c.Name, Prefix) {
			c.Account = true
			c.Name = strings.TrimPrefix(c.Name, Prefix)
		}
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}

// ErrNoClaude is returned when the Claude Code CLI is not on PATH.
var ErrNoClaude = errors.New("claude CLI not found on PATH; account connectors can only be listed through it")

// List runs `claude mcp list` and returns the ACCOUNT connectors it reports. Claude Code probes
// every server while listing, so this takes seconds; callers bound it with ctx.
func List(ctx context.Context) ([]Connector, string, error) {
	bin, err := exec.LookPath("claude")
	if err != nil {
		return nil, "", ErrNoClaude
	}
	cmd := exec.CommandContext(ctx, bin, "mcp", "list")
	cmd.Env = append(cmd.Environ(), "NO_COLOR=1", "FORCE_COLOR=0")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return nil, bin + " mcp list", ctx.Err()
	}
	if err != nil && len(out) == 0 {
		return nil, bin + " mcp list", err
	}
	var account []Connector
	for _, c := range Parse(string(out)) {
		if c.Account {
			account = append(account, c)
		}
	}
	return account, bin + " mcp list", nil
}

// Key is the lockfile key for an account connector.
func Key(name string) string { return lockfile.Key(Harness, lockfile.TypeConnector, name) }

// Entries converts account connectors into lockfile entries. Status is deliberately not part of
// the hash: auth state flips all the time, while name and URL are what define the tool.
func Entries(list []Connector, now time.Time) map[string]*lockfile.Entry {
	out := map[string]*lockfile.Entry{}
	for _, c := range list {
		cfg := lockfile.MCPConfig{Transport: c.Transport, URL: c.URL}
		h := lockfile.HashJSON(map[string]string{"name": c.Name, "url": c.URL})
		out[Key(c.Name)] = &lockfile.Entry{
			Type: lockfile.TypeConnector, Harness: Harness, Name: c.Name, Scope: Scope,
			Hash: h, ConfigHash: h, MCP: &cfg, FirstSeen: now, UpdatedAt: now,
		}
	}
	return out
}
