// Package known holds the allowlists that keep kova quiet about things everyone already trusts:
// installer scripts from well-known hosts, and instruction files shipped verbatim inside popular
// packages. The embedded lists are the floor; a signed list published at kovaverified.io can
// extend them (see Refresh) so new entries reach users without a release.
package known

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Source says where a known-benign artifact comes from.
type Source struct {
	Package string `json:"package"`
	Note    string `json:"note,omitempty"`
}

var (
	mu sync.RWMutex

	// benign: sha256 hex of an instruction file -> the package that ships it. Seeded from npm
	// tarballs; a file that matches byte-for-byte is the package's own, not an injection.
	benign = map[string]Source{
		"a0a11c391399292708d332d794aaca6160e4b4d256157eb281acc3677eef352a": {Package: "ts-loader@9.6.2", Note: "CLAUDE.md shipped in the npm package (points at AGENTS.md)"},
		"b5e4c21aa4757211d314c11289909fcc2c412fe1b3e74fb0d3cc56c907a2f306": {Package: "ts-loader@9.6.2", Note: "AGENTS.md shipped in the npm package (build/test instructions for contributors)"},
	}

	// installers: hosts whose `curl … | sh` scripts are the documented install path for widely
	// used tools. Piping one of these is routine; piping anything else still gets flagged.
	installers = map[string]bool{
		"kovaverified.io": true, "www.kovaverified.io": true,
		"sh.rustup.rs": true, "rustup.rs": true,
		"get.docker.com": true,
		"brew.sh":        true, "raw.githubusercontent.com/Homebrew": true,
		"bun.sh": true, "deno.land": true,
		"get.pnpm.io": true, "raw.githubusercontent.com/nvm-sh": true, "fnm.vercel.app": true,
		"astral.sh": true, "install.python-poetry.org": true, "pyenv.run": true,
		"ollama.com": true, "ollama.ai": true,
		"tailscale.com": true, "get.helm.sh": true, "cli.nexus.dev": true,
		"claude.ai": true, "cursor.com": true, "windsurf.com": true, "codeium.com": true,
		"mise.run": true, "get.sdkman.io": true, "get.volta.sh": true, "starship.rs": true,
		"install.determinate.systems": true, "nixos.org": true,
	}
)

// Benign reports the package that ships a file with this content hash ("sha256:…" or bare hex).
func Benign(hash string) (Source, bool) {
	h := strings.TrimPrefix(hash, "sha256:")
	mu.RLock()
	defer mu.RUnlock()
	s, ok := benign[h]
	return s, ok
}

var urlRe = regexp.MustCompile(`https?://[^\s'"|)>]+`)

// InstallerText reports whether every URL in a `curl … | sh`-style text points at a known
// installer host (or host/first-path-segment, for GitHub raw URLs). Text with no URL is not known.
func InstallerText(text string) bool {
	urls := urlRe.FindAllString(text, -1)
	if len(urls) == 0 {
		return false
	}
	mu.RLock()
	defer mu.RUnlock()
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return false
		}
		host := strings.ToLower(u.Host)
		seg := host
		if parts := strings.SplitN(strings.TrimPrefix(u.Path, "/"), "/", 2); len(parts) > 0 && parts[0] != "" {
			seg = host + "/" + parts[0]
		}
		if !installers[host] && !installers[seg] {
			return false
		}
	}
	return true
}

// Add merges extra entries (from the published list) into the embedded ones.
func Add(b map[string]Source, hosts []string) {
	mu.Lock()
	defer mu.Unlock()
	for h, s := range b {
		benign[strings.TrimPrefix(h, "sha256:")] = s
	}
	for _, h := range hosts {
		installers[strings.ToLower(h)] = true
	}
}

// Published is the shape of https://kovaverified.io/known.json.
type Published struct {
	UpdatedAt  time.Time         `json:"updated_at"`
	Benign     map[string]Source `json:"benign"`
	Installers []string          `json:"installers"`
}

// DefaultURL is where the published list lives.
const DefaultURL = "https://kovaverified.io/known.json"

// Refresh loads the cached published list, re-fetches it when older than maxAge, and merges it.
// Failures are silent: the embedded lists always apply.
func Refresh(ctx context.Context, cachePath string, maxAge time.Duration) {
	var cached Published
	if b, err := os.ReadFile(cachePath); err == nil {
		_ = json.Unmarshal(b, &cached)
	}
	if cached.UpdatedAt.IsZero() || time.Since(cached.UpdatedAt) > maxAge {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, DefaultURL, nil)
		req.Header.Set("User-Agent", "kova")
		if resp, err := http.DefaultClient.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				var fresh Published
				if json.NewDecoder(resp.Body).Decode(&fresh) == nil && (len(fresh.Benign) > 0 || len(fresh.Installers) > 0) {
					fresh.UpdatedAt = time.Now().UTC()
					if b, err := json.Marshal(fresh); err == nil {
						_ = os.WriteFile(cachePath, b, 0o600)
					}
					cached = fresh
				}
			}
		}
	}
	Add(cached.Benign, cached.Installers)
}
