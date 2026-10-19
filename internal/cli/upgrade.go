package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ian-hickey/kova/internal/hooks"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const releaseRepo = "ian-hickey/kova"

// cmdUpgrade replaces the running binary with a GitHub release build for this OS/arch, verifying
// the published SHA-256 first. The swap is a rename into place; on Windows the running executable
// is renamed aside first because it cannot be overwritten while it runs.
func (a *App) cmdUpgrade(args []string) int {
	fs := newFlags("upgrade")
	want := fs.String("version", "", "release tag to install (default: latest)")
	force := fs.Bool("force", false, "reinstall even if already on that version")
	if err := fs.Parse(args); err != nil {
		return a.errorf("%v", err)
	}
	client := &http.Client{Timeout: 60 * time.Second}

	tag := *want
	if tag == "" {
		t, err := latestTag(client)
		if err != nil {
			return a.errorf("could not determine the latest release: %v", err)
		}
		tag = t
	}
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	if !*force && (Version == tag || "v"+Version == tag) {
		a.printf("kova %s is already the %s release.\n", Version, tag)
		return ExitOK
	}

	exe, err := os.Executable()
	if err != nil {
		return a.errorf("cannot locate the running binary: %v", err)
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	asset := fmt.Sprintf("kova-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		asset += ".exe"
	}
	base := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", releaseRepo, tag, asset)

	a.printf("Downloading kova %s for %s/%s ...\n", tag, runtime.GOOS, runtime.GOARCH)
	tmp := exe + ".new"
	if err := download(client, base, tmp); err != nil {
		return a.errorf("%v", err)
	}
	defer os.Remove(tmp)
	sum, err := fetchString(client, base+".sha256")
	if err != nil {
		return a.errorf("checksum file: %v", err)
	}
	want256 := strings.Fields(sum)
	if len(want256) == 0 {
		return a.errorf("checksum file for %s is empty", asset)
	}
	got, err := fileSHA256(tmp)
	if err != nil {
		return a.errorf("%v", err)
	}
	if !strings.EqualFold(got, want256[0]) {
		return a.errorf("checksum mismatch for %s: release says %s, download is %s", asset, want256[0], got)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return a.errorf("%v", err)
	}
	if runtime.GOOS == "windows" {
		old := exe + ".old"
		_ = os.Remove(old)
		if err := os.Rename(exe, old); err != nil {
			return a.errorf("cannot move the running binary aside: %v", err)
		}
	}
	if err := os.Rename(tmp, exe); err != nil {
		return a.errorf("cannot replace %s: %v (try again with permission to write there)", exe, err)
	}
	a.printf("Installed kova %s at %s (was %s).\n", tag, exe, Version)
	// Re-run hook installation with the NEW binary so hook entries added since (observed-edit
	// tracking, new harness dialects) land without a separate step.
	for _, st := range hooks.Check(a.Home, exe) {
		if !st.Installed {
			continue
		}
		cmd := exec.Command(exe, "hooks", "install", "--harness", st.Harness)
		cmd.Env = os.Environ()
		if outb, err := cmd.CombinedOutput(); err != nil {
			a.printf("  ! could not refresh %s hooks: %v %s\n", st.Harness, err, strings.TrimSpace(string(outb)))
		} else {
			a.printf("  hooks refreshed for %s\n", st.Harness)
		}
	}
	if outb, err := exec.Command(exe, "skills", "refresh").CombinedOutput(); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(outb)), "\n") {
			if strings.Contains(line, "refreshed") {
				a.printf("  %s\n", line)
			}
		}
	}
	if runtime.GOOS == "windows" {
		a.printf("The previous binary was left at %s.old and can be deleted.\n", exe)
	}
	return ExitOK
}

func latestTag(c *http.Client) (string, error) {
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/"+releaseRepo+"/releases/latest", nil)
	req.Header.Set("User-Agent", "kova-upgrade")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GitHub API returned %s", resp.Status)
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil || rel.TagName == "" {
		return "", fmt.Errorf("unexpected release response")
	}
	return rel.TagName, nil
}

func download(c *http.Client, url, dst string) error {
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download %s: %s", url, resp.Status)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func fetchString(c *http.Client, url string) (string, error) {
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return string(b), err
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
