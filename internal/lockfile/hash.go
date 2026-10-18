package lockfile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// HashBytes returns "sha256:<hex>".
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// HashStrings hashes a sequence of strings with length framing.
func HashStrings(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%d:", len(p))
		h.Write([]byte(p))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// HashJSON hashes the canonical (sorted-key) JSON encoding of v.
func HashJSON(v any) string {
	b, err := CanonicalJSON(v)
	if err != nil {
		return HashBytes([]byte(fmt.Sprintf("%v", v)))
	}
	return HashBytes(b)
}

// CanonicalJSON marshals with sorted object keys and no insignificant whitespace.
func CanonicalJSON(v any) ([]byte, error) {
	// Round-trip through interface{} so struct field order doesn't matter.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	var sb strings.Builder
	if err := writeCanonical(&sb, generic); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

func writeCanonical(sb *strings.Builder, v any) error {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			sb.Write(kb)
			sb.WriteByte(':')
			if err := writeCanonical(sb, t[k]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	case []any:
		sb.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := writeCanonical(sb, e); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return err
		}
		sb.Write(b)
	}
	return nil
}

// HashFile hashes a single file's contents.
func HashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), n, nil
}

// Ignored directory names inside skills/plugins (never part of what the agent loads).
var ignoredDirs = map[string]bool{
	".git": true, "node_modules": true, "__pycache__": true, ".venv": true, "venv": true,
	".cache": true, "dist": true, "build": true, ".next": true,
	".in_use": true, // Claude Code plugin runtime lock files (one per process)
}

// Ignored file names / suffixes: OS droppings and runtime artifacts, never loaded by an agent.
var ignoredFiles = map[string]bool{".DS_Store": true, "Thumbs.db": true, "desktop.ini": true}
var ignoredSuffixes = []string{".pyc", ".pyo", ".log", ".swp", ".tmp"}

func ignoredFile(name string) bool {
	if ignoredFiles[name] {
		return true
	}
	for _, s := range ignoredSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// HashTree hashes every regular file under root (relative path + content), returning the
// aggregate hash, a per-file map and the total size. Symlinks are hashed by their target path
// (not followed) so a skill cannot smuggle in content from elsewhere on disk unnoticed.
func HashTree(root string) (string, map[string]string, int64, error) {
	files := map[string]string{}
	var total int64
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && ignoredDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if ignoredFile(d.Name()) {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			files[rel] = HashStrings("symlink", target)
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		h, n, err := HashFile(p)
		if err != nil {
			return err
		}
		files[rel] = h
		total += n
		return nil
	})
	if err != nil {
		return "", nil, 0, err
	}
	rels := make([]string, 0, len(files))
	for r := range files {
		rels = append(rels, r)
	}
	sort.Strings(rels)
	parts := make([]string, 0, len(rels)*2)
	for _, r := range rels {
		parts = append(parts, r, files[r])
	}
	return HashStrings(parts...), files, total, nil
}
