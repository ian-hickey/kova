package lockfile

import (
	"os"
	"path/filepath"
	"strings"
)

// Blobs: a tiny content-addressed store beside the lockfile (`~/.kova/blobs/<hex>`) holding the
// text of every pinned single-file instruction artifact (CLAUDE.md, AGENTS.md, rules, commands,
// agents). It exists so `kova verify` can show WHAT changed in a file, and so the optional triage
// stage can judge the edit instead of the whole file. Trees (skills, plugins) are not stored.
const MaxBlobSize = 256 << 10

// BlobsDirFor returns the blob directory for a lockfile path.
func BlobsDirFor(lockfilePath string) string {
	return filepath.Join(filepath.Dir(lockfilePath), "blobs")
}

func blobPath(dir, hash string) string {
	return filepath.Join(dir, strings.TrimPrefix(hash, "sha256:"))
}

// PutBlob stores content under hash (no-op when present).
func PutBlob(dir, hash string, content []byte) error {
	if hash == "" || len(content) == 0 || len(content) > MaxBlobSize {
		return nil
	}
	p := blobPath(dir, hash)
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// GetBlob returns the stored content for hash.
func GetBlob(dir, hash string) ([]byte, bool) {
	if hash == "" {
		return nil, false
	}
	data, err := os.ReadFile(blobPath(dir, hash))
	if err != nil {
		return nil, false
	}
	return data, true
}

// writeBlobs stores the content carried by entries and drops blobs nothing references any more
// (pinned hashes and approved hashes stay).
func (lf *Lockfile) writeBlobs(dir string) {
	keep := map[string]bool{}
	for _, e := range lf.Entries {
		if e.Hash != "" {
			keep[strings.TrimPrefix(e.Hash, "sha256:")] = true
		}
		if len(e.Content) > 0 {
			_ = PutBlob(dir, e.Hash, e.Content)
		}
	}
	for h := range lf.ApprovedHashes {
		keep[strings.TrimPrefix(h, "sha256:")] = true
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, d := range ents {
		if d.IsDir() || strings.HasSuffix(d.Name(), ".tmp") {
			continue
		}
		if !keep[d.Name()] {
			_ = os.Remove(filepath.Join(dir, d.Name()))
		}
	}
}
