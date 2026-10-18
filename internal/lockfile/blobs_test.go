package lockfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveWritesAndPrunesBlobs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kova.lock")
	lf := New("test")
	content := []byte("# rules\nbe nice\n")
	h := HashBytes(content)
	lf.Entries["k"] = &Entry{Type: TypeMemory, Harness: "claude-code", Name: "x", Hash: h, Content: content}
	if err := lf.Save(path); err != nil {
		t.Fatal(err)
	}
	bd := BlobsDirFor(path)
	got, ok := GetBlob(bd, h)
	if !ok || string(got) != string(content) {
		t.Fatalf("blob not stored: ok=%v %q", ok, got)
	}
	// Reloading the lockfile must not carry content (it is not serialised).
	re, err := Load(path)
	if err != nil || len(re.Entries["k"].Content) != 0 {
		t.Fatalf("content must not be serialised: %v %q", err, re.Entries["k"].Content)
	}
	// Approved hashes keep their blob; everything else unreferenced is pruned.
	keep := HashBytes([]byte("approved elsewhere"))
	_ = PutBlob(bd, keep, []byte("approved elsewhere"))
	_ = PutBlob(bd, HashBytes([]byte("orphan")), []byte("orphan"))
	re.ApprovedHashes = map[string]string{keep: "k2"}
	re.Entries["k"].Hash = HashBytes([]byte("new"))
	re.Entries["k"].Content = []byte("new")
	if err := re.Save(path); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(bd)
	names := map[string]bool{}
	for _, e := range ents {
		names[e.Name()] = true
	}
	if len(names) != 2 || !names[keep[len("sha256:"):]] || !names[HashBytes([]byte("new"))[len("sha256:"):]] {
		t.Fatalf("expected the approved blob and the new pin only, got %v", names)
	}
}
