// Package store holds kova's local state under ~/.kova (or $KOVA_HOME): config, lockfile,
// append-only JSONL logs for drift events and the install ledger, and sync offsets.
package store

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

var mu sync.Mutex

// Dir returns the kova state directory, creating it if needed.
func Dir() string {
	if d := os.Getenv("KOVA_HOME"); d != "" {
		_ = os.MkdirAll(d, 0o700)
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	d := filepath.Join(home, ".kova")
	_ = os.MkdirAll(d, 0o700)
	return d
}

// Paths inside Dir().
func LockfilePath() string { return filepath.Join(Dir(), "kova.lock") }
func ConfigPath() string   { return filepath.Join(Dir(), "config.json") }
func EventsPath() string   { return filepath.Join(Dir(), "events.jsonl") }
func LedgerPath() string   { return filepath.Join(Dir(), "ledger.jsonl") }
func SyncPath() string     { return filepath.Join(Dir(), "sync.json") }
func BackupDir() string {
	d := filepath.Join(Dir(), "backups")
	_ = os.MkdirAll(d, 0o700)
	return d
}

// AppendJSONL appends one JSON document as a line.
func AppendJSONL(path string, v any) error {
	mu.Lock()
	defer mu.Unlock()
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

// ReadJSONL decodes every line into a slice of T. Missing file yields an empty slice.
func ReadJSONL[T any](path string) ([]T, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []T
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var v T
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			continue
		}
		out = append(out, v)
	}
	return out, sc.Err()
}

// ReadJSON / WriteJSON for small documents.
func ReadJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func WriteJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}
