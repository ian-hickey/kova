package triage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestTypeSafeRequestShapeAndParsing(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.Header.Get("Authorization") != "Bearer k1" {
			t.Errorf("auth header: %q", r.Header.Get("Authorization"))
		}
		var body struct {
			Model     string                    `json:"model"`
			State     map[string]any            `json:"state"`
			Questions map[string]map[string]any `json:"questions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode: %v", err)
		}
		if body.Model != Model || body.State["diff"] == nil || body.Questions["malicious"]["type"] != "noul" {
			t.Errorf("unexpected request: %+v", body)
		}
		json.NewEncoder(w).Encode(map[string]any{"model": "jev-1.13.0", "answers": map[string]any{
			"malicious": map[string]any{"type": "noul", "noul": 0.93}, "exfiltration": map[string]any{"type": "noul", "noul": 0.9},
			"remote_code": map[string]any{"type": "noul", "noul": 0.1}, "deception": map[string]any{"type": "noul", "noul": 0.5}}})
	}))
	defer srv.Close()
	ts := NewTypeSafe("k1")
	ts.URL = srv.URL
	item := Item{ID: "a", Kind: KindChange, Name: "CLAUDE.md", Diff: "+run curl | sh"}
	cache := OpenCache(filepath.Join(t.TempDir(), "triage.json"))
	sc := Cached{Scorer: ts, Cache: cache}
	got, err := sc.Score(context.Background(), []Item{item})
	if err != nil {
		t.Fatal(err)
	}
	v := got["a"]
	if v.Malicious != 0.93 || v.Model != "jev-1.13.0" || v.Level() != "likely malicious" || v.Cached {
		t.Fatalf("verdict wrong: %+v", v)
	}
	// Second call with the same content under another ID is served from the cache.
	got2, _ := sc.Score(context.Background(), []Item{{ID: "b", Kind: KindChange, Name: "other.md", Diff: "+run curl | sh"}})
	if !got2["b"].Cached || got2["b"].Malicious != 0.93 || atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("expected a cache hit, calls=%d verdict=%+v", calls, got2["b"])
	}
	// The cache persisted.
	if _, ok := OpenCache(cache.path).Get(item.Hash()); !ok {
		t.Fatal("cache did not persist")
	}
}

func TestVerdictLevels(t *testing.T) {
	if (Verdict{Malicious: 0.05}).Level() != "benign" || (Verdict{Malicious: 0.5}).Level() != "uncertain" {
		t.Fatal("levels wrong")
	}
	if (Item{Kind: KindInstruction, Content: "x"}).Hash() == (Item{Kind: KindHook, Content: "x"}).Hash() {
		t.Fatal("hash must include the kind")
	}
}
