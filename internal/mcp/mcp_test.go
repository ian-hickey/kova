package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ian-hickey/kova/internal/demoserver"
	"github.com/ian-hickey/kova/internal/lockfile"
)

// TestHelperProcess lets the test binary act as the drifting demo server for proxy tests.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("KOVA_HELPER_DEMO") == "" {
		return
	}
	_ = demoserver.Serve(os.Stdin, os.Stdout, demoserver.Options{DriftAfter: 2, HiddenTags: os.Getenv("KOVA_HELPER_TAGS") == "1"})
	os.Exit(0)
}

func TestConnectStreamPinsTools(t *testing.T) {
	cIn, sOut := io.Pipe() // server writes -> client reads
	sIn, cOut := io.Pipe() // client writes -> server reads
	go func() { _ = demoserver.Serve(sIn, sOut, demoserver.Options{}) }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snap, err := ConnectStream(ctx, cOut, cIn)
	if err != nil {
		t.Fatal(err)
	}
	if snap.ServerName != "markdown-helper" || len(snap.Tools) != 1 || snap.Tools[0].Name != "format_markdown" {
		t.Fatalf("unexpected snapshot %+v", snap)
	}
	if !strings.HasPrefix(snap.ToolsHash, "sha256:") || len(snap.Pinned) != 1 {
		t.Fatalf("bad pin %+v", snap)
	}
	// Deterministic across connections
	cIn2, sOut2 := io.Pipe()
	sIn2, cOut2 := io.Pipe()
	go func() { _ = demoserver.Serve(sIn2, sOut2, demoserver.Options{}) }()
	snap2, err := ConnectStream(ctx, cOut2, cIn2)
	if err != nil {
		t.Fatal(err)
	}
	if snap2.ToolsHash != snap.ToolsHash {
		t.Fatal("tools hash not deterministic")
	}
}

func req(id int, method string, params any) []byte {
	m := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		m["params"] = params
	}
	b, _ := json.Marshal(m)
	return append(b, '\n')
}

func TestProxyCatchesDriftAfterNCalls(t *testing.T) {
	for _, enforce := range []bool{false, true} {
		var in bytes.Buffer
		in.Write(req(1, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "t"}}))
		in.Write(req(2, "tools/list", nil))
		in.Write(req(3, "tools/call", map[string]any{"name": "format_markdown", "arguments": map[string]any{"text": "a"}}))
		in.Write(req(4, "tools/call", map[string]any{"name": "format_markdown", "arguments": map[string]any{"text": "b"}}))
		in.Write(req(5, "tools/list", nil))

		var out, errBuf bytes.Buffer
		var events []Event
		var pinned string
		opts := ProxyOptions{
			Name: "markdown-helper",
			Config: lockfile.MCPConfig{Transport: "stdio", Command: os.Args[0], Args: []string{"-test.run=TestHelperProcess"},
				Env: map[string]string{"KOVA_HELPER_DEMO": "1"}},
			Enforce: enforce, NetWatch: false,
			Stdin: &in, Stdout: &out, Stderr: &errBuf,
			OnEvent: func(e Event) { events = append(events, e) },
			OnPin:   func(h string, _ []lockfile.Tool, _ string, _ int) { pinned = h },
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		if err := RunProxy(ctx, opts); err != nil {
			cancel()
			t.Fatal(err)
		}
		cancel()
		if pinned == "" {
			t.Fatal("expected trust-on-first-use pin")
		}
		if len(events) != 1 || events[0].Kind != lockfile.ChangeMCPTools || events[0].Severity != lockfile.SevCritical {
			t.Fatalf("enforce=%v: expected one critical mcp_tools_changed event, got %+v (stderr: %s)", enforce, events, errBuf.String())
		}
		added, _ := events[0].Details["added_tools"].([]string)
		if len(added) != 1 || added[0] != "sync_settings" {
			t.Fatalf("expected sync_settings added, got %v", events[0].Details)
		}
		// Inspect the response to request 5.
		var last Message
		for _, line := range bytes.Split(bytes.TrimSpace(out.Bytes()), []byte("\n")) {
			var m Message
			if json.Unmarshal(line, &m) == nil && string(m.ID) == "5" {
				last = m
			}
		}
		if enforce {
			if last.Error == nil || !strings.Contains(last.Error.Message, "kova") {
				t.Fatalf("enforce: expected error response for drifted tools/list, got %s", out.String())
			}
		} else {
			if last.Error != nil || !bytes.Contains(last.Result, []byte("sync_settings")) {
				t.Fatalf("alert mode: expected drifted result passed through, got %s", out.String())
			}
		}
	}
}

func TestProxyHelperFound(t *testing.T) {
	// Sanity: the helper binary runs.
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
	cmd.Env = append(os.Environ(), "KOVA_HELPER_DEMO=1")
	cmd.Stdin = strings.NewReader(string(req(1, "ping", nil)))
	outp, err := cmd.Output()
	if err != nil || !bytes.Contains(outp, []byte(`"id":1`)) {
		t.Fatalf("helper did not answer: %v %s", err, outp)
	}
}
