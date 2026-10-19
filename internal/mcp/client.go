package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ian-hickey/kova/internal/lockfile"
)

// Snapshot is the result of connecting to a server once and listing its tools.
type Snapshot struct {
	ServerName    string
	ServerVersion string
	Instructions  string
	Tools         []Tool
	ToolsHash     string
	Pinned        []lockfile.Tool
}

// snapshotHash computes the pin: instructions + canonical sorted tools.
func snapshotHash(instructions string, tools []Tool) (string, []lockfile.Tool) {
	sorted := append([]Tool(nil), tools...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	pinned := make([]lockfile.Tool, 0, len(sorted))
	canon := make([]any, 0, len(sorted))
	for _, t := range sorted {
		var schema any
		if len(t.InputSchema) > 0 {
			_ = json.Unmarshal(t.InputSchema, &schema)
		}
		desc := t.Description
		if len(desc) > lockfile.MaxToolDescription {
			desc = desc[:lockfile.MaxToolDescription]
		}
		pinned = append(pinned, lockfile.Tool{
			Name:            t.Name,
			DescriptionHash: lockfile.HashBytes([]byte(t.Description)),
			SchemaHash:      lockfile.HashJSON(schema),
			Description:     desc,
		})
		canon = append(canon, map[string]any{"name": t.Name, "description": t.Description, "inputSchema": schema})
	}
	toolsCanon, _ := lockfile.CanonicalJSON(canon)
	return lockfile.HashStrings(instructions, string(toolsCanon)), pinned
}

// HashToolsList is exposed for the proxy, which sees raw tools/list results.
func HashToolsList(instructions string, tools []Tool) (string, []lockfile.Tool) {
	return snapshotHash(instructions, tools)
}

// Connect launches (or dials) the server, performs the MCP handshake and lists tools.
func Connect(ctx context.Context, cfg lockfile.MCPConfig, timeout time.Duration) (*Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	switch cfg.Transport {
	case "stdio":
		return connectStdio(ctx, cfg)
	case "http":
		return connectHTTP(ctx, cfg)
	default:
		return nil, fmt.Errorf("transport %q is not supported for pinning (only stdio and http)", cfg.Transport)
	}
}

// ───────────────────────────── stdio ─────────────────────────────

type stdioConn struct {
	stdin  io.Writer
	out    *bufio.Scanner
	mu     sync.Mutex
	nextID int
}

func connectStdio(ctx context.Context, cfg lockfile.MCPConfig) (*Snapshot, error) {
	cmd := exec.CommandContext(ctx, cfg.Command, cfg.Args...)
	cmd.Env = mergedEnv(cfg.Env)
	cmd.Stderr = io.Discard
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", cfg.Command, err)
	}
	defer func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	return ConnectStream(ctx, stdin, stdout)
}

// ConnectStream performs the handshake over an already-open pair of streams (w is the server's
// stdin, r its stdout). Used for in-process testing and by the proxy.
func ConnectStream(ctx context.Context, w io.Writer, r io.Reader) (*Snapshot, error) {
	conn := &stdioConn{stdin: w, out: lineReader(r)}
	return handshakeAndList(ctx, conn.call, conn.notify)
}

func (c *stdioConn) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	id := c.nextID
	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	b, _ := json.Marshal(req)
	if _, err := c.stdin.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	type res struct {
		msg Message
		err error
	}
	ch := make(chan res, 1)
	go func() {
		for c.out.Scan() {
			line := bytes.TrimSpace(c.out.Bytes())
			if len(line) == 0 || line[0] != '{' {
				continue
			}
			var m Message
			if err := json.Unmarshal(line, &m); err != nil {
				continue
			}
			if string(m.ID) == fmt.Sprint(id) {
				ch <- res{msg: m}
				return
			}
		}
		err := c.out.Err()
		if err == nil {
			err = io.EOF
		}
		ch <- res{err: fmt.Errorf("server closed stdout before answering %s: %w", method, err)}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		if r.msg.Error != nil {
			return nil, fmt.Errorf("%s: %s (code %d)", method, r.msg.Error.Message, r.msg.Error.Code)
		}
		return r.msg.Result, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("%s: %w", method, ctx.Err())
	}
}

func (c *stdioConn) notify(method string, params any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	req := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		req["params"] = params
	}
	b, _ := json.Marshal(req)
	_, err := c.stdin.Write(append(b, '\n'))
	return err
}

func mergedEnv(extra map[string]string) []string {
	env := os.Environ()
	for k, v := range extra {
		env = append(env, k+"="+os.ExpandEnv(v))
	}
	return env
}

// ───────────────────────────── streamable HTTP ─────────────────────────────

type httpConn struct {
	url       string
	headers   map[string]string
	sessionID string
	client    *http.Client
	nextID    int
}

func connectHTTP(ctx context.Context, cfg lockfile.MCPConfig) (*Snapshot, error) {
	conn := &httpConn{url: cfg.URL, headers: map[string]string{}, client: &http.Client{}}
	for k, v := range cfg.Env { // harnesses commonly put headers in "headers"; we accept env-style too
		if strings.HasPrefix(strings.ToLower(k), "header_") {
			conn.headers[k[7:]] = os.ExpandEnv(v)
		}
	}
	return handshakeAndList(ctx, conn.call, conn.notify)
}

func (c *httpConn) post(ctx context.Context, body any) (*http.Response, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", c.sessionID)
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	return c.client.Do(req)
}

func (c *httpConn) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	c.nextID++
	id := c.nextID
	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	resp, err := c.post(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.sessionID = sid
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s: HTTP %d", method, resp.StatusCode)
	}
	var payload []byte
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 64*1024), 32*1024*1024)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "data:") {
				data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				var m Message
				if json.Unmarshal([]byte(data), &m) == nil && string(m.ID) == fmt.Sprint(id) {
					payload = []byte(data)
					break
				}
			}
		}
	} else {
		payload, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
	}
	var m Message
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, fmt.Errorf("%s: bad response: %w", method, err)
	}
	if m.Error != nil {
		return nil, fmt.Errorf("%s: %s (code %d)", method, m.Error.Message, m.Error.Code)
	}
	return m.Result, nil
}

func (c *httpConn) notify(method string, params any) error {
	req := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		req["params"] = params
	}
	resp, err := c.post(context.Background(), req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// ───────────────────────────── shared handshake ─────────────────────────────

type callFn func(ctx context.Context, method string, params any) (json.RawMessage, error)
type notifyFn func(method string, params any) error

func handshakeAndList(ctx context.Context, call callFn, notify notifyFn) (*Snapshot, error) {
	initRaw, err := call(ctx, "initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "kova", "version": "0.1"},
	})
	if err != nil {
		return nil, err
	}
	var init initializeResult
	_ = json.Unmarshal(initRaw, &init)
	_ = notify("notifications/initialized", nil)

	var tools []Tool
	cursor := ""
	for i := 0; i < 50; i++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		raw, err := call(ctx, "tools/list", params)
		if err != nil {
			return nil, err
		}
		var page toolsListResult
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, fmt.Errorf("tools/list: bad result: %w", err)
		}
		tools = append(tools, page.Tools...)
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	hash, pinned := snapshotHash(init.Instructions, tools)
	return &Snapshot{
		ServerName: init.ServerInfo.Name, ServerVersion: init.ServerInfo.Version, Instructions: init.Instructions,
		Tools: tools, ToolsHash: hash, Pinned: pinned,
	}, nil
}
