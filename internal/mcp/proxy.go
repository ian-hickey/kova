package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/ian-hickey/kova/internal/lockfile"
)

// Event is something the proxy observed that a human should know about.
type Event struct {
	Kind     lockfile.ChangeKind `json:"kind"`
	Severity lockfile.Severity   `json:"severity"`
	Message  string              `json:"message"`
	Details  map[string]any      `json:"details,omitempty"`
	At       time.Time           `json:"at"`
}

// ProxyOptions configure a verifying stdio proxy.
type ProxyOptions struct {
	Name     string
	Config   lockfile.MCPConfig // the ORIGINAL server launch config
	Pinned   *lockfile.Entry    // lockfile entry for this server; may be nil (trust on first use)
	Enforce  bool               // replace drifted tools/list results with a JSON-RPC error
	NetWatch bool               // snapshot network destinations around each tools/call

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	OnEvent func(Event)
	// OnPin is called with the first tools/list seen when no pin exists yet.
	OnPin func(hash string, tools []lockfile.Tool, instructions string, toolCount int)
}

type pending struct {
	method    string
	toolName  string
	netBefore map[string]bool
}

// RunProxy launches the server and relays JSON-RPC between opts.Stdin/Stdout and the child,
// verifying every tools/list response against the pinned tools hash.
func RunProxy(ctx context.Context, opts ProxyOptions) error {
	if opts.Stderr == nil {
		opts.Stderr = io.Discard
	}
	cmd := exec.CommandContext(ctx, opts.Config.Command, opts.Config.Args...)
	cmd.Env = mergedEnv(opts.Config.Env)
	cmd.Stderr = opts.Stderr
	childIn, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	childOut, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("kova proxy: start %s: %w", opts.Config.Command, err)
	}
	pid := cmd.Process.Pid

	var (
		mu           sync.Mutex
		inflight     = map[string]*pending{}
		instructions string
		knownDest    = map[string]bool{}
		outMu        sync.Mutex
	)
	writeOut := func(line []byte) {
		outMu.Lock()
		defer outMu.Unlock()
		_, _ = opts.Stdout.Write(append(line, '\n'))
	}
	emit := func(ev Event) {
		ev.At = time.Now().UTC()
		fmt.Fprintf(opts.Stderr, "kova proxy [%s] %s: %s\n", opts.Name, ev.Severity, ev.Message)
		if opts.OnEvent != nil {
			opts.OnEvent(ev)
		}
	}

	// client -> server
	go func() {
		sc := lineReader(opts.Stdin)
		for sc.Scan() {
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 {
				continue
			}
			var m Message
			if json.Unmarshal(line, &m) == nil && len(m.ID) > 0 && m.Method != "" {
				p := &pending{method: m.Method}
				if m.Method == "tools/call" {
					var params struct {
						Name string `json:"name"`
					}
					_ = json.Unmarshal(m.Params, &params)
					p.toolName = params.Name
					if opts.NetWatch {
						p.netBefore = NetSnapshot(pid)
						for k := range p.netBefore {
							knownDest[k] = true
						}
					}
				}
				mu.Lock()
				inflight[idString(m.ID)] = p
				mu.Unlock()
			}
			if _, err := childIn.Write(append(append([]byte(nil), line...), '\n')); err != nil {
				break
			}
		}
		_ = childIn.Close()
	}()

	// server -> client
	sc := lineReader(childOut)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var m Message
		if err := json.Unmarshal(line, &m); err != nil {
			writeOut(line)
			continue
		}
		// Server-initiated notification: the server announces its tool list changed mid-session.
		if len(m.ID) == 0 && m.Method == "notifications/tools/list_changed" {
			emit(Event{Kind: lockfile.ChangeListChanged, Severity: lockfile.SevMedium,
				Message: "server announced tools/list changed mid-session; next tools/list will be re-verified"})
			writeOut(line)
			continue
		}
		if len(m.ID) == 0 {
			writeOut(line)
			continue
		}
		mu.Lock()
		p := inflight[idString(m.ID)]
		delete(inflight, idString(m.ID))
		mu.Unlock()
		if p == nil || m.Result == nil {
			writeOut(line)
			continue
		}
		switch p.method {
		case "initialize":
			var init initializeResult
			if json.Unmarshal(m.Result, &init) == nil {
				instructions = init.Instructions
			}
		case "tools/list":
			var res toolsListResult
			if json.Unmarshal(m.Result, &res) == nil {
				hash, pinned := snapshotHash(instructions, res.Tools)
				if opts.Pinned == nil || opts.Pinned.ToolsHash == "" {
					if opts.OnPin != nil {
						opts.OnPin(hash, pinned, instructions, len(res.Tools))
					}
					// Adopt the pin for the rest of this session.
					if opts.Pinned == nil {
						opts.Pinned = &lockfile.Entry{}
					}
					opts.Pinned.ToolsHash = hash
					opts.Pinned.Tools = pinned
				} else if hash != opts.Pinned.ToolsHash {
					details := toolDiffFor(opts.Pinned.Tools, pinned)
					details["expected_hash"] = opts.Pinned.ToolsHash
					details["actual_hash"] = hash
					details["tool_count"] = len(res.Tools)
					emit(Event{Kind: lockfile.ChangeMCPTools, Severity: lockfile.SevCritical,
						Message: fmt.Sprintf("tool definitions changed since pinned (%v)", summarize(details)), Details: details})
					if opts.Enforce {
						errResp, _ := json.Marshal(map[string]any{
							"jsonrpc": "2.0", "id": m.ID,
							"error": RPCError{Code: -32001, Message: fmt.Sprintf(
								"kova: MCP server %q changed its tool definitions after they were pinned. Blocked. Review with `kova verify --mcp` and accept with `kova approve mcp:%s` if intended.", opts.Name, opts.Name)},
						})
						writeOut(errResp)
						continue
					}
				}
			}
		case "tools/call":
			if opts.NetWatch {
				after := NetSnapshot(pid)
				newDest := NewDestinations(knownDest, after)
				for k := range after {
					knownDest[k] = true
				}
				if len(newDest) > 0 {
					emit(Event{Kind: lockfile.ChangeNetwork, Severity: lockfile.SevLow,
						Message: fmt.Sprintf("tool %q opened connection(s) to %v not seen earlier this session", p.toolName, newDest),
						Details: map[string]any{"tool": p.toolName, "destinations": newDest}})
				}
			}
		}
		writeOut(line)
	}
	_ = cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return nil
}

func toolDiffFor(pinned, live []lockfile.Tool) map[string]any {
	pm := map[string]lockfile.Tool{}
	for _, t := range pinned {
		pm[t.Name] = t
	}
	lm := map[string]lockfile.Tool{}
	for _, t := range live {
		lm[t.Name] = t
	}
	var added, removed, changed []string
	for n, lt := range lm {
		pt, ok := pm[n]
		if !ok {
			added = append(added, n)
		} else if pt.DescriptionHash != lt.DescriptionHash || pt.SchemaHash != lt.SchemaHash {
			changed = append(changed, n)
		}
	}
	for n := range pm {
		if _, ok := lm[n]; !ok {
			removed = append(removed, n)
		}
	}
	return map[string]any{"added_tools": added, "removed_tools": removed, "changed_tools": changed}
}

func summarize(d map[string]any) string {
	var parts []string
	for _, k := range []string{"added_tools", "removed_tools", "changed_tools"} {
		if v, ok := d[k].([]string); ok && len(v) > 0 {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}
	if len(parts) == 0 {
		return "instructions changed"
	}
	return fmt.Sprint(parts)
}

var _ = os.Getenv
