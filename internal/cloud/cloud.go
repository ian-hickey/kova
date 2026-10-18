// Package cloud is the CLI's client for the KovaVerified team API: machine registration,
// lockfile snapshots, drift events, install ledger upload and the shared policy lockfile.
package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/ian-hickey/kova/internal/ledger"
	"github.com/ian-hickey/kova/internal/lockfile"
	"github.com/ian-hickey/kova/internal/store"
	"github.com/ian-hickey/kova/internal/triage"
)

const DefaultAPIURL = "https://api.kovaverified.io"

// Config is ~/.kova/config.json.
type Config struct {
	APIKey   string `json:"api_key,omitempty"`
	APIURL   string `json:"api_url,omitempty"`
	Enforce  bool   `json:"enforce"`   // proxy blocks drifted tools/list
	NetWatch bool   `json:"net_watch"` // proxy snapshots network destinations around tool calls
	// Connectors inventories the claude.ai ACCOUNT connectors through `claude mcp list` on verify.
	Connectors bool `json:"connectors"`
	// Triage: "" follows the team policy, "on" forces it (with TriageKey scoring directly at TypeSafe),
	// "off" never sends content anywhere. See internal/triage.
	Triage    string `json:"triage,omitempty"`
	TriageKey string `json:"triage_key,omitempty"`
}

// LoadConfig reads config or returns defaults.
func LoadConfig() Config {
	cfg := Config{APIURL: DefaultAPIURL, NetWatch: true}
	_ = store.ReadJSON(store.ConfigPath(), &cfg)
	if v := os.Getenv("KOVA_API_URL"); v != "" {
		cfg.APIURL = v
	}
	if v := os.Getenv("KOVA_API_KEY"); v != "" {
		cfg.APIKey = v
	}
	if cfg.APIURL == "" {
		cfg.APIURL = DefaultAPIURL
	}
	return cfg
}

// Save persists config.
func (c Config) Save() error { return store.WriteJSON(store.ConfigPath(), c) }

// EventRecord is a drift event as stored locally and uploaded.
type EventRecord struct {
	ID           string                `json:"id"`
	At           time.Time             `json:"at"`
	Source       string                `json:"source"` // verify | proxy | scan
	Kind         lockfile.ChangeKind   `json:"kind"`
	Severity     lockfile.Severity     `json:"severity"`
	Harness      string                `json:"harness,omitempty"`
	ArtifactType lockfile.ArtifactType `json:"artifact_type,omitempty"`
	Key          string                `json:"key,omitempty"`
	Name         string                `json:"name,omitempty"`
	Path         string                `json:"path,omitempty"`
	ExpectedHash string                `json:"expected_hash,omitempty"`
	ActualHash   string                `json:"actual_hash,omitempty"`
	Details      map[string]any        `json:"details,omitempty"`
	Message      string                `json:"message"`
}

// RecordEvent appends to the local events log.
func RecordEvent(e EventRecord) error {
	if e.ID == "" {
		e.ID = ledger.NewID()
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	return store.AppendJSONL(store.EventsPath(), e)
}

// Events reads the local events log.
func Events() ([]EventRecord, error) { return store.ReadJSONL[EventRecord](store.EventsPath()) }

// MachineInfo is sent on registration.
type MachineInfo struct {
	MachineID        string   `json:"machine_id"`
	Hostname         string   `json:"hostname"`
	OS               string   `json:"os"`
	Arch             string   `json:"arch"`
	Username         string   `json:"username"`
	CLIVersion       string   `json:"cli_version"`
	Harnesses        []string `json:"harnesses"`
	EntryCount       int      `json:"entry_count"`
	LastVerifyStatus string   `json:"last_verify_status,omitempty"`
}

// Policy is the org's shared approve/block list.
type Policy struct {
	Approved map[string]string `json:"approved"` // artifact_key -> hash
	Blocked  map[string]string `json:"blocked"`  // artifact_key -> hash
	Plan     string            `json:"plan"`
	Org      string            `json:"org"`
	Triage   struct {
		Enabled bool `json:"enabled"`
	} `json:"triage"`
}

type syncState struct {
	EventsSynced int `json:"events_synced"`
	LedgerSynced int `json:"ledger_synced"`
}

// Client talks to the API.
type Client struct {
	cfg  Config
	http *http.Client
}

// NewClient returns a client or nil when no API key is configured.
func NewClient(cfg Config) *Client {
	if cfg.APIKey == "" {
		return nil
	}
	return &Client{cfg: cfg, http: &http.Client{Timeout: 8 * time.Second}}
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.APIURL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "kova-cli")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = string(bytes.TrimSpace(data))
		}
		return fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, e.Error)
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// Score sends triage items to the team API, which scores them with the org's AI triage setting
// and caches verdicts org-wide. Implements triage.Scorer.
func (c *Client) Score(ctx context.Context, items []triage.Item) (map[string]triage.Verdict, error) {
	var out struct {
		Verdicts map[string]triage.Verdict `json:"verdicts"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/triage", map[string]any{"items": items}, &out)
	return out.Verdicts, err
}

// Whoami validates the key.
func (c *Client) Whoami(ctx context.Context) (*Policy, error) {
	var p Policy
	return &p, c.do(ctx, http.MethodGet, "/v1/policy", nil, &p)
}

// RegisterMachine upserts this machine.
func (c *Client) RegisterMachine(ctx context.Context, info MachineInfo) error {
	return c.do(ctx, http.MethodPost, "/v1/machines", info, nil)
}

// UploadLockfile stores a snapshot.
func (c *Client) UploadLockfile(ctx context.Context, lf *lockfile.Lockfile) error {
	return c.do(ctx, http.MethodPost, "/v1/lockfiles", map[string]any{
		"machine_id": lf.MachineID, "lockfile": lf, "lockfile_hash": lf.ContentHash(), "entry_count": len(lf.Entries),
	}, nil)
}

// Policy fetches the org policy.
func (c *Client) Policy(ctx context.Context) (*Policy, error) { return c.Whoami(ctx) }

// SyncLogs uploads any events and ledger entries not yet uploaded to this API endpoint.
// Offsets are tracked per API URL so switching endpoints (local → staging → prod) re-uploads.
func (c *Client) SyncLogs(ctx context.Context, machineID string) (events, ledgerRows int, err error) {
	all := map[string]syncState{}
	_ = store.ReadJSON(store.SyncPath(), &all)
	st := all[c.cfg.APIURL]
	save := func() {
		all[c.cfg.APIURL] = st
		_ = store.WriteJSON(store.SyncPath(), all)
	}

	evs, _ := Events()
	if len(evs) > st.EventsSynced {
		batch := evs[st.EventsSynced:]
		for i := 0; i < len(batch); i += 200 {
			end := i + 200
			if end > len(batch) {
				end = len(batch)
			}
			if err := c.do(ctx, http.MethodPost, "/v1/events", map[string]any{"machine_id": machineID, "events": batch[i:end]}, nil); err != nil {
				return events, ledgerRows, err
			}
			st.EventsSynced += end - i
			events += end - i
			save()
		}
	}
	rows, _ := ledger.All()
	if len(rows) > st.LedgerSynced {
		batch := rows[st.LedgerSynced:]
		for i := 0; i < len(batch); i += 200 {
			end := i + 200
			if end > len(batch) {
				end = len(batch)
			}
			if err := c.do(ctx, http.MethodPost, "/v1/ledger", map[string]any{"machine_id": machineID, "entries": batch[i:end]}, nil); err != nil {
				return events, ledgerRows, err
			}
			st.LedgerSynced += end - i
			ledgerRows += end - i
			save()
		}
	}
	return events, ledgerRows, nil
}
