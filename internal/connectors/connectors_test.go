package connectors

import (
	"strings"
	"testing"
	"time"
)

const sample = "claude mcp list\n" +
	"claude.ai Claude Docs: https://api.anthropic.com/v1/pages/mcp - ✔ Connected\n" +
	"claude.ai Salesforce: https://api.salesforce.com/platform/mcp/v1/platform/headless-360 - ! Needs authentication\n" +
	"\x1b[32mclaude.ai Datadog: https://mcp.datadoghq.com/v1/mcp - ✔ Connected\x1b[0m\n" +
	"plugin:datadog:mcp: https://not-setup/v1/mcp?referrer_ide=claude-code-plugin&plugin_version=0.7.17 (HTTP) - ✘ Failed to connect — ENOTFOUND\n" +
	"atlassian: https://mcp.atlassian.com/v1/mcp/authv2 (HTTP) - ✔ Connected\n" +
	"local-fs: npx -y @modelcontextprotocol/server-filesystem - ✔ Connected\n"

func TestParse(t *testing.T) {
	list := Parse(sample)
	if len(list) != 6 {
		t.Fatalf("want 6 rows, got %d: %+v", len(list), list)
	}
	byName := map[string]Connector{}
	for _, c := range list {
		byName[c.Name] = c
	}
	if c := byName["Claude Docs"]; !c.Account || c.Status != "connected" || c.Transport != "http" {
		t.Errorf("Claude Docs: %+v", c)
	}
	if c := byName["Salesforce"]; !c.Account || c.Status != "needs_auth" {
		t.Errorf("Salesforce: %+v", c)
	}
	if c := byName["Datadog"]; !c.Account || c.Status != "connected" {
		t.Errorf("ANSI-wrapped row not parsed: %+v", c)
	}
	if c := byName["plugin:datadog:mcp"]; c.Account || c.Status != "failed" {
		t.Errorf("plugin row: %+v", c)
	}
	if c := byName["atlassian"]; c.Account {
		t.Errorf("file-defined server must not be marked account: %+v", c)
	}
	if c := byName["local-fs"]; c.Transport != "stdio" {
		t.Errorf("stdio row: %+v", c)
	}
}

func TestEntriesHashIgnoresStatus(t *testing.T) {
	a := Entries([]Connector{{Name: "Vanta", URL: "https://mcp.vanta.com/mcp", Transport: "http", Status: "needs_auth", Account: true}}, time.Now())
	b := Entries([]Connector{{Name: "Vanta", URL: "https://mcp.vanta.com/mcp", Transport: "http", Status: "connected", Account: true}}, time.Now())
	k := Key("Vanta")
	if !strings.HasPrefix(k, "claude-code:connector:") || a[k].Hash != b[k].Hash {
		t.Fatalf("status must not affect the pin: %s vs %s", a[k].Hash, b[k].Hash)
	}
	c := Entries([]Connector{{Name: "Vanta", URL: "https://evil.example/mcp", Transport: "http", Account: true}}, time.Now())
	if c[k].Hash == a[k].Hash {
		t.Fatalf("URL change must change the pin")
	}
}
