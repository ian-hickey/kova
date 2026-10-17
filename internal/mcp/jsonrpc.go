// Package mcp speaks just enough Model Context Protocol to pin tool definitions and to sit
// transparently between a harness and a stdio server as a verifying proxy.
package mcp

import (
	"bufio"
	"encoding/json"
	"io"
)

// Message is a loosely-typed JSON-RPC 2.0 envelope.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is a JSON-RPC error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Tool mirrors the MCP tool definition fields that matter for pinning.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

type toolsListResult struct {
	Tools      []Tool `json:"tools"`
	NextCursor string `json:"nextCursor,omitempty"`
}

type initializeResult struct {
	ProtocolVersion string `json:"protocolVersion"`
	ServerInfo      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"serverInfo"`
	Instructions string         `json:"instructions,omitempty"`
	Capabilities map[string]any `json:"capabilities,omitempty"`
}

// lineReader yields newline-delimited JSON messages with a generous buffer.
func lineReader(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 32*1024*1024)
	return sc
}

func idString(raw json.RawMessage) string { return string(raw) }
