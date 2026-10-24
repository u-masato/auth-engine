package main

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"

	"github.com/u-masato/auth-engine/resourceserver"
)

// MCP（Streamable HTTP transport）の最小実装。認可の相互運用（MCP Inspector や公式 SDK のクライアントで
// 接続できること）を確かめるために、initialize / ping / tools/list / tools/call だけを JSON-RPC 2.0 で答える。
// 応答は常に 1 件の JSON（SSE は使わない）。セッション ID・GET のストリーム・通知の配信は実装しない。
// MCP Authorization の確認が目的なので、プロトコルの網羅は目指さない。
//
// 対応するプロトコル版（initialize の protocolVersion）: クライアントの要求が既知ならそれを返し、
// 未知なら最新を返す（MCP Lifecycle「Version Negotiation」）。

var supportedProtocolVersions = []string{"2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// mcpHandler は resourceserver.Protect の内側で動く。Principal は検証済み。
func mcpHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
	case http.MethodGet:
		// サーバー起点のストリームは提供しない（Streamable HTTP「Listening for Messages from the Server」は MAY）
		http.Error(w, "server-initiated streams are not supported", http.StatusMethodNotAllowed)
		return
	case http.MethodDelete:
		w.WriteHeader(http.StatusOK) // セッションを持たないので、終了要求は受け取るだけ
		return
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil || req.JSONRPC != "2.0" {
		writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{Code: -32700, Message: "parse error"}})
		return
	}
	if len(req.ID) == 0 {
		// 通知（notifications/initialized など）は 202 で受け取る（Streamable HTTP「Sending Messages to the Server」）
		w.WriteHeader(http.StatusAccepted)
		return
	}
	pr, _ := resourceserver.FromContext(r.Context())
	res := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		version := supportedProtocolVersions[0]
		if slices.Contains(supportedProtocolVersions, p.ProtocolVersion) {
			version = p.ProtocolVersion
		}
		res.Result = map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "auth-engine-demo-mcp-server", "version": "0.1.0"},
			"instructions":    "Demo MCP server for auth-engine. The whoami tool shows the verified access token.",
		}
	case "ping":
		res.Result = map[string]any{}
	case "tools/list":
		res.Result = map[string]any{"tools": []map[string]any{{
			"name":        "whoami",
			"title":       "Who am I",
			"description": "Returns the subject, client_id, scope and audience of the access token that authorized this call.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		}}}
	case "tools/call":
		var p struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(req.Params, &p)
		if p.Name != "whoami" {
			res.Error = &rpcError{Code: -32602, Message: "unknown tool: " + p.Name}
			break
		}
		view := principalView(pr)
		text, _ := json.Marshal(view)
		res.Result = map[string]any{
			"content":           []map[string]any{{"type": "text", "text": string(text)}},
			"structuredContent": view,
		}
	default:
		res.Error = &rpcError{Code: -32601, Message: "method not found: " + req.Method}
	}
	writeRPC(w, res)
}

func writeRPC(w http.ResponseWriter, res rpcResponse) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}
