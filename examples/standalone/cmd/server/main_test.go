package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/storage/memory"
)

// リポジトリに置いている -clients のファイルが、いまの書式（adminapi.ClientSpec）で読めること。
func TestRegisterClientsFromConformanceFile(t *testing.T) {
	store := memory.New()
	logger := slog.New(slog.DiscardHandler)
	path := filepath.Join("..", "..", "..", "..", "conformance", "clients.json")
	secrets, err := registerClientsFromFile(t.Context(), store, logger, path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := store.GetClient(t.Context(), "conformance-web")
	if err != nil {
		t.Fatal(err)
	}
	// ファイルに書いたシークレットがそのまま使われ、コンソールに渡す一覧にも入る
	if c.Profile != client.ProfileWeb || !c.VerifySecret(secrets["conformance-web"]) || len(secrets) != 2 {
		t.Fatalf("registered client: %+v, secrets for %d clients", c, len(secrets))
	}
	// 2 回目は登録済みとして飛ばす（内容を上書きしない）。シークレットの一覧は同じものが返る
	again, err := registerClientsFromFile(t.Context(), store, logger, path)
	if err != nil || again["conformance-web"] != secrets["conformance-web"] {
		t.Fatalf("second run: %v, %v", again, err)
	}
}

// 項目名の打ち間違い（旧書式の "secret" を含む）は、既定値での登録にせず起動を止める。
func TestRegisterClientsRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.json")
	old := `[{"client_id":"m1","profile":"machine","name":"M","scopes":["api.read"],"secret":"0123456789abcdef0123456789abcdef"}]`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	store := memory.New()
	_, err := registerClientsFromFile(t.Context(), store, slog.New(slog.DiscardHandler), path)
	if err == nil || !strings.Contains(err.Error(), `unknown field "secret"`) {
		t.Fatalf("an unknown field must be rejected: %v", err)
	}
	if cs, _ := store.ListClients(t.Context(), "", 10); len(cs) != 0 {
		t.Fatalf("nothing must be registered: %v", cs)
	}
}
