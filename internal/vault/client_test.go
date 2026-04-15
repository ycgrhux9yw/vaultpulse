package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/vaultpulse/internal/vault"
)

func newMockVaultServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/secret/data/myapp/db", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"lease_id":       "secret/data/myapp/db/abc123",
			"lease_duration": 3600,
			"renewable":      true,
			"data":           map[string]interface{}{"password": "s3cr3t"},
		})
	})

	mux.HandleFunc("/v1/secret/metadata/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"keys": []string{"db", "api"},
			},
		})
	})

	return httptest.NewServer(mux)
}

func TestGetSecretMeta(t *testing.T) {
	server := newMockVaultServer(t)
	defer server.Close()

	client, err := vault.NewClient(server.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	meta, err := client.GetSecretMeta("secret/data/myapp/db")
	if err != nil {
		t.Fatalf("GetSecretMeta() error = %v", err)
	}

	if meta.Path != "secret/data/myapp/db" {
		t.Errorf("expected path %q, got %q", "secret/data/myapp/db", meta.Path)
	}
	if meta.LeaseTTL.Seconds() != 3600 {
		t.Errorf("expected TTL 3600s, got %v", meta.LeaseTTL)
	}
	if !meta.Renewable {
		t.Error("expected secret to be renewable")
	}
}

func TestNewClient_InvalidAddress(t *testing.T) {
	_, err := vault.NewClient("://bad-address", "token")
	if err == nil {
		t.Error("expected error for invalid address, got nil")
	}
}
