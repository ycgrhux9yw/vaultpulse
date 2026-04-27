package cmd

import (
	"testing"
)

func TestRunSummary_MissingPaths(t *testing.T) {
	auditPaths = []string{}
	vaultAddr = "http://127.0.0.1:8200"
	vaultToken = "test-token"

	err := runSummary(nil, nil)
	if err == nil {
		t.Fatal("expected error for missing paths")
	}
	if err.Error() != "--paths is required" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunSummary_MissingVaultAddr(t *testing.T) {
	auditPaths = []string{"secret/db"}
	vaultAddr = ""
	vaultToken = "test-token"

	err := runSummary(nil, nil)
	if err == nil {
		t.Fatal("expected error for missing vault addr")
	}
	if err.Error() != "--vault-addr or VAULT_ADDR is required" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunSummary_InvalidVaultAddr(t *testing.T) {
	auditPaths = []string{"secret/db"}
	vaultAddr = "://bad-addr"
	vaultToken = "test-token"

	err := runSummary(nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid vault address")
	}
}

func TestRunSummary_UnreachableVault(t *testing.T) {
	auditPaths = []string{"secret/db"}
	vaultAddr = "http://127.0.0.1:19999"
	vaultToken = "test-token"

	err := runSummary(nil, nil)
	// unreachable vault skips all paths → no secrets evaluated
	if err == nil {
		t.Fatal("expected error when vault is unreachable")
	}
}
