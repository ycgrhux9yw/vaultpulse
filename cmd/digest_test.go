package cmd

import (
	"bytes"
	"testing"
)

func TestRunDigest_MissingPaths(t *testing.T) {
	cmd := rootCmd
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"digest", "--vault-addr", "http://127.0.0.1:8200"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when --paths is missing")
	}
}

func TestRunDigest_InvalidVaultAddr(t *testing.T) {
	cmd := rootCmd
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"digest", "--paths", "secret/test", "--vault-addr", ""})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for empty vault address")
	}
}

func TestRunDigest_UnreachableVault(t *testing.T) {
	cmd := rootCmd
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		"digest",
		"--paths", "secret/test",
		"--vault-addr", "http://127.0.0.1:19999",
		"--vault-token", "test-token",
	})
	// Should not panic; unreachable vault results in skipped paths and empty digest.
	_ = cmd.Execute()
}
