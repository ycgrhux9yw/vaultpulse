package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"vaultpulse/internal/audit"
)

func writeTempSnapshot(t *testing.T, dir string, name string, reports []audit.SecretReport) {
	t.Helper()
	data, err := json.Marshal(reports)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadSnapshotDir_ReturnsEntries(t *testing.T) {
	dir := t.TempDir()
	writeTempSnapshot(t, dir, "snap1.json", []audit.SecretReport{
		{Path: "secret/x", Status: "ok"},
	})
	writeTempSnapshot(t, dir, "snap2.json", []audit.SecretReport{
		{Path: "secret/y", Status: "warning"},
	})
	entries, err := loadSnapshotDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestLoadSnapshotDir_SkipsMalformed(t *testing.T) {
	dir := t.TempDir()
	// valid
	writeTempSnapshot(t, dir, "good.json", []audit.SecretReport{
		{Path: "secret/z", Status: "ok"},
	})
	// malformed
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte("not-json{"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := loadSnapshotDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 valid entry, got %d", len(entries))
	}
}

func TestLoadSnapshotDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	entries, err := loadSnapshotDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}
