package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func sampleSecretReports() []SecretReport {
	return []SecretReport{
		{Path: "secret/db", Status: "OK", TTL: 3600},
		{Path: "secret/api", Status: "Warning", TTL: 300, Note: "expiring soon"},
		{Path: "secret/old", Status: "Expired", TTL: 0},
	}
}

func TestSaveAndLoadSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")

	reports := sampleSecretReports()
	if err := SaveSnapshot(path, reports); err != nil {
		t.Fatalf("SaveSnapshot error: %v", err)
	}

	snap, err := LoadSnapshot(path)
	if err != nil {
		t.Fatalf("LoadSnapshot error: %v", err)
	}
	if len(snap.Reports) != len(reports) {
		t.Errorf("expected %d reports, got %d", len(reports), len(snap.Reports))
	}
	if snap.Reports[0].Path != "secret/db" {
		t.Errorf("unexpected path: %s", snap.Reports[0].Path)
	}
}

func TestLoadSnapshot_InvalidFile(t *testing.T) {
	_, err := LoadSnapshot("/nonexistent/path.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadSnapshot_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(path, []byte("not json{"), 0644)
	_, err := LoadSnapshot(path)
	if err == nil {
		t.Error("expected parse error")
	}
}

func TestDiffSnapshots_DetectsChanges(t *testing.T) {
	old := &Snapshot{Reports: []SecretReport{
		{Path: "secret/db", Status: "OK"},
		{Path: "secret/api", Status: "OK"},
	}}
	new := &Snapshot{Reports: []SecretReport{
		{Path: "secret/db", Status: "Warning"},
		{Path: "secret/api", Status: "OK"},
	}}
	changed := DiffSnapshots(old, new)
	if len(changed) != 1 || changed[0] != "secret/db" {
		t.Errorf("expected [secret/db], got %v", changed)
	}
}

func TestDiffSnapshots_NoChanges(t *testing.T) {
	old := &Snapshot{Reports: []SecretReport{
		{Path: "secret/db", Status: "OK"},
	}}
	new := &Snapshot{Reports: []SecretReport{
		{Path: "secret/db", Status: "OK"},
	}}
	changed := DiffSnapshots(old, new)
	if len(changed) != 0 {
		t.Errorf("expected no changes, got %v", changed)
	}
}
