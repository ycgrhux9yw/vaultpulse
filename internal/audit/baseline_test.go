package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func baselineReports() []SecretReport {
	return []SecretReport{
		{Path: "secret/alpha", TTL: 3600, Status: StatusOK},
		{Path: "secret/beta", TTL: 300, Status: StatusWarning},
	}
}

func TestSaveAndLoadBaseline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	reports := baselineReports()
	if err := SaveBaseline(path, reports); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	b, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if len(b.Reports) != len(reports) {
		t.Errorf("expected %d reports, got %d", len(reports), len(b.Reports))
	}
	if b.CreatedAt.IsZero() {
		t.Error("expected non-zero CreatedAt")
	}
}

func TestLoadBaseline_MissingFile(t *testing.T) {
	_, err := LoadBaseline("/nonexistent/baseline.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadBaseline_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("{invalid"), 0644)
	_, err := LoadBaseline(path)
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestCompareBaseline_NoChanges(t *testing.T) {
	reports := baselineReports()
	b := &Baseline{Reports: reports}
	diffs := CompareBaseline(b, reports)
	if len(diffs) != 0 {
		t.Errorf("expected no diffs, got %d", len(diffs))
	}
}

func TestCompareBaseline_StatusChange(t *testing.T) {
	base := baselineReports()
	current := baselineReports()
	current[0].Status = StatusCritical

	b := &Baseline{Reports: base}
	diffs := CompareBaseline(b, current)

	found := false
	for _, d := range diffs {
		if d.Path == "secret/alpha" && d.Field == "status" {
			found = true
			if d.Before != StatusOK || d.After != StatusCritical {
				t.Errorf("unexpected diff values: %+v", d)
			}
		}
	}
	if !found {
		t.Error("expected status diff for secret/alpha")
	}
}

func TestCompareBaseline_NewSecret(t *testing.T) {
	base := baselineReports()
	current := append(baselineReports(), SecretReport{Path: "secret/gamma", TTL: 7200, Status: StatusOK})

	b := &Baseline{Reports: base}
	diffs := CompareBaseline(b, current)

	for _, d := range diffs {
		if d.Path == "secret/gamma" && d.Field == "existence" {
			return
		}
	}
	t.Error("expected existence diff for secret/gamma")
}

var _ = json.Marshal // avoid unused import
