package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExportReport_JSON(t *testing.T) {
	reports := []Report{
		{Path: "secret/foo", Status: StatusOK, TTLRemaining: 24 * time.Hour, Message: "ok"},
		{Path: "secret/bar", Status: StatusWarning, TTLRemaining: 2 * time.Hour, Message: "expiring soon"},
	}

	tmp := filepath.Join(t.TempDir(), "out.json")
	err := ExportReport(reports, ExportOptions{Format: FormatJSON, FilePath: tmp})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, _ := os.ReadFile(tmp)
	var parsed jsonReport
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(parsed.Reports) != 2 {
		t.Errorf("expected 2 reports, got %d", len(parsed.Reports))
	}
	if parsed.GeneratedAt == "" {
		t.Error("expected generated_at to be set")
	}
}

func TestExportReport_CSV(t *testing.T) {
	reports := []Report{
		{Path: "secret/foo", Status: StatusOK, TTLRemaining: 24 * time.Hour, Message: "ok"},
		{Path: "secret/bar,baz", Status: StatusCritical, TTLRemaining: 0, Message: "expired"},
	}

	tmp := filepath.Join(t.TempDir(), "out.csv")
	err := ExportReport(reports, ExportOptions{Format: FormatCSV, FilePath: tmp})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, _ := os.ReadFile(tmp)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 lines (header + 2), got %d", len(lines))
	}
	if !strings.HasPrefix(lines[0], "path,status") {
		t.Error("missing CSV header")
	}
	// path with comma should be quoted
	if !strings.Contains(lines[2], `"secret/bar,baz"`) {
		t.Errorf("expected quoted path in CSV, got: %s", lines[2])
	}
}

func TestExportReport_UnsupportedFormat(t *testing.T) {
	err := ExportReport(nil, ExportOptions{Format: "xml"})
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}
