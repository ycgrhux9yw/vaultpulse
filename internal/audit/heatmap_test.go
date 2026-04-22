package audit

import (
	"strings"
	"testing"
)

func heatmapReports() []SecretReport {
	return []SecretReport{
		{Path: "secret/prod/db", Status: StatusOK, TTL: 3600},
		{Path: "secret/prod/api", Status: StatusWarning, TTL: 1800},
		{Path: "secret/dev/db", Status: StatusCritical, TTL: 300},
		{Path: "secret/dev/cache", Status: StatusExpired, TTL: 0},
		{Path: "infra/prod/tls", Status: StatusOK, TTL: 7200},
	}
}

func TestBuildHeatmap_RowCount(t *testing.T) {
	rows := BuildHeatmap(heatmapReports())
	// Expect: secret/prod, secret/dev, infra/prod
	if len(rows) != 3 {
		t.Errorf("expected 3 rows, got %d", len(rows))
	}
}

func TestBuildHeatmap_PrefixGrouping(t *testing.T) {
	rows := BuildHeatmap(heatmapReports())
	prefixes := make(map[string]int)
	for _, r := range rows {
		prefixes[r.Prefix] = len(r.Cells)
	}
	if prefixes["secret/prod"] != 2 {
		t.Errorf("expected 2 cells in secret/prod, got %d", prefixes["secret/prod"])
	}
	if prefixes["secret/dev"] != 2 {
		t.Errorf("expected 2 cells in secret/dev, got %d", prefixes["secret/dev"])
	}
	if prefixes["infra/prod"] != 1 {
		t.Errorf("expected 1 cell in infra/prod, got %d", prefixes["infra/prod"])
	}
}

func TestBuildHeatmap_Sorted(t *testing.T) {
	rows := BuildHeatmap(heatmapReports())
	if rows[0].Prefix != "infra/prod" {
		t.Errorf("expected first row to be infra/prod, got %s", rows[0].Prefix)
	}
}

func TestBuildHeatmap_EmptyInput(t *testing.T) {
	rows := BuildHeatmap([]SecretReport{})
	if len(rows) != 0 {
		t.Errorf("expected 0 rows for empty input, got %d", len(rows))
	}
}

func TestFormatHeatmap_ContainsHeader(t *testing.T) {
	rows := BuildHeatmap(heatmapReports())
	out := FormatHeatmap(rows)
	if !strings.Contains(out, "PREFIX") {
		t.Error("expected output to contain PREFIX header")
	}
	if !strings.Contains(out, "SCORE") {
		t.Error("expected output to contain SCORE header")
	}
}

func TestFormatHeatmap_ContainsPrefixes(t *testing.T) {
	rows := BuildHeatmap(heatmapReports())
	out := FormatHeatmap(rows)
	if !strings.Contains(out, "secret/prod") {
		t.Error("expected output to contain secret/prod")
	}
	if !strings.Contains(out, "infra/prod") {
		t.Error("expected output to contain infra/prod")
	}
}

func TestFormatHeatmap_EmptyInput(t *testing.T) {
	out := FormatHeatmap([]HeatmapRow{})
	if !strings.Contains(out, "no data") {
		t.Errorf("expected no-data message, got: %s", out)
	}
}
