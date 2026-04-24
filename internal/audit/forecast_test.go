package audit

import (
	"strings"
	"testing"
	"time"
)

func forecastReports() []SecretReport {
	return []SecretReport{
		{Path: "secret/prod/db", TTL: 10 * 24 * time.Hour, Status: "OK"},
		{Path: "secret/prod/api", TTL: 2 * 24 * time.Hour, Status: "Warning"},
		{Path: "secret/prod/cache", TTL: 12 * time.Hour, Status: "Critical"},
		{Path: "secret/dev/token", TTL: 0, Status: "Unknown"},
	}
}

func TestBuildForecast_SkipsZeroTTL(t *testing.T) {
	reports := forecastReports()
	entries := BuildForecast(reports, 7, DefaultThresholds)
	for _, e := range entries {
		if e.Path == "secret/dev/token" {
			t.Errorf("expected zero-TTL secret to be skipped")
		}
	}
}

func TestBuildForecast_EntryCount(t *testing.T) {
	reports := forecastReports()
	entries := BuildForecast(reports, 7, DefaultThresholds)
	// 3 secrets have TTL > 0
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
}

func TestBuildForecast_PredictedExpired(t *testing.T) {
	reports := []SecretReport{
		{Path: "secret/short", TTL: 1 * time.Hour, Status: "Critical"},
	}
	entries := BuildForecast(reports, 7, DefaultThresholds)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry")
	}
	if entries[0].PredictedStatus != "Expired" {
		t.Errorf("expected Expired, got %s", entries[0].PredictedStatus)
	}
}

func TestBuildForecast_SortedByExpiry(t *testing.T) {
	reports := []SecretReport{
		{Path: "secret/long", TTL: 30 * 24 * time.Hour, Status: "OK"},
		{Path: "secret/short", TTL: 1 * 24 * time.Hour, Status: "Critical"},
	}
	entries := BuildForecast(reports, 3, DefaultThresholds)
	if entries[0].Path != "secret/short" {
		t.Errorf("expected shortest expiry first, got %s", entries[0].Path)
	}
}

func TestFormatForecast_ContainsHeader(t *testing.T) {
	reports := forecastReports()
	entries := BuildForecast(reports, 7, DefaultThresholds)
	out := FormatForecast(entries, 7)
	if !strings.Contains(out, "PATH") {
		t.Errorf("expected header to contain PATH")
	}
	if !strings.Contains(out, "STATUS") {
		t.Errorf("expected header to contain STATUS")
	}
}

func TestFormatForecast_EmptyInput(t *testing.T) {
	out := FormatForecast([]ForecastEntry{}, 7)
	if !strings.Contains(out, "No forecastable") {
		t.Errorf("expected empty message, got: %s", out)
	}
}
