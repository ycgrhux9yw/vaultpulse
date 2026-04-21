package audit

import (
	"strings"
	"testing"
	"time"
)

func driftBaseline() map[string]SecretReport {
	return map[string]SecretReport{
		"secret/app/db": {Path: "secret/app/db", TTL: 72 * time.Hour},
		"secret/app/api": {Path: "secret/app/api", TTL: 48 * time.Hour},
		"secret/app/ok": {Path: "secret/app/ok", TTL: 24 * time.Hour},
	}
}

func TestDetectDrift_NoDrift(t *testing.T) {
	reports := []SecretReport{
		{Path: "secret/app/ok", TTL: 24 * time.Hour},
	}
	entries := DetectDrift(reports, driftBaseline(), DefaultDriftConfig)
	if len(entries) != 0 {
		t.Fatalf("expected 0 drift entries, got %d", len(entries))
	}
}

func TestDetectDrift_WarningSeverity(t *testing.T) {
	reports := []SecretReport{
		{Path: "secret/app/api", TTL: 24 * time.Hour}, // delta = 24h → warn
	}
	entries := DetectDrift(reports, driftBaseline(), DefaultDriftConfig)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Severity != "warning" {
		t.Errorf("expected warning, got %s", entries[0].Severity)
	}
}

func TestDetectDrift_CriticalSeverity(t *testing.T) {
	reports := []SecretReport{
		{Path: "secret/app/db", TTL: 0}, // delta = 72h → critical
	}
	entries := DetectDrift(reports, driftBaseline(), DefaultDriftConfig)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Severity != "critical" {
		t.Errorf("expected critical, got %s", entries[0].Severity)
	}
}

func TestDetectDrift_SkipsUnknownPaths(t *testing.T) {
	reports := []SecretReport{
		{Path: "secret/unknown/path", TTL: 0},
	}
	entries := DetectDrift(reports, driftBaseline(), DefaultDriftConfig)
	if len(entries) != 0 {
		t.Errorf("expected no entries for unknown path, got %d", len(entries))
	}
}

func TestDetectDrift_SortedByDeltaDesc(t *testing.T) {
	reports := []SecretReport{
		{Path: "secret/app/api", TTL: 24 * time.Hour}, // delta 24h
		{Path: "secret/app/db", TTL: 0},               // delta 72h
	}
	entries := DetectDrift(reports, driftBaseline(), DefaultDriftConfig)
	if len(entries) < 2 {
		t.Fatal("expected at least 2 entries")
	}
	if entries[0].Delta < entries[1].Delta {
		t.Error("entries not sorted by delta descending")
	}
}

func TestFormatDrift_ContainsHeader(t *testing.T) {
	entries := []DriftEntry{
		{Path: "secret/app/db", ExpectedTTL: 72 * time.Hour, ActualTTL: 0, Delta: 72 * time.Hour, Severity: "critical"},
	}
	out := FormatDrift(entries)
	if !strings.Contains(out, "PATH") || !strings.Contains(out, "SEVERITY") {
		t.Error("formatted drift missing header columns")
	}
	if !strings.Contains(out, "secret/app/db") {
		t.Error("formatted drift missing path")
	}
}

func TestFormatDrift_EmptyMessage(t *testing.T) {
	out := FormatDrift(nil)
	if !strings.Contains(out, "No TTL drift detected") {
		t.Errorf("expected empty message, got: %s", out)
	}
}
