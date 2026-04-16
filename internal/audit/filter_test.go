package audit

import (
	"testing"
	"time"
)

func filterSample() []Report {
	return []Report{
		{Path: "secret/app/db", Status: "ok", TTL: 48 * time.Hour},
		{Path: "secret/app/api", Status: "warning", TTL: 20 * time.Hour},
		{Path: "secret/infra/tls", Status: "critical", TTL: 4 * time.Hour},
		{Path: "secret/infra/ssh", Status: "expired", TTL: 0},
	}
}

func TestFilterReports_ByStatus(t *testing.T) {
	out := FilterReports(filterSample(), FilterOptions{Status: "warning"})
	if len(out) != 1 || out[0].Path != "secret/app/api" {
		t.Fatalf("expected 1 warning report, got %d", len(out))
	}
}

func TestFilterReports_ByPathPrefix(t *testing.T) {
	out := FilterReports(filterSample(), FilterOptions{PathPrefix: "secret/infra"})
	if len(out) != 2 {
		t.Fatalf("expected 2 infra reports, got %d", len(out))
	}
}

func TestFilterReports_ByMinTTL(t *testing.T) {
	out := FilterReports(filterSample(), FilterOptions{MinTTL: 24 * time.Hour})
	if len(out) != 1 || out[0].Path != "secret/app/db" {
		t.Fatalf("expected 1 report with TTL >= 24h, got %d", len(out))
	}
}

func TestFilterReports_ByMaxTTL(t *testing.T) {
	out := FilterReports(filterSample(), FilterOptions{MaxTTL: 5 * time.Hour})
	if len(out) != 2 {
		t.Fatalf("expected 2 reports with TTL <= 5h, got %d", len(out))
	}
}

func TestFilterReports_NoMatch(t *testing.T) {
	out := FilterReports(filterSample(), FilterOptions{Status: "unknown"})
	if len(out) != 0 {
		t.Fatalf("expected 0 reports, got %d", len(out))
	}
}

func TestFilterReports_Empty(t *testing.T) {
	out := FilterReports([]Report{}, FilterOptions{Status: "ok"})
	if len(out) != 0 {
		t.Fatal("expected empty result")
	}
}
