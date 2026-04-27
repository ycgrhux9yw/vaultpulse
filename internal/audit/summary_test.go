package audit

import (
	"strings"
	"testing"
	"time"
)

func summarySample() []SecretReport {
	return []SecretReport{
		{Path: "secret/db/prod", Status: "critical", TTL: 10 * time.Hour},
		{Path: "secret/db/dev", Status: "ok", TTL: 720 * time.Hour},
		{Path: "secret/api/key", Status: "expired", TTL: 0},
		{Path: "secret/api/token", Status: "warning", TTL: 48 * time.Hour},
		{Path: "secret/infra/ssh", Status: "ok", TTL: 360 * time.Hour},
		{Path: "secret/infra/tls", Status: "warning", TTL: 36 * time.Hour},
	}
}

func TestBuildSummary_TotalSecrets(t *testing.T) {
	s := BuildSummary(summarySample())
	if s.TotalSecrets != 6 {
		t.Errorf("expected 6 secrets, got %d", s.TotalSecrets)
	}
}

func TestBuildSummary_ByStatus(t *testing.T) {
	s := BuildSummary(summarySample())
	if s.ByStatus["ok"] != 2 {
		t.Errorf("expected 2 ok, got %d", s.ByStatus["ok"])
	}
	if s.ByStatus["warning"] != 2 {
		t.Errorf("expected 2 warning, got %d", s.ByStatus["warning"])
	}
	if s.ByStatus["critical"] != 1 {
		t.Errorf("expected 1 critical, got %d", s.ByStatus["critical"])
	}
	if s.ByStatus["expired"] != 1 {
		t.Errorf("expected 1 expired, got %d", s.ByStatus["expired"])
	}
}

func TestBuildSummary_TopRisksMaxFive(t *testing.T) {
	s := BuildSummary(summarySample())
	if len(s.TopRisks) > 5 {
		t.Errorf("expected at most 5 top risks, got %d", len(s.TopRisks))
	}
}

func TestBuildSummary_TopRisksExpiredFirst(t *testing.T) {
	s := BuildSummary(summarySample())
	if len(s.TopRisks) == 0 {
		t.Fatal("expected top risks to be non-empty")
	}
	if s.TopRisks[0].Status != "expired" {
		t.Errorf("expected first top risk to be expired, got %s", s.TopRisks[0].Status)
	}
}

func TestBuildSummary_AvgTTL(t *testing.T) {
	s := BuildSummary(summarySample())
	if s.AvgTTLDays <= 0 {
		t.Errorf("expected positive avg TTL, got %f", s.AvgTTLDays)
	}
}

func TestBuildSummary_Empty(t *testing.T) {
	s := BuildSummary([]SecretReport{})
	if s.TotalSecrets != 0 {
		t.Errorf("expected 0 secrets for empty input")
	}
}

func TestFormatSummary_ContainsHeader(t *testing.T) {
	s := BuildSummary(summarySample())
	out := FormatSummary(s)
	if !strings.Contains(out, "Executive Summary") {
		t.Error("expected header in formatted summary")
	}
}

func TestFormatSummary_ContainsTopRisks(t *testing.T) {
	s := BuildSummary(summarySample())
	out := FormatSummary(s)
	if !strings.Contains(out, "Top Risks") {
		t.Error("expected Top Risks section in formatted summary")
	}
}
