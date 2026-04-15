package audit

import (
	"testing"
	"time"
)

func TestEvaluateTTL_OK(t *testing.T) {
	thresholds := DefaultThresholds()
	ttl := 7 * 24 * time.Hour // 7 days

	report := EvaluateTTL("secret/myapp/db", ttl, thresholds)

	if report.Status != StatusOK {
		t.Errorf("expected StatusOK, got %s", report.Status)
	}
	if report.Path != "secret/myapp/db" {
		t.Errorf("unexpected path: %s", report.Path)
	}
	if report.TTL != ttl {
		t.Errorf("unexpected TTL: %s", report.TTL)
	}
}

func TestEvaluateTTL_Warning(t *testing.T) {
	thresholds := DefaultThresholds()
	ttl := 48 * time.Hour // within warning threshold

	report := EvaluateTTL("secret/myapp/api", ttl, thresholds)

	if report.Status != StatusWarning {
		t.Errorf("expected StatusWarning, got %s", report.Status)
	}
}

func TestEvaluateTTL_Critical(t *testing.T) {
	thresholds := DefaultThresholds()
	ttl := 12 * time.Hour // within critical threshold

	report := EvaluateTTL("secret/myapp/token", ttl, thresholds)

	if report.Status != StatusCritical {
		t.Errorf("expected StatusCritical, got %s", report.Status)
	}
}

func TestEvaluateTTL_Expired(t *testing.T) {
	thresholds := DefaultThresholds()

	report := EvaluateTTL("secret/myapp/old", 0, thresholds)

	if report.Status != StatusExpired {
		t.Errorf("expected StatusExpired, got %s", report.Status)
	}
}

func TestEvaluateTTL_NegativeTTL(t *testing.T) {
	thresholds := DefaultThresholds()

	report := EvaluateTTL("secret/myapp/stHour, thresholds)

	if report.Status != StatusExpired {
		t.Errorf("expected StatusExpired for negative TTL, got %s", report.Status)
	}
}

func TestDefaultThresholds(t *testing.T) {
	th := DefaultThresholds()
	if th.Warning != 72*time.Hour {
		t.Errorf("expected 72h warning threshold, got %s", th.Warning)
	}
	if th.Critical != 24*time.Hour {
		t.Errorf("expected 24h critical threshold, got %s", th.Critical)
	}
}
