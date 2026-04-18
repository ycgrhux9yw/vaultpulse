package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func alertSample() []SecretReport {
	return []SecretReport{
		{Path: "secret/ok", Status: "ok", TTL: 72 * time.Hour},
		{Path: "secret/warn", Status: "warning", TTL: 20 * time.Hour},
		{Path: "secret/crit", Status: "critical", TTL: 2 * time.Hour},
		{Path: "secret/exp", Status: "expired", TTL: 0},
	}
}

func TestDispatchAlerts_WarningAndAbove(t *testing.T) {
	var buf bytes.Buffer
	cfg := DefaultAlertConfig()
	cfg.Writer = &buf
	cfg.MinStatus = "warning"

	if err := DispatchAlerts(alertSample(), cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "secret/ok") {
		t.Error("ok status should not appear in alerts")
	}
	for _, p := range []string{"secret/warn", "secret/crit", "secret/exp"} {
		if !strings.Contains(out, p) {
			t.Errorf("expected alert for %s", p)
		}
	}
}

func TestDispatchAlerts_CriticalOnly(t *testing.T) {
	var buf bytes.Buffer
	cfg := DefaultAlertConfig()
	cfg.Writer = &buf
	cfg.MinStatus = "critical"

	DispatchAlerts(alertSample(), cfg)
	out := buf.String()
	if strings.Contains(out, "secret/warn") {
		t.Error("warning should not appear when min is critical")
	}
	if !strings.Contains(out, "secret/crit") {
		t.Error("critical should appear")
	}
}

func TestDispatchAlerts_NoMatches(t *testing.T) {
	var buf bytes.Buffer
	cfg := DefaultAlertConfig()
	cfg.Writer = &buf
	cfg.MinStatus = "expired"

	reports := []SecretReport{{Path: "secret/ok", Status: "ok", TTL: 72 * time.Hour}}
	DispatchAlerts(reports, cfg)
	if !strings.Contains(buf.String(), "No alerts") {
		t.Error("expected no-alerts message")
	}
}

func TestDispatchAlerts_FileError(t *testing.T) {
	cfg := DefaultAlertConfig()
	cfg.Channel = AlertChannelFile
	cfg.FilePath = "/nonexistent_dir/alert.log"

	err := DispatchAlerts(alertSample(), cfg)
	if err == nil {
		t.Error("expected error for invalid file path")
	}
}
