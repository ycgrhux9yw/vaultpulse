package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func sampleReports() []SecretTTLReport {
	now := time.Now()
	return []SecretTTLReport{
		{Path: "secret/app/db", TTL: 7 * 24 * time.Hour, ExpiresAt: now.Add(7 * 24 * time.Hour), Status: StatusOK, Message: "expires in 168h0m0s"},
		{Path: "secret/app/api", TTL: 48 * time.Hour, ExpiresAt: now.Add(48 * time.Hour), Status: StatusWarning, Message: "expires in 48h0m0s"},
		{Path: "secret/app/token", TTL: 12 * time.Hour, ExpiresAt: now.Add(12 * time.Hour), Status: StatusCritical, Message: "expires in 12h0m0s"},
		{Path: "secret/app/old", TTL: 0, ExpiresAt: now, Status: StatusExpired, Message: "secret has expired"},
	}
}

func TestPrintReport_ContainsPaths(t *testing.T) {
	var buf bytes.Buffer
	opts := ReportOptions{Writer: &buf, Colorized: false}

	PrintReport(sampleReports(), opts)

	output := buf.String()
	for _, path := range []string{"secret/app/db", "secret/app/api", "secret/app/token", "secret/app/old"} {
		if !strings.Contains(output, path) {
			t.Errorf("expected output to contain path %q", path)
		}
	}
}

func TestPrintReport_ContainsHeader(t *testing.T) {
	var buf bytes.Buffer
	opts := ReportOptions{Writer: &buf, Colorized: false}

	PrintReport(sampleReports(), opts)

	output := buf.String()
	if !strings.Contains(output, "PATH") || !strings.Contains(output, "STATUS") {
		t.Errorf("expected output to contain table headers, got:\n%s", output)
	}
}

func TestSummaryStats(t *testing.T) {
	reports := sampleReports()
	stats := SummaryStats(reports)

	if stats[StatusOK] != 1 {
		t.Errorf("expected 1 OK, got %d", stats[StatusOK])
	}
	if stats[StatusWarning] != 1 {
		t.Errorf("expected 1 WARNING, got %d", stats[StatusWarning])
	}
	if stats[StatusCritical] != 1 {
		t.Errorf("expected 1 CRITICAL, got %d", stats[StatusCritical])
	}
	if stats[StatusExpired] != 1 {
		t.Errorf("expected 1 EXPIRED, got %d", stats[StatusExpired])
	}
}
