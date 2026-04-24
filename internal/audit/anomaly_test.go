package audit

import (
	"strings"
	"testing"
)

func anomalySample() []SecretReport {
	return []SecretReport{
		{Path: "secret/a", TTL: 3600, Status: StatusOK},
		{Path: "secret/b", TTL: 3500, Status: StatusOK},
		{Path: "secret/c", TTL: 3700, Status: StatusOK},
		{Path: "secret/d", TTL: 100, Status: StatusCritical},
		{Path: "secret/e", TTL: 0, Status: StatusExpired},
	}
}

func TestDetectAnomalies_ExpiredIsHigh(t *testing.T) {
	reports := anomalySample()
	anomalies := DetectAnomalies(reports, 2.0)
	for _, a := range anomalies {
		if a.Path == "secret/e" && a.Level != AnomalyHigh {
			t.Errorf("expected high anomaly for expired secret, got %s", a.Level)
		}
	}
}

func TestDetectAnomalies_CriticalIsMedium(t *testing.T) {
	reports := anomalySample()
	anomalies := DetectAnomalies(reports, 2.0)
	found := false
	for _, a := range anomalies {
		if a.Path == "secret/d" {
			found = true
			if a.Level != AnomalyMedium {
				t.Errorf("expected medium for critical secret, got %s", a.Level)
			}
		}
	}
	if !found {
		t.Error("expected anomaly for critical secret not found")
	}
}

func TestDetectAnomalies_HighTTLFlaggedLow(t *testing.T) {
	reports := []SecretReport{
		{Path: "secret/normal1", TTL: 3600, Status: StatusOK},
		{Path: "secret/normal2", TTL: 3600, Status: StatusOK},
		{Path: "secret/outlier", TTL: 100000, Status: StatusOK},
	}
	anomalies := DetectAnomalies(reports, 2.0)
	found := false
	for _, a := range anomalies {
		if a.Path == "secret/outlier" && a.Level == AnomalyLow {
			found = true
		}
	}
	if !found {
		t.Error("expected low anomaly for outlier high TTL")
	}
}

func TestDetectAnomalies_EmptyInput(t *testing.T) {
	result := DetectAnomalies(nil, 2.0)
	if len(result) != 0 {
		t.Errorf("expected no anomalies for empty input, got %d", len(result))
	}
}

func TestDetectAnomalies_DefaultDeviationFactor(t *testing.T) {
	reports := anomalySample()
	// zero factor should default to 2.0 without panic
	anomalies := DetectAnomalies(reports, 0)
	if anomalies == nil {
		t.Error("expected non-nil result")
	}
}

func TestDetectAnomalies_SortedByLevel(t *testing.T) {
	reports := anomalySample()
	anomalies := DetectAnomalies(reports, 2.0)
	for i := 1; i < len(anomalies); i++ {
		if levelRank(anomalies[i-1].Level) < levelRank(anomalies[i].Level) {
			t.Error("anomalies not sorted by descending severity")
		}
	}
}

func TestFormatAnomalies_ContainsHeader(t *testing.T) {
	out := FormatAnomalies(anomalySample()[:0])
	if !strings.Contains(out, "No anomalies") {
		t.Error("expected empty message")
	}

	anomalies := DetectAnomalies(anomalySample(), 2.0)
	out = FormatAnomalies(anomalies)
	if !strings.Contains(out, "LEVEL") || !strings.Contains(out, "PATH") {
		t.Error("expected table header in output")
	}
}
