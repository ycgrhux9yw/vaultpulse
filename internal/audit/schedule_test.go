package audit

import (
	"testing"
	"time"
)

func makeEntry(path string, period time.Duration, lastRotatedOffset time.Duration) ScheduleEntry {
	lr := time.Now().Add(lastRotatedOffset)
	return ScheduleEntry{
		Path:           path,
		RotationPeriod: period,
		LastRotated:    lr,
		NextRotation:   lr.Add(period),
	}
}

func TestEvaluateSchedule_OK(t *testing.T) {
	entry := makeEntry("secret/db", 30*24*time.Hour, -24*time.Hour)
	report := EvaluateSchedule(entry, 48*time.Hour)
	if report.Status != ScheduleOK {
		t.Errorf("expected OK, got %s", report.Status)
	}
}

func TestEvaluateSchedule_DueSoon(t *testing.T) {
	entry := makeEntry("secret/api", 24*time.Hour, -23*time.Hour)
	report := EvaluateSchedule(entry, 2*time.Hour)
	if report.Status != ScheduleDueSoon {
		t.Errorf("expected DUE_SOON, got %s", report.Status)
	}
}

func TestEvaluateSchedule_Overdue(t *testing.T) {
	entry := makeEntry("secret/token", 12*time.Hour, -24*time.Hour)
	report := EvaluateSchedule(entry, 2*time.Hour)
	if report.Status != ScheduleOverdue {
		t.Errorf("expected OVERDUE, got %s", report.Status)
	}
	if report.Remaining >= 0 {
		t.Error("expected negative remaining for overdue")
	}
}

func TestEvaluateSchedule_MessageNotEmpty(t *testing.T) {
	entry := makeEntry("secret/cert", 7*24*time.Hour, -time.Hour)
	report := EvaluateSchedule(entry, time.Hour)
	if report.Message == "" {
		t.Error("expected non-empty message")
	}
}

func TestBuildSchedule(t *testing.T) {
	policies := map[string]time.Duration{
		"secret/a": 24 * time.Hour,
		"secret/b": 48 * time.Hour,
	}
	lastRotated := map[string]time.Time{
		"secret/a": time.Now().Add(-12 * time.Hour),
		"secret/b": time.Now().Add(-50 * time.Hour),
	}
	entries := BuildSchedule(policies, lastRotated)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Path == "" {
			t.Error("entry path should not be empty")
		}
		expected := lastRotated[e.Path].Add(policies[e.Path])
		if !e.NextRotation.Equal(expected) {
			t.Errorf("NextRotation mismatch for %s", e.Path)
		}
	}
}
