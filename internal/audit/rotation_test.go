package audit

import (
	"testing"
	"time"
)

func TestEvaluateRotation_OK(t *testing.T) {
	lastRotated := time.Now().Add(-30 * 24 * time.Hour) // 30 days ago
	result := EvaluateRotation("secret/db/password", lastRotated, DefaultRotationPolicy)

	if result.Status != RotationOK {
		t.Errorf("expected OK, got %s: %s", result.Status, result.Message)
	}
}

func TestEvaluateRotation_Due(t *testing.T) {
	// 80 days ago — within 14-day warning window of 90-day max
	lastRotated := time.Now().Add(-80 * 24 * time.Hour)
	result := EvaluateRotation("secret/api/key", lastRotated, DefaultRotationPolicy)

	if result.Status != RotationDue {
		t.Errorf("expected DUE, got %s: %s", result.Status, result.Message)
	}
}

func TestEvaluateRotation_Overdue(t *testing.T) {
	lastRotated := time.Now().Add(-100 * 24 * time.Hour) // 100 days ago
	result := EvaluateRotation("secret/ssh/key", lastRotated, DefaultRotationPolicy)

	if result.Status != RotationOverdue {
		t.Errorf("expected OVERDUE, got %s: %s", result.Status, result.Message)
	}
}

func TestEvaluateRotation_Unknown(t *testing.T) {
	result := EvaluateRotation("secret/unknown", time.Time{}, DefaultRotationPolicy)

	if result.Status != RotationUnknown {
		t.Errorf("expected UNKNOWN, got %s", result.Status)
	}
}

func TestEvaluateRotation_CustomPolicy(t *testing.T) {
	policy := RotationPolicy{
		MaxAge:     7 * 24 * time.Hour,
		WarnBefore: 2 * 24 * time.Hour,
	}
	lastRotated := time.Now().Add(-6 * 24 * time.Hour) // 6 days ago, within warn window
	result := EvaluateRotation("secret/token", lastRotated, policy)

	if result.Status != RotationDue {
		t.Errorf("expected DUE with custom policy, got %s", result.Status)
	}
}

func TestEvaluateRotation_PathPreserved(t *testing.T) {
	path := "secret/my/service"
	lastRotated := time.Now().Add(-10 * 24 * time.Hour)
	result := EvaluateRotation(path, lastRotated, DefaultRotationPolicy)

	if result.Path != path {
		t.Errorf("expected path %q, got %q", path, result.Path)
	}
}
