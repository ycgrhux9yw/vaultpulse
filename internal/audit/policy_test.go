package audit

import (
	"testing"
	"time"
)

func policyReports() []SecretReport {
	return []SecretReport{
		{Path: "secret/db/password", TTL: 10 * time.Hour, Status: StatusOK},
		{Path: "secret/api/key", TTL: 200 * time.Hour, Status: StatusOK},
		{Path: "secret/db/token", TTL: 30 * time.Minute, Status: StatusWarning},
	}
}

func TestEvaluatePolicy_NoViolations(t *testing.T) {
	policy := Policy{Rules: []PolicyRule{
		{PathPrefix: "secret/", MaxTTL: 300 * time.Hour, WarnBeforeExpiry: 10 * time.Minute},
	}}
	v := EvaluatePolicy(policyReports(), policy)
	if len(v) != 0 {
		t.Fatalf("expected 0 violations, got %d", len(v))
	}
}

func TestEvaluatePolicy_MaxTTLViolation(t *testing.T) {
	policy := Policy{Rules: []PolicyRule{
		{PathPrefix: "secret/api", MaxTTL: 100 * time.Hour},
	}}
	v := EvaluatePolicy(policyReports(), policy)
	if len(v) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(v))
	}
	if v[0].Path != "secret/api/key" {
		t.Errorf("unexpected path %s", v[0].Path)
	}
}

func TestEvaluatePolicy_WarnWindowViolation(t *testing.T) {
	policy := Policy{Rules: []PolicyRule{
		{PathPrefix: "secret/db", WarnBeforeExpiry: 1 * time.Hour},
	}}
	v := EvaluatePolicy(policyReports(), policy)
	if len(v) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(v))
	}
	if v[0].Path != "secret/db/token" {
		t.Errorf("unexpected path %s", v[0].Path)
	}
}

func TestEvaluatePolicy_EmptyPrefix(t *testing.T) {
	policy := Policy{Rules: []PolicyRule{
		{PathPrefix: "", MaxTTL: 5 * time.Hour},
	}}
	v := EvaluatePolicy(policyReports(), policy)
	// secret/db/password (10h) and secret/api/key (200h) exceed 5h
	if len(v) != 2 {
		t.Fatalf("expected 2 violations, got %d", len(v))
	}
}

func TestEvaluatePolicy_NoRules(t *testing.T) {
	v := EvaluatePolicy(policyReports(), Policy{})
	if len(v) != 0 {
		t.Fatalf("expected 0 violations, got %d", len(v))
	}
}
