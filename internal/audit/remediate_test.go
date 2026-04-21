package audit

import (
	"strings"
	"testing"
	"time"
)

var remediationReports = []SecretReport{
	{Path: "secret/db/prod", Status: "expired", TTL: 0},
	{Path: "secret/api/key", Status: "critical", TTL: 2 * time.Hour},
	{Path: "secret/tls/cert", Status: "warning", TTL: 48 * time.Hour},
	{Path: "secret/safe/token", Status: "ok", TTL: 720 * time.Hour},
}

func TestBuildRemediationPlan_ExcludesOK(t *testing.T) {
	plan := BuildRemediationPlan(remediationReports)
	for _, a := range plan.Actions {
		if strings.ToLower(a.Status) == "ok" {
			t.Errorf("expected ok secrets to be excluded, got path %q", a.Path)
		}
	}
}

func TestBuildRemediationPlan_ActionCount(t *testing.T) {
	plan := BuildRemediationPlan(remediationReports)
	if len(plan.Actions) != 3 {
		t.Errorf("expected 3 actions, got %d", len(plan.Actions))
	}
}

func TestBuildRemediationPlan_PriorityOrder(t *testing.T) {
	plan := BuildRemediationPlan(remediationReports)
	for i := 1; i < len(plan.Actions); i++ {
		if plan.Actions[i].Priority < plan.Actions[i-1].Priority {
			t.Errorf("actions not sorted by priority at index %d", i)
		}
	}
}

func TestBuildRemediationPlan_ExpiredIsP1(t *testing.T) {
	plan := BuildRemediationPlan([]SecretReport{
		{Path: "secret/x", Status: "expired", TTL: 0},
	})
	if len(plan.Actions) == 0 {
		t.Fatal("expected at least one action")
	}
	if plan.Actions[0].Priority != 1 {
		t.Errorf("expected priority 1 for expired, got %d", plan.Actions[0].Priority)
	}
}

func TestFormatPlan_ContainsHeader(t *testing.T) {
	plan := BuildRemediationPlan(remediationReports)
	out := FormatPlan(plan)
	if !strings.Contains(out, "Remediation Plan") {
		t.Error("expected output to contain 'Remediation Plan'")
	}
}

func TestFormatPlan_EmptyPlan(t *testing.T) {
	plan := BuildRemediationPlan([]SecretReport{
		{Path: "secret/fine", Status: "ok", TTL: 999 * time.Hour},
	})
	out := FormatPlan(plan)
	if !strings.Contains(out, "No remediation actions required") {
		t.Errorf("expected empty plan message, got: %s", out)
	}
}

func TestFormatPlan_ContainsPaths(t *testing.T) {
	plan := BuildRemediationPlan(remediationReports)
	out := FormatPlan(plan)
	for _, r := range remediationReports {
		if r.Status == "ok" {
			continue
		}
		if !strings.Contains(out, r.Path) {
			t.Errorf("expected output to contain path %q", r.Path)
		}
	}
}
