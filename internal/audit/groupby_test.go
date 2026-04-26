package audit

import (
	"testing"
)

var groupSample = []SecretReport{
	{Path: "secret/team-a/db/password", Status: StatusOK, TTLSeconds: 3600},
	{Path: "secret/team-a/api/key", Status: StatusWarning, TTLSeconds: 1200},
	{Path: "secret/team-b/db/creds", Status: StatusCritical, TTLSeconds: 300},
	{Path: "infra/team-b/cert", Status: StatusExpired, TTLSeconds: 0},
	{Path: "infra/team-a/token", Status: StatusOK, TTLSeconds: 7200},
}

func TestGroupReports_ByPrefix(t *testing.T) {
	groups, err := GroupReports(groupSample, GroupByPrefix)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	if groups[0].Key != "infra" {
		t.Errorf("expected first group 'infra', got %q", groups[0].Key)
	}
	if groups[1].Key != "secret" {
		t.Errorf("expected second group 'secret', got %q", groups[1].Key)
	}
}

func TestGroupReports_ByStatus(t *testing.T) {
	groups, err := GroupReports(groupSample, GroupByStatus)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	statuses := make(map[string]int)
	for _, g := range groups {
		statuses[g.Key] = len(g.Reports)
	}
	if statuses[string(StatusOK)] != 2 {
		t.Errorf("expected 2 OK, got %d", statuses[string(StatusOK)])
	}
	if statuses[string(StatusWarning)] != 1 {
		t.Errorf("expected 1 Warning, got %d", statuses[string(StatusWarning)])
	}
}

func TestGroupReports_ByTeam(t *testing.T) {
	reports := []SecretReport{
		{Path: "secret/team:eng/env:prod/db", Status: StatusOK, TTLSeconds: 3600},
		{Path: "secret/team:ops/env:prod/cert", Status: StatusWarning, TTLSeconds: 900},
		{Path: "secret/nolabel/token", Status: StatusOK, TTLSeconds: 7200},
	}
	groups, err := GroupReports(reports, GroupByTeam)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	keys := make(map[string]bool)
	for _, g := range groups {
		keys[g.Key] = true
	}
	if !keys["unknown"] {
		t.Error("expected 'unknown' group for paths without team tag")
	}
}

func TestGroupReports_InvalidKey(t *testing.T) {
	_, err := GroupReports(groupSample, GroupKey("invalid"))
	if err == nil {
		t.Error("expected error for unsupported group key")
	}
}

func TestFormatGrouped_ContainsHeader(t *testing.T) {
	groups, _ := GroupReports(groupSample, GroupByPrefix)
	out := FormatGrouped(groups)
	if !contains(out, "GROUP") {
		t.Error("expected header 'GROUP' in output")
	}
	if !contains(out, "secret") {
		t.Error("expected 'secret' prefix in output")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
