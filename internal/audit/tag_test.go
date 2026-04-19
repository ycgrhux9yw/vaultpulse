package audit

import (
	"testing"

	"github.com/your-org/vaultpulse/internal/vault"
)

func taggedSample() []TaggedReport {
	return []TaggedReport{
		{Report: vault.SecretReport{Path: "secret/teamA/prod/db"}, Tags: map[string]string{"team": "teamA", "env": "prod"}},
		{Report: vault.SecretReport{Path: "secret/teamB/staging/api"}, Tags: map[string]string{"team": "teamB", "env": "staging"}},
		{Report: vault.SecretReport{Path: "secret/teamA/staging/cache"}, Tags: map[string]string{"team": "teamA", "env": "staging"}},
	}
}

func TestApplyTagFilter_ByTeam(t *testing.T) {
	res := ApplyTagFilter(taggedSample(), TagFilter{RequiredTags: map[string]string{"team": "teamA"}})
	if len(res) != 2 {
		t.Fatalf("expected 2, got %d", len(res))
	}
}

func TestApplyTagFilter_ByTeamAndEnv(t *testing.T) {
	res := ApplyTagFilter(taggedSample(), TagFilter{RequiredTags: map[string]string{"team": "teamA", "env": "prod"}})
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Report.Path != "secret/teamA/prod/db" {
		t.Errorf("unexpected path: %s", res[0].Report.Path)
	}
}

func TestApplyTagFilter_NoMatch(t *testing.T) {
	res := ApplyTagFilter(taggedSample(), TagFilter{RequiredTags: map[string]string{"team": "teamC"}})
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestApplyTagFilter_Empty(t *testing.T) {
	res := ApplyTagFilter(taggedSample(), TagFilter{})
	if len(res) != 3 {
		t.Fatalf("expected 3, got %d", len(res))
	}
}

func TestParseTagsFromPath(t *testing.T) {
	tags := ParseTagsFromPath("secret/teamA/prod/db")
	if tags["team"] != "teamA" {
		t.Errorf("expected teamA, got %s", tags["team"])
	}
	if tags["env"] != "prod" {
		t.Errorf("expected prod, got %s", tags["env"])
	}
}

func TestParseTagsFromPath_Short(t *testing.T) {
	tags := ParseTagsFromPath("secret/only")
	if len(tags) != 0 {
		t.Errorf("expected no tags for short path")
	}
}
