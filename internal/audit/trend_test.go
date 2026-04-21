package audit

import (
	"strings"
	"testing"
	"time"
)

func trendSnapshots() []SnapshotEntry {
	now := time.Now()
	return []SnapshotEntry{
		{
			CapturedAt: now.Add(-48 * time.Hour),
			Reports: []SecretReport{
				{Path: "secret/a", Status: "ok"},
				{Path: "secret/b", Status: "critical"},
			},
		},
		{
			CapturedAt: now.Add(-24 * time.Hour),
			Reports: []SecretReport{
				{Path: "secret/a", Status: "ok"},
				{Path: "secret/b", Status: "warning"},
			},
		},
		{
			CapturedAt: now,
			Reports: []SecretReport{
				{Path: "secret/a", Status: "ok"},
				{Path: "secret/b", Status: "ok"},
			},
		},
	}
}

func TestBuildTrend_PointCount(t *testing.T) {
	tr := BuildTrend(trendSnapshots())
	if len(tr.Points) != 3 {
		t.Fatalf("expected 3 points, got %d", len(tr.Points))
	}
}

func TestBuildTrend_Sorted(t *testing.T) {
	snaps := trendSnapshots()
	// reverse order to test sorting
	snaps[0], snaps[2] = snaps[2], snaps[0]
	tr := BuildTrend(snaps)
	for i := 1; i < len(tr.Points); i++ {
		if tr.Points[i].Timestamp.Before(tr.Points[i-1].Timestamp) {
			t.Errorf("points not sorted at index %d", i)
		}
	}
}

func TestBuildTrend_ScoreImproves(t *testing.T) {
	tr := BuildTrend(trendSnapshots())
	if tr.Points[2].Score <= tr.Points[0].Score {
		t.Errorf("expected score to improve over time, got %.1f -> %.1f",
			tr.Points[0].Score, tr.Points[2].Score)
	}
}

func TestFormatTrend_ContainsHeader(t *testing.T) {
	tr := BuildTrend(trendSnapshots())
	out := FormatTrend(tr)
	if !strings.Contains(out, "Score") {
		t.Error("expected header to contain 'Score'")
	}
}

func TestFormatTrend_Empty(t *testing.T) {
	out := FormatTrend(TrendReport{})
	if !strings.Contains(out, "No trend data") {
		t.Errorf("expected empty message, got: %s", out)
	}
}
