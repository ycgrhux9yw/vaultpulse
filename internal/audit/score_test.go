package audit

import (
	"strings"
	"testing"
)

func scoreReports() []SecretReport {
	return []SecretReport{
		{Path: "secret/a", Status: "OK"},
		{Path: "secret/b", Status: "Warning"},
		{Path: "secret/c", Status: "Critical"},
		{Path: "secret/d", Status: "Expired"},
	}
}

func TestComputeScore_Counts(t *testing.T) {
	res := ComputeScore(scoreReports(), DefaultScoreWeights)
	if res.Counts["OK"] != 1 || res.Counts["Warning"] != 1 || res.Counts["Critical"] != 1 || res.Counts["Expired"] != 1 {
		t.Errorf("unexpected counts: %+v", res.Counts)
	}
}

func TestComputeScore_Total(t *testing.T) {
	res := ComputeScore(scoreReports(), DefaultScoreWeights)
	// 0 + 1 + 3 + 5 = 9
	if res.Total != 9.0 {
		t.Errorf("expected total 9.0, got %.1f", res.Total)
	}
}

func TestComputeScore_GradeA(t *testing.T) {
	reports := []SecretReport{
		{Path: "secret/a", Status: "OK"},
		{Path: "secret/b", Status: "OK"},
	}
	res := ComputeScore(reports, DefaultScoreWeights)
	if res.Grade != "A" {
		t.Errorf("expected grade A, got %s", res.Grade)
	}
}

func TestComputeScore_GradeF(t *testing.T) {
	reports := []SecretReport{
		{Path: "secret/a", Status: "Expired"},
		{Path: "secret/b", Status: "Expired"},
	}
	res := ComputeScore(reports, DefaultScoreWeights)
	if res.Grade != "F" {
		t.Errorf("expected grade F, got %s", res.Grade)
	}
}

func TestComputeScore_Empty(t *testing.T) {
	res := ComputeScore([]SecretReport{}, DefaultScoreWeights)
	if res.Total != 0 || res.Grade != "A" {
		t.Errorf("expected zero score and grade A for empty input")
	}
}

func TestFormatScore_ContainsGrade(t *testing.T) {
	res := ComputeScore(scoreReports(), DefaultScoreWeights)
	out := FormatScore(res)
	if !strings.Contains(out, "Grade:") {
		t.Errorf("expected 'Grade:' in output, got: %s", out)
	}
}
