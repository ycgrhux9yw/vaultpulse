package audit

import "fmt"

// ScoreWeights defines how much each status contributes to the risk score.
type ScoreWeights struct {
	OK       float64
	Warning  float64
	Critical float64
	Expired  float64
}

// DefaultScoreWeights provides sensible defaults.
var DefaultScoreWeights = ScoreWeights{
	OK:       0.0,
	Warning:  1.0,
	Critical: 3.0,
	Expired:  5.0,
}

// ScoreResult holds the computed risk score and breakdown.
type ScoreResult struct {
	Total    float64
	MaxScore float64
	Percent  float64
	Grade    string
	Counts   map[string]int
}

// ComputeScore calculates a risk score across all SecretReports.
func ComputeScore(reports []SecretReport, w ScoreWeights) ScoreResult {
	counts := map[string]int{"OK": 0, "Warning": 0, "Critical": 0, "Expired": 0}
	var total float64

	for _, r := range reports {
		switch r.Status {
		case "OK":
			counts["OK"]++
			total += w.OK
		case "Warning":
			counts["Warning"]++
			total += w.Warning
		case "Critical":
			counts["Critical"]++
			total += w.Critical
		case "Expired":
			counts["Expired"]++
			total += w.Expired
		}
	}

	maxScore := float64(len(reports)) * w.Expired
	var percent float64
	if maxScore > 0 {
		percent = (total / maxScore) * 100
	}

	return ScoreResult{
		Total:    total,
		MaxScore: maxScore,
		Percent:  percent,
		Grade:    grade(percent),
		Counts:   counts,
	}
}

func grade(pct float64) string {
	switch {
	case pct == 0:
		return "A"
	case pct < 20:
		return "B"
	case pct < 40:
		return "C"
	case pct < 60:
		return "D"
	default:
		return "F"
	}
}

// FormatScore returns a human-readable summary line.
func FormatScore(r ScoreResult) string {
	return fmt.Sprintf("Risk Score: %.1f / %.1f (%.1f%%) — Grade: %s | OK:%d Warn:%d Crit:%d Exp:%d",
		r.Total, r.MaxScore, r.Percent, r.Grade,
		r.Counts["OK"], r.Counts["Warning"], r.Counts["Critical"], r.Counts["Expired"])
}
