package audit

import (
	"fmt"
	"sort"
	"time"
)

// TrendPoint represents a scored snapshot at a point in time.
type TrendPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Score     float64   `json:"score"`
	Grade     string    `json:"grade"`
	OK        int       `json:"ok"`
	Warning   int       `json:"warning"`
	Critical  int       `json:"critical"`
	Expired   int       `json:"expired"`
}

// TrendReport holds an ordered series of trend points.
type TrendReport struct {
	Points []TrendPoint `json:"points"`
}

// BuildTrend constructs a TrendReport from a slice of named snapshots.
// Each entry in snapshots maps a label/timestamp string to SecretReports.
func BuildTrend(snapshots []SnapshotEntry) TrendReport {
	points := make([]TrendPoint, 0, len(snapshots))
	for _, s := range snapshots {
		sc := ComputeScore(s.Reports)
		points = append(points, TrendPoint{
			Timestamp: s.CapturedAt,
			Score:     sc.Score,
			Grade:     sc.Grade,
			OK:        sc.OK,
			Warning:   sc.Warning,
			Critical:  sc.Critical,
			Expired:   sc.Expired,
		})
	}
	sort.Slice(points, func(i, j int) bool {
		return points[i].Timestamp.Before(points[j].Timestamp)
	})
	return TrendReport{Points: points}
}

// FormatTrend returns a human-readable table of the trend report.
func FormatTrend(tr TrendReport) string {
	if len(tr.Points) == 0 {
		return "No trend data available.\n"
	}
	out := fmt.Sprintf("%-25s %6s %5s %7s %8s %7s\n",
		"Timestamp", "Score", "Grade", "OK", "Warning", "Critical")
	out += fmt.Sprintf("%s\n", "---------------------------------------------------------------")
	for _, p := range tr.Points {
		out += fmt.Sprintf("%-25s %6.1f %5s %7d %8d %7d\n",
			p.Timestamp.Format(time.RFC3339),
			p.Score,
			p.Grade,
			p.OK,
			p.Warning,
			p.Critical,
		)
	}
	return out
}

// SnapshotEntry pairs a captured-at timestamp with its reports.
type SnapshotEntry struct {
	CapturedAt time.Time     `json:"captured_at"`
	Reports    []SecretReport `json:"reports"`
}
