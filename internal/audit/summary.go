package audit

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// SummaryReport holds an aggregated executive summary across all evaluated secrets.
type SummaryReport struct {
	GeneratedAt  time.Time
	TotalSecrets int
	ByStatus     map[string]int
	TopRisks     []SecretReport
	AvgTTLDays   float64
	Grade        string
	Score        int
}

// BuildSummary creates a SummaryReport from a slice of SecretReports.
func BuildSummary(reports []SecretReport) SummaryReport {
	if len(reports) == 0 {
		return SummaryReport{GeneratedAt: time.Now()}
	}

	byStatus := make(map[string]int)
	var ttlSum float64
	var ttlCount int

	for _, r := range reports {
		byStatus[r.Status]++
		if r.TTL > 0 {
			ttlSum += r.TTL.Hours() / 24
			ttlCount++
		}
	}

	var avgTTL float64
	if ttlCount > 0 {
		avgTTL = ttlSum / float64(ttlCount)
	}

	// top risks: expired > critical > warning, up to 5
	risks := make([]SecretReport, len(reports))
	copy(risks, reports)
	sort.Slice(risks, func(i, j int) bool {
		return levelRank(risks[i].Status) > levelRank(risks[j].Status)
	})
	if len(risks) > 5 {
		risks = risks[:5]
	}

	sc := ComputeScore(reports)

	return SummaryReport{
		GeneratedAt:  time.Now(),
		TotalSecrets: len(reports),
		ByStatus:     byStatus,
		TopRisks:     risks,
		AvgTTLDays:   avgTTL,
		Grade:        sc.Grade,
		Score:        sc.Score,
	}
}

// FormatSummary returns a human-readable summary string.
func FormatSummary(s SummaryReport) string {
	var sb strings.Builder
	sb.WriteString("=== VaultPulse Executive Summary ===\n")
	sb.WriteString(fmt.Sprintf("Generated : %s\n", s.GeneratedAt.Format(time.RFC1123)))
	sb.WriteString(fmt.Sprintf("Secrets   : %d\n", s.TotalSecrets))
	sb.WriteString(fmt.Sprintf("Score     : %d  Grade: %s\n", s.Score, s.Grade))
	sb.WriteString(fmt.Sprintf("Avg TTL   : %.1f days\n", s.AvgTTLDays))
	sb.WriteString("\nStatus Breakdown:\n")
	for _, st := range []string{"ok", "warning", "critical", "expired", "unknown"} {
		if n, ok := s.ByStatus[st]; ok {
			sb.WriteString(fmt.Sprintf("  %-10s %d\n", st, n))
		}
	}
	if len(s.TopRisks) > 0 {
		sb.WriteString("\nTop Risks:\n")
		for _, r := range s.TopRisks {
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", r.Status, r.Path))
		}
	}
	return sb.String()
}

// ActionableInsights returns a slice of human-readable recommendation strings
// derived from the summary, suitable for display in CLI output or reports.
func ActionableInsights(s SummaryReport) []string {
	var insights []string
	if n := s.ByStatus["expired"]; n > 0 {
		insights = append(insights, fmt.Sprintf("Rotate %d expired secret(s) immediately.", n))
	}
	if n := s.ByStatus["critical"]; n > 0 {
		insights = append(insights, fmt.Sprintf("Review %d critical secret(s) expiring very soon.", n))
	}
	if s.AvgTTLDays > 0 && s.AvgTTLDays < 7 {
		insights = append(insights, fmt.Sprintf("Average TTL is low (%.1f days); consider extending secret lifetimes.", s.AvgTTLDays))
	}
	if s.Score < 50 {
		insights = append(insights, "Overall vault health is poor; prioritise a full secret audit.")
	}
	return insights
}
