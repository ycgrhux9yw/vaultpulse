package audit

import (
	"fmt"
	"sort"
	"strings"
)

// AnomalyLevel indicates the severity of a detected anomaly.
type AnomalyLevel string

const (
	AnomalyLow    AnomalyLevel = "low"
	AnomalyMedium AnomalyLevel = "medium"
	AnomalyHigh   AnomalyLevel = "high"
)

// Anomaly represents an unusual pattern detected across secret reports.
type Anomaly struct {
	Path    string
	Level   AnomalyLevel
	Reason  string
}

// DetectAnomalies inspects a slice of SecretReports and flags secrets whose
// TTL deviates significantly from the group median, or that are already expired.
func DetectAnomalies(reports []SecretReport, deviationFactor float64) []Anomaly {
	if len(reports) == 0 {
		return nil
	}
	if deviationFactor <= 0 {
		deviationFactor = 2.0
	}

	var ttls []float64
	for _, r := range reports {
		if r.TTL > 0 {
			ttls = append(ttls, float64(r.TTL))
		}
	}

	median := computeMedian(ttls)

	var anomalies []Anomaly
	for _, r := range reports {
		switch r.Status {
		case StatusExpired:
			anomalies = append(anomalies, Anomaly{
				Path:   r.Path,
				Level:  AnomalyHigh,
				Reason: "secret is expired",
			})
			continue
		case StatusCritical:
			anomalies = append(anomalies, Anomaly{
				Path:   r.Path,
				Level:  AnomalyMedium,
				Reason: "secret TTL is critically low",
			})
			continue
		}

		if median > 0 && r.TTL > 0 {
			ratio := float64(r.TTL) / median
			if ratio > deviationFactor {
				anomalies = append(anomalies, Anomaly{
					Path:   r.Path,
					Level:  AnomalyLow,
					Reason: fmt.Sprintf("TTL %.0fs is %.1fx above median %.0fs", float64(r.TTL), ratio, median),
				})
			} else if ratio < 1.0/deviationFactor {
				anomalies = append(anomalies, Anomaly{
					Path:   r.Path,
					Level:  AnomalyMedium,
					Reason: fmt.Sprintf("TTL %.0fs is %.1fx below median %.0fs", float64(r.TTL), 1.0/ratio, median),
				})
			}
		}
	}

	sort.Slice(anomalies, func(i, j int) bool {
		return levelRank(anomalies[i].Level) > levelRank(anomalies[j].Level)
	})
	return anomalies
}

// FormatAnomalies renders anomalies as a human-readable table.
func FormatAnomalies(anomalies []Anomaly) string {
	if len(anomalies) == 0 {
		return "No anomalies detected.\n"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-8s  %-40s  %s\n", "LEVEL", "PATH", "REASON"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")
	for _, a := range anomalies {
		sb.WriteString(fmt.Sprintf("%-8s  %-40s  %s\n", a.Level, a.Path, a.Reason))
	}
	return sb.String()
}

func computeMedian(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sorted := make([]float64, len(vals))
	copy(sorted, vals)
	sort.Float64s(sorted)
	n := len(sorted)
	if n%2 == 0 {
		return (sorted[n/2-1] + sorted[n/2]) / 2
	}
	return sorted[n/2]
}

func levelRank(l AnomalyLevel) int {
	switch l {
	case AnomalyHigh:
		return 3
	case AnomalyMedium:
		return 2
	case AnomalyLow:
		return 1
	}
	return 0
}
