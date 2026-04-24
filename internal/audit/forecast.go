package audit

import (
	"fmt"
	"sort"
	"time"
)

// ForecastEntry represents a predicted future state for a secret.
type ForecastEntry struct {
	Path        string
	CurrentTTL  time.Duration
	PredictedAt time.Time
	PredictedStatus string
	DaysUntilCritical int
	DaysUntilExpiry   int
}

// BuildForecast projects the TTL status of secrets over the given horizon (in days).
func BuildForecast(reports []SecretReport, horizonDays int, thresholds TTLThresholds) []ForecastEntry {
	now := time.Now()
	entries := make([]ForecastEntry, 0, len(reports))

	for _, r := range reports {
		if r.TTL <= 0 {
			continue
		}

		daysUntilCritical := int(r.TTL.Seconds()-thresholds.CriticalBelow.Seconds()) / 86400
		daysUntilExpiry := int(r.TTL.Hours() / 24)

		if daysUntilCritical < 0 {
			daysUntilCritical = 0
		}

		predictedAt := now.Add(time.Duration(horizonDays) * 24 * time.Hour)
		remainingAtHorizon := r.TTL - time.Duration(horizonDays)*24*time.Hour

		var predictedStatus string
		switch {
		case remainingAtHorizon <= 0:
			predictedStatus = "Expired"
		case remainingAtHorizon < thresholds.CriticalBelow:
			predictedStatus = "Critical"
		case remainingAtHorizon < thresholds.WarnBelow:
			predictedStatus = "Warning"
		default:
			predictedStatus = "OK"
		}

		entries = append(entries, ForecastEntry{
			Path:              r.Path,
			CurrentTTL:        r.TTL,
			PredictedAt:       predictedAt,
			PredictedStatus:   predictedStatus,
			DaysUntilCritical: daysUntilCritical,
			DaysUntilExpiry:   daysUntilExpiry,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].DaysUntilExpiry < entries[j].DaysUntilExpiry
	})

	return entries
}

// FormatForecast renders the forecast as a human-readable table string.
func FormatForecast(entries []ForecastEntry, horizonDays int) string {
	if len(entries) == 0 {
		return "No forecastable secrets found.\n"
	}

	header := fmt.Sprintf("%-45s %-12s %-10s %-10s\n",
		"PATH", "STATUS@+"+fmt.Sprintf("%dd", horizonDays), "DAYS->CRIT", "DAYS->EXP")
	sep := fmt.Sprintf("%s\n", repeatChar('-', 80))
	out := header + sep

	for _, e := range entries {
		out += fmt.Sprintf("%-45s %-12s %-10d %-10d\n",
			e.Path, e.PredictedStatus, e.DaysUntilCritical, e.DaysUntilExpiry)
	}

	return out
}

func repeatChar(c rune, n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}
