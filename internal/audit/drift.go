package audit

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// DriftEntry represents a detected drift between expected and actual TTL state.
type DriftEntry struct {
	Path        string
	ExpectedTTL time.Duration
	ActualTTL   time.Duration
	Delta       time.Duration
	Severity    string
	Message     string
}

// DriftConfig defines acceptable drift thresholds.
type DriftConfig struct {
	WarnDelta     time.Duration
	CriticalDelta time.Duration
}

// DefaultDriftConfig returns sensible drift detection defaults.
var DefaultDriftConfig = DriftConfig{
	WarnDelta:     24 * time.Hour,
	CriticalDelta: 72 * time.Hour,
}

// DetectDrift compares a set of SecretReports against expected TTLs derived
// from a baseline and returns any entries that have drifted beyond thresholds.
func DetectDrift(reports []SecretReport, baseline map[string]SecretReport, cfg DriftConfig) []DriftEntry {
	var entries []DriftEntry

	for _, r := range reports {
		base, ok := baseline[r.Path]
		if !ok {
			continue
		}

		delta := r.TTL - base.TTL
		if delta < 0 {
			delta = -delta
		}

		if delta < cfg.WarnDelta {
			continue
		}

		severity := "warning"
		if delta >= cfg.CriticalDelta {
			severity = "critical"
		}

		entries = append(entries, DriftEntry{
			Path:        r.Path,
			ExpectedTTL: base.TTL,
			ActualTTL:   r.TTL,
			Delta:       delta,
			Severity:    severity,
			Message:     fmt.Sprintf("TTL drifted by %s from baseline", delta.Round(time.Second)),
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Delta > entries[j].Delta
	})

	return entries
}

// FormatDrift returns a human-readable table of drift entries.
func FormatDrift(entries []DriftEntry) string {
	if len(entries) == 0 {
		return "No TTL drift detected.\n"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-40s %-14s %-14s %-10s %s\n",
		"PATH", "EXPECTED TTL", "ACTUAL TTL", "DELTA", "SEVERITY"))
	sb.WriteString(strings.Repeat("-", 90) + "\n")

	for _, e := range entries {
		sb.WriteString(fmt.Sprintf("%-40s %-14s %-14s %-10s %s\n",
			e.Path,
			e.ExpectedTTL.Round(time.Second),
			e.ActualTTL.Round(time.Second),
			e.Delta.Round(time.Second),
			e.Severity,
		))
	}

	return sb.String()
}
