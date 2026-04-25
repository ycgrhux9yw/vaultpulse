package audit

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// CompareResult represents the outcome of comparing two sets of secret reports.
type CompareResult struct {
	Path       string
	Field      string
	OldValue   string
	NewValue   string
	ChangeType string // "added", "removed", "modified"
}

// CompareOptions controls which fields are compared between report sets.
type CompareOptions struct {
	CheckStatus   bool
	CheckTTL      bool
	CheckExpiry   bool
	TTLDeltaSecs  int64 // minimum TTL change (in seconds) to flag as modified
}

// DefaultCompareOptions returns sensible defaults for comparison.
var DefaultCompareOptions = CompareOptions{
	CheckStatus:  true,
	CheckTTL:     true,
	CheckExpiry:  true,
	TTLDeltaSecs: 60,
}

// CompareReports compares two slices of SecretReport and returns a list of
// differences. Reports are matched by Path. Added/removed paths are included.
func CompareReports(before, after []SecretReport, opts CompareOptions) []CompareResult {
	beforeMap := make(map[string]SecretReport, len(before))
	for _, r := range before {
		beforeMap[r.Path] = r
	}
	afterMap := make(map[string]SecretReport, len(after))
	for _, r := range after {
		afterMap[r.Path] = r
	}

	var results []CompareResult

	// Detect removed and modified paths.
	for path, bReport := range beforeMap {
		aReport, exists := afterMap[path]
		if !exists {
			results = append(results, CompareResult{
				Path:       path,
				Field:      "path",
				OldValue:   path,
				NewValue:   "",
				ChangeType: "removed",
			})
			continue
		}
		results = append(results, diffReports(bReport, aReport, opts)...)
	}

	// Detect added paths.
	for path := range afterMap {
		if _, exists := beforeMap[path]; !exists {
			results = append(results, CompareResult{
				Path:       path,
				Field:      "path",
				OldValue:   "",
				NewValue:   path,
				ChangeType: "added",
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Path != results[j].Path {
			return results[i].Path < results[j].Path
		}
		return results[i].Field < results[j].Field
	})
	return results
}

// diffReports returns field-level differences between two reports for the same path.
func diffReports(before, after SecretReport, opts CompareOptions) []CompareResult {
	var diffs []CompareResult

	if opts.CheckStatus && before.Status != after.Status {
		diffs = append(diffs, CompareResult{
			Path:       before.Path,
			Field:      "status",
			OldValue:   before.Status,
			NewValue:   after.Status,
			ChangeType: "modified",
		})
	}

	if opts.CheckTTL {
		delta := before.TTL - after.TTL
		if delta < 0 {
			delta = -delta
		}
		if delta >= opts.TTLDeltaSecs {
			diffs = append(diffs, CompareResult{
				Path:       before.Path,
				Field:      "ttl",
				OldValue:   fmt.Sprintf("%ds", before.TTL),
				NewValue:   fmt.Sprintf("%ds", after.TTL),
				ChangeType: "modified",
			})
		}
	}

	if opts.CheckExpiry && !before.Expiry.IsZero() && !after.Expiry.IsZero() {
		diff := before.Expiry.Sub(after.Expiry)
		if diff < 0 {
			diff = -diff
		}
		if diff > time.Minute {
			diffs = append(diffs, CompareResult{
				Path:       before.Path,
				Field:      "expiry",
				OldValue:   before.Expiry.UTC().Format(time.RFC3339),
				NewValue:   after.Expiry.UTC().Format(time.RFC3339),
				ChangeType: "modified",
			})
		}
	}

	return diffs
}

// FormatCompare renders comparison results as a human-readable table.
func FormatCompare(results []CompareResult) string {
	if len(results) == 0 {
		return "No differences found.\n"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-45s %-10s %-10s %-26s %-26s\n",
		"PATH", "CHANGE", "FIELD", "BEFORE", "AFTER"))
	sb.WriteString(strings.Repeat("-", 120) + "\n")

	for _, r := range results {
		old := r.OldValue
		if len(old) > 24 {
			old = old[:21] + "..."
		}
		newVal := r.NewValue
		if len(newVal) > 24 {
			newVal = newVal[:21] + "..."
		}
		path := r.Path
		if len(path) > 43 {
			path = path[:40] + "..."
		}
		sb.WriteString(fmt.Sprintf("%-45s %-10s %-10s %-26s %-26s\n",
			path, r.ChangeType, r.Field, old, newVal))
	}
	return sb.String()
}
