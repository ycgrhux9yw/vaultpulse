package audit

import (
	"strings"
	"time"
)

// FilterOptions defines criteria for filtering audit reports.
type FilterOptions struct {
	Status    string // "ok", "warning", "critical", "expired", or "" for all
	PathPrefix string
	MinTTL    time.Duration
	MaxTTL    time.Duration
}

// FilterReports returns a subset of reports matching the given options.
func FilterReports(reports []Report, opts FilterOptions) []Report {
	var out []Report
	for _, r := range reports {
		if opts.Status != "" && !strings.EqualFold(r.Status, opts.Status) {
			continue
		}
		if opts.PathPrefix != "" && !strings.HasPrefix(r.Path, opts.PathPrefix) {
			continue
		}
		if opts.MinTTL > 0 && r.TTL < opts.MinTTL {
			continue
		}
		if opts.MaxTTL > 0 && r.TTL > opts.MaxTTL {
			continue
		}
		out = append(out, r)
	}
	return out
}
