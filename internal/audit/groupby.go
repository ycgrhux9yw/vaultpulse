package audit

import (
	"fmt"
	"sort"
	"strings"
)

// GroupKey defines the field to group secret reports by.
type GroupKey string

const (
	GroupByPrefix GroupKey = "prefix"
	GroupByStatus GroupKey = "status"
	GroupByTeam   GroupKey = "team"
)

// GroupResult holds a named collection of SecretReports.
type GroupResult struct {
	Key     string
	Reports []SecretReport
}

// GroupReports partitions reports by the given GroupKey.
// Returns groups sorted by key name.
func GroupReports(reports []SecretReport, by GroupKey) ([]GroupResult, error) {
	index := make(map[string][]SecretReport)

	for _, r := range reports {
		var key string
		switch by {
		case GroupByPrefix:
			key = topLevelPrefix(r.Path)
		case GroupByStatus:
			key = string(r.Status)
		case GroupByTeam:
			tags := ParseTagsFromPath(r.Path)
			key = tags["team"]
			if key == "" {
				key = "unknown"
			}
		default:
			return nil, fmt.Errorf("unsupported group key: %q", by)
		}
		index[key] = append(index[key], r)
	}

	results := make([]GroupResult, 0, len(index))
	for k, v := range index {
		results = append(results, GroupResult{Key: k, Reports: v})
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Key < results[j].Key
	})
	return results, nil
}

// FormatGrouped returns a human-readable table of grouped results.
func FormatGrouped(groups []GroupResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-30s %6s %8s %8s %8s\n",
		"GROUP", "TOTAL", "OK", "WARN", "CRIT"))
	sb.WriteString(strings.Repeat("-", 64) + "\n")
	for _, g := range groups {
		ok, warn, crit := 0, 0, 0
		for _, r := range g.Reports {
			switch r.Status {
			case StatusOK:
				ok++
			case StatusWarning:
				warn++
			case StatusCritical, StatusExpired:
				crit++
			}
		}
		sb.WriteString(fmt.Sprintf("%-30s %6d %8d %8d %8d\n",
			g.Key, len(g.Reports), ok, warn, crit))
	}
	return sb.String()
}

// topLevelPrefix returns the first path segment of a secret path.
func topLevelPrefix(path string) string {
	parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		return "root"
	}
	return parts[0]
}
