package audit

import (
	"fmt"
	"sort"
	"strings"
)

// HeatmapCell represents a single cell in the secret health heatmap.
type HeatmapCell struct {
	Path   string
	Status string
	Score  int
}

// HeatmapRow groups cells by a common path prefix (namespace/mount).
type HeatmapRow struct {
	Prefix string
	Cells  []HeatmapCell
	AvgScore float64
}

// BuildHeatmap groups SecretReports by their top-level path prefix and
// computes per-group average scores for a visual health overview.
func BuildHeatmap(reports []SecretReport) []HeatmapRow {
	groups := make(map[string][]SecretReport)

	for _, r := range reports {
		parts := strings.SplitN(r.Path, "/", 3)
		prefix := parts[0]
		if len(parts) > 1 {
			prefix = parts[0] + "/" + parts[1]
		}
		groups[prefix] = append(groups[prefix], r)
	}

	prefixes := make([]string, 0, len(groups))
	for p := range groups {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)

	var rows []HeatmapRow
	for _, prefix := range prefixes {
		group := groups[prefix]
		score := ComputeScore(group)
		var cells []HeatmapCell
		for _, r := range group {
			cells = append(cells, HeatmapCell{
				Path:   r.Path,
				Status: r.Status,
				Score:  int(score.Score),
			})
		}
		rows = append(rows, HeatmapRow{
			Prefix:   prefix,
			Cells:    cells,
			AvgScore: score.Score,
		})
	}
	return rows
}

// FormatHeatmap renders a text-based heatmap table to a string.
func FormatHeatmap(rows []HeatmapRow) string {
	if len(rows) == 0 {
		return "no data available for heatmap\n"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-40s  %6s  %5s  %s\n", "PREFIX", "SCORE", "GRADE", "SECRETS"))
	sb.WriteString(strings.Repeat("-", 70) + "\n")

	for _, row := range rows {
		g := grade(row.AvgScore)
		sb.WriteString(fmt.Sprintf("%-40s  %6.1f  %5s  %d\n",
			row.Prefix, row.AvgScore, g, len(row.Cells)))
	}
	return sb.String()
}
