package audit

import (
	"strings"

	"github.com/your-org/vaultpulse/internal/vault"
)

// TagFilter holds tag-based filtering criteria.
type TagFilter struct {
	RequiredTags map[string]string // key=value pairs that must all match
}

// TaggedReport associates a SecretReport with metadata tags.
type TaggedReport struct {
	Report vault.SecretReport
	Tags   map[string]string
}

// ApplyTagFilter returns only those TaggedReports whose tags satisfy all
// required key=value pairs in the filter.
func ApplyTagFilter(reports []TaggedReport, f TagFilter) []TaggedReport {
	if len(f.RequiredTags) == 0 {
		return reports
	}
	var out []TaggedReport
	for _, r := range reports {
		if matchesTags(r.Tags, f.RequiredTags) {
			out = append(out, r)
		}
	}
	return out
}

// ParseTagsFromPath extracts pseudo-tags encoded in a Vault path.
// Convention: secret/<team>/<env>/name => team=<team>, env=<env>
func ParseTagsFromPath(path string) map[string]string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	tags := make(map[string]string)
	if len(parts) >= 3 {
		tags["team"] = parts[1]
		tags["env"] = parts[2]
	}
	return tags
}

func matchesTags(have, required map[string]string) bool {
	for k, v := range required {
		if have[k] != v {
			return false
		}
	}
	return true
}
