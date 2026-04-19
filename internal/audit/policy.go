package audit

import (
	"fmt"
	"time"
)

// PolicyRule defines a TTL/rotation rule for a secret path prefix.
type PolicyRule struct {
	PathPrefix      string        `json:"path_prefix"`
	MaxTTL          time.Duration `json:"max_ttl"`
	RotationPeriod  time.Duration `json:"rotation_period"`
	WarnBeforeExpiry time.Duration `json:"warn_before_expiry"`
}

// Policy holds a collection of rules.
type Policy struct {
	Rules []PolicyRule `json:"rules"`
}

// PolicyViolation describes a rule breach for a secret.
type PolicyViolation struct {
	Path    string
	Rule    PolicyRule
	Message string
}

// EvaluatePolicy checks SecretReports against a Policy and returns violations.
func EvaluatePolicy(reports []SecretReport, policy Policy) []PolicyViolation {
	var violations []PolicyViolation
	for _, r := range reports {
		for _, rule := range policy.Rules {
			if !matchesPrefix(r.Path, rule.PathPrefix) {
				continue
			}
			if rule.MaxTTL > 0 && r.TTL > rule.MaxTTL {
				violations = append(violations, PolicyViolation{
					Path: r.Path,
					Rule: rule,
					Message: fmt.Sprintf("TTL %s exceeds max allowed %s", r.TTL, rule.MaxTTL),
				})
			}
			if rule.WarnBeforeExpiry > 0 && r.TTL > 0 && r.TTL < rule.WarnBeforeExpiry {
				violations = append(violations, PolicyViolation{
					Path: r.Path,
					Rule: rule,
					Message: fmt.Sprintf("TTL %s is within warn window %s", r.TTL, rule.WarnBeforeExpiry),
				})
			}
		}
	}
	return violations
}

func matchesPrefix(path, prefix string) bool {
	if prefix == "" {
		return true
	}
	if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
		return true
	}
	return false
}
