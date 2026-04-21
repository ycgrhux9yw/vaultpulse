package audit

import (
	"fmt"
	"strings"
	"time"
)

// RemediationAction describes a suggested corrective action for a secret report.
type RemediationAction struct {
	Path       string
	Status     string
	TTL        time.Duration
	Suggestion string
	Priority   int // 1 = high, 2 = medium, 3 = low
}

// RemediationPlan holds a list of actions sorted by priority.
type RemediationPlan struct {
	Actions   []RemediationAction
	CreatedAt time.Time
}

// BuildRemediationPlan generates a remediation plan from a slice of SecretReports.
func BuildRemediationPlan(reports []SecretReport) RemediationPlan {
	plan := RemediationPlan{CreatedAt: time.Now()}

	for _, r := range reports {
		action := remediationFor(r)
		if action != nil {
			plan.Actions = append(plan.Actions, *action)
		}
	}

	// Sort: priority 1 first
	sortActions(plan.Actions)
	return plan
}

func remediationFor(r SecretReport) *RemediationAction {
	switch strings.ToLower(r.Status) {
	case "expired":
		return &RemediationAction{
			Path:       r.Path,
			Status:     r.Status,
			TTL:        r.TTL,
			Suggestion: fmt.Sprintf("Secret at %q has expired. Rotate or renew immediately.", r.Path),
			Priority:   1,
		}
	case "critical":
		return &RemediationAction{
			Path:       r.Path,
			Status:     r.Status,
			TTL:        r.TTL,
			Suggestion: fmt.Sprintf("Secret at %q is critically close to expiry (TTL: %s). Schedule rotation now.", r.Path, r.TTL.Round(time.Second)),
			Priority:   1,
		}
	case "warning":
		return &RemediationAction{
			Path:       r.Path,
			Status:     r.Status,
			TTL:        r.TTL,
			Suggestion: fmt.Sprintf("Secret at %q is nearing expiry (TTL: %s). Plan rotation soon.", r.Path, r.TTL.Round(time.Second)),
			Priority:   2,
		}
	default:
		return nil
	}
}

func sortActions(actions []RemediationAction) {
	// Simple insertion sort by priority (small slice expected)
	for i := 1; i < len(actions); i++ {
		for j := i; j > 0 && actions[j].Priority < actions[j-1].Priority; j-- {
			actions[j], actions[j-1] = actions[j-1], actions[j]
		}
	}
}

// FormatPlan returns a human-readable string of the remediation plan.
func FormatPlan(plan RemediationPlan) string {
	if len(plan.Actions) == 0 {
		return "No remediation actions required.\n"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Remediation Plan (%s)\n", plan.CreatedAt.Format(time.RFC3339)))
	sb.WriteString(strings.Repeat("-", 60) + "\n")
	for _, a := range plan.Actions {
		sb.WriteString(fmt.Sprintf("[P%d] %s\n  → %s\n", a.Priority, a.Path, a.Suggestion))
	}
	return sb.String()
}
