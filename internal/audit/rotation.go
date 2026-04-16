package audit

import "time"

// RotationStatus represents the rotation health of a secret.
type RotationStatus string

const (
	RotationOK       RotationStatus = "OK"
	RotationDue      RotationStatus = "DUE"
	RotationOverdue  RotationStatus = "OVERDUE"
	RotationUnknown  RotationStatus = "UNKNOWN"
)

// RotationPolicy defines the expected rotation schedule for a secret.
type RotationPolicy struct {
	// MaxAge is the maximum allowed age before a secret must be rotated.
	MaxAge time.Duration
	// WarnBefore is how far in advance to warn before rotation is due.
	WarnBefore time.Duration
}

// DefaultRotationPolicy is a sensible default rotation policy.
var DefaultRotationPolicy = RotationPolicy{
	MaxAge:     90 * 24 * time.Hour, // 90 days
	WarnBefore: 14 * 24 * time.Hour, // warn 14 days before
}

// RotationResult holds the result of evaluating a secret's rotation schedule.
type RotationResult struct {
	Path        string
	LastRotated time.Time
	Age         time.Duration
	Status      RotationStatus
	Message     string
}

// EvaluateRotation checks whether a secret needs rotation based on its last
// rotation time and the provided policy.
func EvaluateRotation(path string, lastRotated time.Time, policy RotationPolicy) RotationResult {
	if lastRotated.IsZero() {
		return RotationResult{
			Path:    path,
			Status:  RotationUnknown,
			Message: "last rotation time unavailable",
		}
	}

	now := time.Now()
	age := now.Sub(lastRotated)
	dueIn := policy.MaxAge - age

	var status RotationStatus
	var message string

	switch {
	case age >= policy.MaxAge:
		status = RotationOverdue
		message = "secret rotation is overdue"
	case dueIn <= policy.WarnBefore:
		status = RotationDue
		message = "secret rotation due soon"
	default:
		status = RotationOK
		message = "secret rotation is current"
	}

	return RotationResult{
		Path:        path,
		LastRotated: lastRotated,
		Age:         age,
		Status:      status,
		Message:     message,
	}
}
