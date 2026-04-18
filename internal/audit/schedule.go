package audit

import (
	"fmt"
	"time"
)

// ScheduleEntry represents a planned rotation schedule for a secret path.
type ScheduleEntry struct {
	Path           string
	RotationPeriod time.Duration
	LastRotated    time.Time
	NextRotation   time.Time
}

// ScheduleStatus indicates whether a rotation is upcoming, due, or overdue.
type ScheduleStatus string

const (
	ScheduleOK      ScheduleStatus = "OK"
	ScheduleDueSoon ScheduleStatus = "DUE_SOON"
	ScheduleOverdue ScheduleStatus = "OVERDUE"
)

// ScheduleReport is the result of evaluating a ScheduleEntry.
type ScheduleReport struct {
	Entry     ScheduleEntry
	Status    ScheduleStatus
	Message   string
	Remaining time.Duration
}

// EvaluateSchedule checks a ScheduleEntry against the current time.
// warnWithin defines how close to NextRotation triggers a DUE_SOON status.
func EvaluateSchedule(entry ScheduleEntry, warnWithin time.Duration) ScheduleReport {
	now := time.Now()
	remaining := entry.NextRotation.Sub(now)

	var status ScheduleStatus
	var msg string

	switch {
	case remaining < 0:
		status = ScheduleOverdue
		msg = fmt.Sprintf("rotation overdue by %s", (-remaining).Round(time.Second))
	case remaining <= warnWithin:
		status = ScheduleDueSoon
		msg = fmt.Sprintf("rotation due in %s", remaining.Round(time.Second))
	default:
		status = ScheduleOK
		msg = fmt.Sprintf("next rotation in %s", remaining.Round(time.Second))
	}

	return ScheduleReport{
		Entry:     entry,
		Status:    status,
		Message:   msg,
		Remaining: remaining,
	}
}

// BuildSchedule constructs ScheduleEntry values from a map of path -> rotation period.
func BuildSchedule(policies map[string]time.Duration, lastRotated map[string]time.Time) []ScheduleEntry {
	entries := make([]ScheduleEntry, 0, len(policies))
	for path, period := range policies {
		lr := lastRotated[path]
		entries = append(entries, ScheduleEntry{
			Path:           path,
			RotationPeriod: period,
			LastRotated:    lr,
			NextRotation:   lr.Add(period),
		})
	}
	return entries
}
