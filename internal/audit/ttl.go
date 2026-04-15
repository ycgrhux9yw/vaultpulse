package audit

import (
	"fmt"
	"time"
)

// TTLStatus represents the urgency level of a secret's TTL.
type TTLStatus string

const (
	StatusOK       TTLStatus = "OK"
	StatusWarning  TTLStatus = "WARNING"
	StatusCritical TTLStatus = "CRITICAL"
	StatusExpired  TTLStatus = "EXPIRED"
)

// SecretTTLReport holds the evaluated TTL information for a single secret.
type SecretTTLReport struct {
	Path        string
	TTL         time.Duration
	ExpiresAt   time.Time
	Status      TTLStatus     string
}

// TTLThresholds defines warning and critical thresholds for TTL evaluation.
type TTLThresholds struct {
	Warning  time.Duration
	Critical time.Duration
}

// DefaultThresholds returns sensible default TTL thresholds.
func DefaultThresholds() TTLThresholds {
	return TTLThresholds{
		Warning:  72 * time.Hour,
		Critical: 24 * time.Hour,
	}
}

// EvaluateTTL checks a secret's TTL against the given thresholds and returns a report.
func EvaluateTTL(path string, ttl time.Duration, thresholds TTLThresholds) SecretTTLReport {
	now := time.Now()
	expiresAt := now.Add(ttl)

	report := SecretTTLReport{
		Path:      path,
		TTL:       ttl,
		ExpiresAt: expiresAt,
	}

	switch {
	case ttl <= 0:
		report.Status = StatusExpired
		report.Message = "secret has expired or has no TTL"
	case ttl <= thresholds.Critical:
		report.Status = StatusCritical
		report.Message = fmt.Sprintf("expires in %s (critical threshold: %s)", ttl.Round(time.Second), thresholds.Critical)
	case ttl <= thresholds.Warning:
		report.Status = StatusWarning
		report.Message = fmt.Sprintf("expires in %s (warning threshold: %s)", ttl.Round(time.Second), thresholds.Warning)
	default:
		report.Status = StatusOK
		report.Message = fmt.Sprintf("expires in %s", ttl.Round(time.Second))
	}

	return report
}
