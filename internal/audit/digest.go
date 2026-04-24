package audit

import (
	"fmt"
	"strings"
	"time"
)

// DigestEntry summarises a single secret's health for a daily/weekly digest.
type DigestEntry struct {
	Path    string
	Status  string
	TTL     time.Duration
	Message string
}

// DigestReport holds a collection of digest entries and metadata.
type DigestReport struct {
	GeneratedAt time.Time
	Entries     []DigestEntry
	OKCount     int
	WarnCount   int
	CritCount   int
	ExpCount    int
}

// BuildDigest creates a DigestReport from a slice of SecretReport.
func BuildDigest(reports []SecretReport) DigestReport {
	dr := DigestReport{GeneratedAt: time.Now()}
	for _, r := range reports {
		entry := DigestEntry{
			Path:    r.Path,
			Status:  r.Status,
			TTL:     r.TTL,
			Message: r.Message,
		}
		dr.Entries = append(dr.Entries, entry)
		switch r.Status {
		case "OK":
			dr.OKCount++
		case "WARNING":
			dr.WarnCount++
		case "CRITICAL":
			dr.CritCount++
		case "EXPIRED":
			dr.ExpCount++
		}
	}
	return dr
}

// FormatDigest returns a human-readable digest summary string.
func FormatDigest(dr DigestReport) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("VaultPulse Digest — %s\n", dr.GeneratedAt.Format(time.RFC1123)))
	sb.WriteString(strings.Repeat("-", 60) + "\n")
	sb.WriteString(fmt.Sprintf("  OK: %d  WARNING: %d  CRITICAL: %d  EXPIRED: %d\n",
		dr.OKCount, dr.WarnCount, dr.CritCount, dr.ExpCount))
	sb.WriteString(strings.Repeat("-", 60) + "\n")
	for _, e := range dr.Entries {
		if e.Status == "OK" {
			continue
		}
		sb.WriteString(fmt.Sprintf("  [%-8s] %-40s %s\n", e.Status, e.Path, e.Message))
	}
	return sb.String()
}
