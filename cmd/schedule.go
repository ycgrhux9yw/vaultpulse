package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"vaultpulse/internal/audit"
)

var (
	scheduleWarnHours int
	schedulePaths     []string
)

func init() {
	scheduleCmd := &cobra.Command{
		Use:   "schedule",
		Short: "Evaluate rotation schedules for secrets",
		RunE:  runSchedule,
	}
	scheduleCmd.Flags().IntVar(&scheduleWarnHours, "warn-hours", 48, "Hours before next rotation to trigger DUE_SOON")
	scheduleCmd.Flags().StringSliceVar(&schedulePaths, "paths", nil, "Secret paths to evaluate (required)")
	_ = scheduleCmd.MarkFlagRequired("paths")
	rootCmd.AddCommand(scheduleCmd)
}

func runSchedule(cmd *cobra.Command, args []string) error {
	warnWithin := time.Duration(scheduleWarnHours) * time.Hour

	// Demo: build a simple schedule from CLI paths with a default 30-day period.
	// In production these would be fetched from Vault metadata.
	policies := make(map[string]time.Duration, len(schedulePaths))
	lastRotated := make(map[string]time.Time, len(schedulePaths))
	for _, p := range schedulePaths {
		policies[p] = 30 * 24 * time.Hour
		lastRotated[p] = time.Now().Add(-29 * 24 * time.Hour) // simulate near-due
	}

	entries := audit.BuildSchedule(policies, lastRotated)

	fmt.Fprintf(os.Stdout, "%-40s %-10s %s\n", "PATH", "STATUS", "MESSAGE")
	fmt.Fprintf(os.Stdout, "%-40s %-10s %s\n", "----", "------", "-------")

	hasIssues := false
	for _, entry := range entries {
		report := audit.EvaluateSchedule(entry, warnWithin)
		fmt.Fprintf(os.Stdout, "%-40s %-10s %s\n", report.Entry.Path, report.Status, report.Message)
		if report.Status != audit.ScheduleOK {
			hasIssues = true
		}
	}

	if hasIssues {
		return fmt.Errorf("one or more secrets have rotation issues")
	}
	return nil
}
