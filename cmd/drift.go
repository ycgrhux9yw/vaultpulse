package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"vaultpulse/internal/audit"
)

var (
	driftBaselineFile string
	driftWarnHours    int
	driftCritHours    int
)

func init() {
	driftCmd := &cobra.Command{
		Use:   "drift",
		Short: "Detect TTL drift compared to a saved baseline",
		RunE:  runDrift,
	}

	driftCmd.Flags().StringVar(&driftBaselineFile, "baseline", "baseline.json", "Path to baseline JSON file")
	driftCmd.Flags().IntVar(&driftWarnHours, "warn-delta", 24, "Hours of TTL delta to trigger a warning")
	driftCmd.Flags().IntVar(&driftCritHours, "crit-delta", 72, "Hours of TTL delta to trigger a critical alert")

	rootCmd.AddCommand(driftCmd)
}

func runDrift(cmd *cobra.Command, args []string) error {
	baseline, err := audit.LoadBaseline(driftBaselineFile)
	if err != nil {
		return fmt.Errorf("loading baseline: %w", err)
	}

	client, err := newVaultClient()
	if err != nil {
		return fmt.Errorf("vault client: %w", err)
	}

	paths, err := resolvePaths(client)
	if err != nil {
		return fmt.Errorf("resolving paths: %w", err)
	}

	reports, err := fetchReports(client, paths)
	if err != nil {
		return fmt.Errorf("fetching reports: %w", err)
	}

	// Convert baseline slice to map keyed by path.
	baselineMap := make(map[string]audit.SecretReport, len(baseline))
	for _, r := range baseline {
		baselineMap[r.Path] = r
	}

	cfg := audit.DriftConfig{
		WarnDelta:     hoursToDuration(driftWarnHours),
		CriticalDelta: hoursToDuration(driftCritHours),
	}

	entries := audit.DetectDrift(reports, baselineMap, cfg)
	fmt.Fprint(os.Stdout, audit.FormatDrift(entries))

	if len(entries) > 0 {
		os.Exit(1)
	}
	return nil
}
