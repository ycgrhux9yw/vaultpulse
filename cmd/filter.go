package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"vaultpulse/internal/audit"
)

var (
	filterStatus     string
	filterPathPrefix string
	filterMinTTL     time.Duration
	filterMaxTTL     time.Duration
)

var filterCmd = &cobra.Command{
	Use:   "filter",
	Short: "Filter audit report results by status, path, or TTL range",
	RunE:  runFilter,
}

func init() {
	rootCmd.AddCommand(filterCmd)
	filterCmd.Flags().StringVar(&filterStatus, "status", "", "Filter by status: ok, warning, critical, expired")
	filterCmd.Flags().StringVar(&filterPathPrefix, "prefix", "", "Filter by secret path prefix")
	filterCmd.Flags().DurationVar(&filterMinTTL, "min-ttl", 0, "Minimum TTL (e.g. 24h)")
	filterCmd.Flags().DurationVar(&filterMaxTTL, "max-ttl", 0, "Maximum TTL (e.g. 72h)")
}

func runFilter(cmd *cobra.Command, args []string) error {
	reports, err := loadReports()
	if err != nil {
		return fmt.Errorf("loading reports: %w", err)
	}

	opts := audit.FilterOptions{
		Status:     filterStatus,
		PathPrefix: filterPathPrefix,
		MinTTL:     filterMinTTL,
		MaxTTL:     filterMaxTTL,
	}

	filtered := audit.FilterReports(reports, opts)
	if len(filtered) == 0 {
		fmt.Println("No reports matched the given filters.")
		return nil
	}

	audit.PrintReport(filtered, audit.DefaultReportOptions())
	stats := audit.SummaryStats(filtered)
	fmt.Fprintf(os.Stdout, "\nFiltered: %d total, %d ok, %d warning, %d critical, %d expired\n",
		stats.Total, stats.OK, stats.Warning, stats.Critical, stats.Expired)
	return nil
}
