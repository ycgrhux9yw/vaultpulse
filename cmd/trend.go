package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"vaultpulse/internal/audit"
)

var (
	trendSnapshotDir string
	trendOutputFormat string
)

func init() {
	trendCmd := &cobra.Command{
		Use:   "trend",
		Short: "Analyse score trends across saved snapshots",
		RunE:  runTrend,
	}
	trendCmd.Flags().StringVar(&trendSnapshotDir, "snapshot-dir", ".", "Directory containing snapshot JSON files")
	trendCmd.Flags().StringVar(&trendOutputFormat, "output", "table", "Output format: table or json")
	rootCmd.AddCommand(trendCmd)
}

func runTrend(cmd *cobra.Command, args []string) error {
	entries, err := loadSnapshotDir(trendSnapshotDir)
	if err != nil {
		return fmt.Errorf("loading snapshots: %w", err)
	}
	if len(entries) == 0 {
		fmt.Println("No snapshots found in", trendSnapshotDir)
		return nil
	}
	tr := audit.BuildTrend(entries)
	switch strings.ToLower(trendOutputFormat) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(tr)
	default:
		fmt.Print(audit.FormatTrend(tr))
	}
	return nil
}

// loadSnapshotDir reads all *.json files in dir as snapshot files.
func loadSnapshotDir(dir string) ([]audit.SnapshotEntry, error) {
	glob := filepath.Join(dir, "*.json")
	matches, err := filepath.Glob(glob)
	if err != nil {
		return nil, err
	}
	var entries []audit.SnapshotEntry
	for _, path := range matches {
		reports, err := audit.LoadSnapshot(path)
		if err != nil {
			continue // skip malformed files
		}
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		entries = append(entries, audit.SnapshotEntry{
			CapturedAt: info.ModTime().UTC().Truncate(time.Second),
			Reports:    reports,
		})
	}
	return entries, nil
}
