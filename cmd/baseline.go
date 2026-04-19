package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"vaultpulse/internal/audit"
	"vaultpulse/internal/vault"
)

var (
	baselineFile   string
	baselineAction string
)

func init() {
	baselineCmd := &cobra.Command{
		Use:   "baseline",
		Short: "Save or compare a baseline of secret TTL statuses",
		RunE:  runBaseline,
	}
	baselineCmd.Flags().StringVar(&baselineFile, "file", "baseline.json", "Path to baseline file")
	baselineCmd.Flags().StringVar(&baselineAction, "action", "compare", "Action: save or compare")
	baselineCmd.Flags().StringVar(&vaultAddr, "addr", "http://127.0.0.1:8200", "Vault address")
	baselineCmd.Flags().StringVar(&vaultToken, "token", "", "Vault token")
	baselineCmd.Flags().StringArrayVar(&secretPaths, "path", nil, "Secret paths to audit")
	rootCmd.AddCommand(baselineCmd)
}

func runBaseline(cmd *cobra.Command, args []string) error {
	client, err := vault.NewClient(vaultAddr, vaultToken)
	if err != nil {
		return fmt.Errorf("vault client: %w", err)
	}

	var reports []audit.SecretReport
	for _, p := range secretPaths {
		meta, err := client.GetSecretMeta(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: skipping %s: %v\n", p, err)
			continue
		}
		r := audit.EvaluateTTL(p, meta.TTL, audit.DefaultThresholds)
		reports = append(reports, r)
	}

	switch baselineAction {
	case "save":
		if err := audit.SaveBaseline(baselineFile, reports); err != nil {
			return fmt.Errorf("save baseline: %w", err)
		}
		fmt.Printf("Baseline saved to %s (%d secrets)\n", baselineFile, len(reports))

	case "compare":
		b, err := audit.LoadBaseline(baselineFile)
		if err != nil {
			return fmt.Errorf("load baseline: %w", err)
		}
		diffs := audit.CompareBaseline(b, reports)
		if len(diffs) == 0 {
			fmt.Println("No changes detected from baseline.")
			return nil
		}
		fmt.Printf("%-30s %-12s %-20s %-20s\n", "PATH", "FIELD", "BEFORE", "AFTER")
		for _, d := range diffs {
			fmt.Printf("%-30s %-12s %-20s %-20s\n", d.Path, d.Field, d.Before, d.After)
		}

	default:
		return fmt.Errorf("unknown action %q: use save or compare", baselineAction)
	}
	return nil
}
