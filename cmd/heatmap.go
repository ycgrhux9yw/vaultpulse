package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vaultpulse/internal/audit"
	"github.com/vaultpulse/internal/vault"
)

var (
	heatmapMount  string
	heatmapOutput string
)

func init() {
	heatmapCmd := &cobra.Command{
		Use:   "heatmap",
		Short: "Display a health heatmap grouped by secret path prefix",
		RunE:  runHeatmap,
	}
	heatmapCmd.Flags().StringVar(&auditAddr, "addr", "", "Vault address (overrides VAULT_ADDR)")
	heatmapCmd.Flags().StringVar(&auditToken, "token", "", "Vault token (overrides VAULT_TOKEN)")
	heatmapCmd.Flags().StringVar(&auditMount, "mount", "secret", "KV mount path")
	heatmapCmd.Flags().StringVar(&heatmapOutput, "output", "table", "Output format: table")
	rootCmd.AddCommand(heatmapCmd)
}

func runHeatmap(cmd *cobra.Command, args []string) error {
	client, err := vault.NewClient(auditAddr, auditToken)
	if err != nil {
		return fmt.Errorf("vault client: %w", err)
	}

	paths, err := client.ListSecrets(auditMount)
	if err != nil {
		return fmt.Errorf("listing secrets: %w", err)
	}

	thresholds := audit.DefaultThresholds()
	var reports []audit.SecretReport
	for _, p := range paths {
		meta, err := client.GetSecretMeta(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: skipping %s: %v\n", p, err)
			continue
		}
		report := audit.EvaluateTTL(p, meta.TTL, thresholds)
		reports = append(reports, report)
	}

	rows := audit.BuildHeatmap(reports)
	fmt.Print(audit.FormatHeatmap(rows))
	return nil
}
