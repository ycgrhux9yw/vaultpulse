package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"vaultpulse/internal/audit"
	"vaultpulse/internal/vault"
)

var summaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Print an executive summary of secret health across all paths",
	RunE:  runSummary,
}

func init() {
	summaryCmd.Flags().StringSliceVar(&auditPaths, "paths", nil, "Secret paths to evaluate (required)")
	summaryCmd.Flags().StringVar(&vaultAddr, "vault-addr", os.Getenv("VAULT_ADDR"), "Vault server address")
	summaryCmd.Flags().StringVar(&vaultToken, "vault-token", os.Getenv("VAULT_TOKEN"), "Vault token")
	rootCmd.AddCommand(summaryCmd)
}

func runSummary(cmd *cobra.Command, args []string) error {
	if len(auditPaths) == 0 {
		return fmt.Errorf("--paths is required")
	}
	if vaultAddr == "" {
		return fmt.Errorf("--vault-addr or VAULT_ADDR is required")
	}

	client, err := vault.NewClient(vaultAddr, vaultToken)
	if err != nil {
		return fmt.Errorf("vault client: %w", err)
	}

	var reports []audit.SecretReport
	thresholds := audit.DefaultThresholds()

	for _, path := range auditPaths {
		meta, err := client.GetSecretMeta(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: skipping %s: %v\n", path, err)
			continue
		}
		reports = append(reports, audit.EvaluateTTL(path, meta, thresholds))
	}

	if len(reports) == 0 {
		return fmt.Errorf("no secrets evaluated")
	}

	s := audit.BuildSummary(reports)
	fmt.Print(audit.FormatSummary(s))
	return nil
}
