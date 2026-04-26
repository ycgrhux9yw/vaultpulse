package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"vaultpulse/internal/audit"
	"vaultpulse/internal/vault"
)

var (
	groupByKey   string
	groupByPaths []string
)

func init() {
	groupByCmd := &cobra.Command{
		Use:   "groupby",
		Short: "Group secret audit results by prefix, status, or team tag",
		RunE:  runGroupBy,
	}
	groupByCmd.Flags().StringVar(&groupByKey, "by", "prefix",
		"Grouping key: prefix | status | team")
	groupByCmd.Flags().StringSliceVar(&groupByPaths, "paths", nil,
		"Secret paths to audit (required)")
	groupByCmd.Flags().StringVar(&vaultAddr, "vault-addr", "",
		"Vault server address (overrides VAULT_ADDR)")
	groupByCmd.Flags().StringVar(&vaultToken, "vault-token", "",
		"Vault token (overrides VAULT_TOKEN)")
	rootCmd.AddCommand(groupByCmd)
}

func runGroupBy(cmd *cobra.Command, args []string) error {
	if len(groupByPaths) == 0 {
		return fmt.Errorf("--paths is required")
	}

	client, err := vault.NewClient(resolveVaultAddr(), resolveVaultToken())
	if err != nil {
		return fmt.Errorf("vault client: %w", err)
	}

	var reports []audit.SecretReport
	for _, p := range groupByPaths {
		meta, err := client.GetSecretMeta(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: skipping %s: %v\n", p, err)
			continue
		}
		r := audit.EvaluateTTL(p, meta.TTLSeconds, audit.DefaultThresholds)
		reports = append(reports, r)
	}

	groups, err := audit.GroupReports(reports, audit.GroupKey(groupByKey))
	if err != nil {
		return err
	}

	fmt.Print(audit.FormatGrouped(groups))
	return nil
}
