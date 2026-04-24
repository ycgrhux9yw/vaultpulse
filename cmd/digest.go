package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"vaultpulse/internal/audit"
	"vaultpulse/internal/vault"
)

var (
	digestPaths     []string
	digestVaultAddr string
	digestToken     string
	digestOnlyBad   bool
)

func init() {
	digestCmd := &cobra.Command{
		Use:   "digest",
		Short: "Print a summary digest of secret health across all monitored paths",
		RunE:  runDigest,
	}
	digestCmd.Flags().StringSliceVar(&digestPaths, "paths", nil, "Vault secret paths to audit (required)")
	digestCmd.Flags().StringVar(&digestVaultAddr, "vault-addr", os.Getenv("VAULT_ADDR"), "Vault server address")
	digestCmd.Flags().StringVar(&digestToken, "vault-token", os.Getenv("VAULT_TOKEN"), "Vault token")
	digestCmd.Flags().BoolVar(&digestOnlyBad, "only-bad", false, "Exit with non-zero status if any non-OK secrets exist")
	_ = digestCmd.MarkFlagRequired("paths")
	rootCmd.AddCommand(digestCmd)
}

func runDigest(cmd *cobra.Command, args []string) error {
	if digestVaultAddr == "" {
		return fmt.Errorf("vault address is required (--vault-addr or VAULT_ADDR)")
	}
	client, err := vault.NewClient(digestVaultAddr, digestToken)
	if err != nil {
		return fmt.Errorf("failed to create vault client: %w", err)
	}
	var reports []audit.SecretReport
	for _, p := range digestPaths {
		p = strings.TrimSpace(p)
		meta, err := client.GetSecretMeta(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: skipping %s: %v\n", p, err)
			continue
		}
		r := audit.EvaluateTTL(p, meta.TTL, audit.DefaultThresholds)
		reports = append(reports, r)
	}
	dr := audit.BuildDigest(reports)
	fmt.Print(audit.FormatDigest(dr))
	if digestOnlyBad && (dr.WarnCount+dr.CritCount+dr.ExpCount) > 0 {
		os.Exit(1)
	}
	return nil
}
