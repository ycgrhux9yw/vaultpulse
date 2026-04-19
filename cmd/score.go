package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"vaultpulse/internal/audit"
	"vaultpulse/internal/vault"
)

var scorePaths []string

var scoreCmd = &cobra.Command{
	Use:   "score",
	Short: "Compute a risk score across audited secrets",
	RunE:  runScore,
}

func init() {
	scoreCmd.Flags().StringSliceVar(&scorePaths, "paths", []string{}, "Secret paths to evaluate")
	scoreCmd.Flags().String("addr", "http://127.0.0.1:8200", "Vault address")
	scoreCmd.Flags().String("token", "", "Vault token")
	rootCmd.AddCommand(scoreCmd)
}

func runScore(cmd *cobra.Command, args []string) error {
	addr, _ := cmd.Flags().GetString("addr")
	token, _ := cmd.Flags().GetString("token")

	if len(scorePaths) == 0 {
		return fmt.Errorf("--paths must specify at least one secret path")
	}

	client, err := vault.NewClient(addr, token)
	if err != nil {
		return fmt.Errorf("vault client error: %w", err)
	}

	var reports []audit.SecretReport
	for _, p := range scorePaths {
		meta, err := client.GetSecretMeta(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: skipping %s: %v\n", p, err)
			continue
		}
		ttl := time.Until(meta.Expiration)
		r := audit.EvaluateTTL(p, ttl, audit.DefaultThresholds)
		reports = append(reports, r)
	}

	result := audit.ComputeScore(reports, audit.DefaultScoreWeights)
	fmt.Println(audit.FormatScore(result))
	return nil
}
