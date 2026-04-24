package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vaultpulse/internal/audit"
	"github.com/vaultpulse/internal/vault"
)

var (
	forecastHorizon int
	forecastPaths   []string
)

var forecastCmd = &cobra.Command{
	Use:   "forecast",
	Short: "Project future TTL status of secrets over a given horizon",
	RunE:  runForecast,
}

func init() {
	forecastCmd.Flags().IntVar(&forecastHorizon, "horizon", 7, "Number of days to project forward")
	forecastCmd.Flags().StringSliceVar(&forecastPaths, "paths", []string{}, "Secret paths to evaluate (comma-separated)")
	forecastCmd.Flags().StringVar(&vaultAddr, "vault-addr", "", "Vault server address")
	forecastCmd.Flags().StringVar(&vaultToken, "vault-token", "", "Vault token")
	rootCmd.AddCommand(forecastCmd)
}

func runForecast(cmd *cobra.Command, args []string) error {
	if len(forecastPaths) == 0 {
		return fmt.Errorf("--paths is required")
	}
	if forecastHorizon <= 0 {
		return fmt.Errorf("--horizon must be a positive integer")
	}

	client, err := vault.NewClient(vaultAddr, vaultToken)
	if err != nil {
		return fmt.Errorf("vault client error: %w", err)
	}

	var reports []audit.SecretReport
	for _, p := range forecastPaths {
		meta, err := client.GetSecretMeta(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: skipping %s: %v\n", p, err)
			continue
		}
		r := audit.EvaluateTTL(p, meta.TTL, audit.DefaultThresholds)
		reports = append(reports, r)
	}

	entries := audit.BuildForecast(reports, forecastHorizon, audit.DefaultThresholds)
	fmt.Print(audit.FormatForecast(entries, forecastHorizon))
	return nil
}
