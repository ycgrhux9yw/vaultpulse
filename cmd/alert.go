package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"vaultpulse/internal/audit"
	"vaultpulse/internal/vault"
)

var (
	alertMinStatus string
	alertChannel   string
	alertFilePath  string
)

func init() {
	alertCmd := &cobra.Command{
		Use:   "alert",
		Short: "Dispatch alerts for secrets meeting a minimum status threshold",
		RunE:  runAlert,
	}
	alertCmd.Flags().StringVar(&alertMinStatus, "min-status", "warning", "Minimum status to alert on (warning|critical|expired)")
	alertCmd.Flags().StringVar(&alertChannel, "channel", "stdout", "Alert channel: stdout or file")
	alertCmd.Flags().StringVar(&alertFilePath, "file", "alerts.log", "File path when channel is 'file'")
	alertCmd.Flags().StringVar(&vaultAddr, "addr", "", "Vault address")
	alertCmd.Flags().StringVar(&vaultToken, "token", "", "Vault token")
	alertCmd.Flags().StringSliceVar(&secretPaths, "paths", nil, "Secret paths to audit")
	rootCmd.AddCommand(alertCmd)
}

func runAlert(cmd *cobra.Command, args []string) error {
	c, err := vault.NewClient(vaultAddr, vaultToken)
	if err != nil {
		return fmt.Errorf("vault client: %w", err)
	}

	var reports []audit.SecretReport
	for _, p := range secretPaths {
		meta, err := c.GetSecretMeta(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: skipping %s: %v\n", p, err)
			continue
		}
		r := audit.EvaluateTTL(p, meta.TTL, audit.DefaultThresholds())
		reports = append(reports, r)
	}

	cfg := audit.AlertConfig{
		Channel:   audit.AlertChannel(alertChannel),
		FilePath:  alertFilePath,
		MinStatus: alertMinStatus,
		Writer:    os.Stdout,
	}
	return audit.DispatchAlerts(reports, cfg)
}
