package cmd

import (
	"fmt"
	"log"
	"time"

	"github.com/spf13/cobra"

	"github.com/yourorg/vaultpulse/internal/audit"
	"github.com/yourorg/vaultpulse/internal/vault"
)

var (
	exportFormat string
	exportOutput string
)

func init() {
	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export audit results to JSON or CSV",
		RunE:  runExport,
	}
	exportCmd.Flags().StringVarP(&exportFormat, "format", "f", "json", "Output format: json or csv")
	exportCmd.Flags().StringVarP(&exportOutput, "output", "o", "", "Output file path (default: stdout)")
	exportCmd.Flags().StringVar(&vaultAddr, "vault-addr", "", "Vault server address")
	exportCmd.Flags().StringVar(&vaultToken, "vault-token", "", "Vault token")
	exportCmd.Flags().StringSliceVar(&secretPaths, "paths", nil, "Secret paths to audit")
	RootCmd.AddCommand(exportCmd)
}

func runExport(cmd *cobra.Command, args []string) error {
	client, err := vault.NewClient(vaultAddr, vaultToken)
	if err != nil {
		return fmt.Errorf("vault client: %w", err)
	}

	thresholds := audit.DefaultThresholds()
	var reports []audit.Report

	for _, path := range secretPaths {
		meta, err := client.GetSecretMeta(path)
		if err != nil {
			log.Printf("warn: skipping %s: %v", path, err)
			continue
		}
		ttl := time.Until(meta.ExpiresAt)
		report := audit.EvaluateTTL(path, ttl, thresholds)
		reports = append(reports, report)
	}

	return audit.ExportReport(reports, audit.ExportOptions{
		Format:   audit.ExportFormat(exportFormat),
		FilePath: exportOutput,
	})
}
