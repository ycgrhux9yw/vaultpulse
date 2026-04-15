package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/yourusername/vaultpulse/internal/vault"
)

var (
	vaultAddr  string
	vaultToken string
	pathPrefix string
	warnTTL    time.Duration
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit secret TTLs under a Vault path prefix",
	RunE:  runAudit,
}

func init() {
	auditCmd.Flags().StringVar(&vaultAddr, "addr", "http://127.0.0.1:8200", "Vault server address")
	auditCmd.Flags().StringVar(&vaultToken, "token", "", "Vault token (or set VAULT_TOKEN)")
	auditCmd.Flags().StringVar(&pathPrefix, "prefix", "secret/metadata/", "Secret path prefix to audit")
	auditCmd.Flags().DurationVar(&warnTTL, "warn-ttl", 24*time.Hour, "Warn if TTL is below this threshold")
	rootCmd.AddCommand(auditCmd)
}

func runAudit(cmd *cobra.Command, args []string) error {
	token := vaultToken
	if token == "" {
		token = os.Getenv("VAULT_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("vault token is required: use --token or set VAULT_TOKEN")
	}

	client, err := vault.NewClient(vaultAddr, token)
	if err != nil {
		return fmt.Errorf("could not connect to vault: %w", err)
	}

	paths, err := client.ListPaths(pathPrefix)
	if err != nil {
		return fmt.Errorf("failed to list paths: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "PATH\tTTL\tRENEWABLE\tEXPIRES AT\tSTATUS")

	for _, p := range paths {
		fullPath := pathPrefix + p
		meta, err := client.GetSecretMeta(fullPath)
		if err != nil {
			fmt.Fprintf(w, "%s\t-\t-\t-\tERROR: %v\n", fullPath, err)
			continue
		}

		status := "OK"
		if meta.LeaseTTL > 0 && meta.LeaseTTL < warnTTL {
			status = "WARN: expiring soon"
		} else if meta.LeaseTTL == 0 {
			status = "NO TTL"
		}

		fmt.Fprintf(w, "%s\t%s\t%v\t%s\t%s\n",
			meta.Path,
			meta.LeaseTTL,
			meta.Renewable,
			meta.ExpiresAt.Format(time.RFC3339),
			status,
		)
	}

	return w.Flush()
}
