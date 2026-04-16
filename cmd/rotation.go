package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/vaultpulse/internal/audit"
	"github.com/vaultpulse/internal/vault"
)

var (
	rotationMaxAgeDays  int
	rotationWarnDays    int
)

func init() {
	rotationCmd.Flags().IntVar(&rotationMaxAgeDays, "max-age", 90, "maximum secret age in days before rotation is overdue")
	rotationCmd.Flags().IntVar(&rotationWarnDays, "warn-before", 14, "days before max-age to start warning")
	rootCmd.AddCommand(rotationCmd)
}

var rotationCmd = &cobra.Command{
	Use:   "rotation [paths...]",
	Short: "Audit secret rotation schedules",
	Long:  `Check when secrets were last rotated and flag those that are due or overdue for rotation.`,
	RunE:  runRotation,
}

func runRotation(cmd *cobra.Command, args []string) error {
	client, err := vault.NewClient(vaultAddr, vaultToken)
	if err != nil {
		return fmt.Errorf("failed to create vault client: %w", err)
	}

	policy := audit.RotationPolicy{
		MaxAge:     time.Duration(rotationMaxAgeDays) * 24 * time.Hour,
		WarnBefore: time.Duration(rotationWarnDays) * 24 * time.Hour,
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "PATH\tLAST ROTATED\tAGE (DAYS)\tSTATUS\tMESSAGE")
	fmt.Fprintln(w, "----\t------------\t----------\t------\t-------")

	overallOK := true
	for _, path := range args {
		meta, err := client.GetSecretMeta(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not fetch %s: %v\n", path, err)
			continue
		}

		result := audit.EvaluateRotation(path, meta.CreatedTime, policy)
		ageDays := int(result.Age.Hours() / 24)
		lastStr := "unknown"
		if !result.LastRotated.IsZero() {
			lastStr = result.LastRotated.Format("2006-01-02")
		}

		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n",
			result.Path, lastStr, ageDays, result.Status, result.Message)

		if result.Status == audit.RotationOverdue {
			overallOK = false
		}
	}
	w.Flush()

	if !overallOK {
		return fmt.Errorf("one or more secrets are overdue for rotation")
	}
	return nil
}
