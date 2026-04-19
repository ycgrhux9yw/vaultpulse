package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"vaultpulse/internal/audit"
)

var (
	policyFile     string
	policySnapshot string
)

func init() {
	policyCmd := &cobra.Command{
		Use:   "policy",
		Short: "Evaluate secrets against a policy file",
		RunE:  runPolicy,
	}
	policyCmd.Flags().StringVar(&policyFile, "policy", "policy.json", "Path to policy JSON file")
	policyCmd.Flags().StringVar(&policySnapshot, "snapshot", "", "Path to snapshot file to evaluate")
	rootCmd.AddCommand(policyCmd)
}

func runPolicy(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(policyFile)
	if err != nil {
		return fmt.Errorf("reading policy file: %w", err)
	}
	var policy audit.Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return fmt.Errorf("parsing policy file: %w", err)
	}

	var reports []audit.SecretReport
	if policySnapshot != "" {
		reports, err = audit.LoadSnapshot(policySnapshot)
		if err != nil {
			return fmt.Errorf("loading snapshot: %w", err)
		}
	} else {
		// Fallback: single demo entry when no snapshot provided
		reports = []audit.SecretReport{
			{Path: "secret/example", TTL: 48 * time.Hour, Status: audit.StatusOK},
		}
	}

	violations := audit.EvaluatePolicy(reports, policy)
	if len(violations) == 0 {
		fmt.Println("✓ No policy violations found.")
		return nil
	}

	fmt.Printf("Policy violations (%d):\n", len(violations))
	for _, v := range violations {
		fmt.Printf("  [VIOLATION] %s — %s\n", v.Path, v.Message)
	}
	return nil
}
