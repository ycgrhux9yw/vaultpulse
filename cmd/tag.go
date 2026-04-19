package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/your-org/vaultpulse/internal/audit"
	"github.com/your-org/vaultpulse/internal/vault"
)

var (
	tagFilterFlags []string
)

func init() {
	tagCmd := &cobra.Command{
		Use:   "tag",
		Short: "Filter and display secrets by path-derived tags",
		RunE:  runTag,
	}
	tagCmd.Flags().StringArrayVar(&tagFilterFlags, "tag", nil, "Tag filter as key=value (repeatable)")
	tagCmd.Flags().StringVar(&vaultAddr, "addr", "http://127.0.0.1:8200", "Vault address")
	tagCmd.Flags().StringVar(&vaultToken, "token", "", "Vault token")
	tagCmd.Flags().StringArrayVar(&secretPaths, "path", nil, "Secret paths to audit")
	rootCmd.AddCommand(tagCmd)
}

func runTag(cmd *cobra.Command, args []string) error {
	client, err := vault.NewClient(vaultAddr, vaultToken)
	if err != nil {
		return fmt.Errorf("vault client: %w", err)
	}

	var tagged []audit.TaggedReport
	for _, p := range secretPaths {
		meta, err := client.GetSecretMeta(p)
		if err != nil {
			fmt.Printf("WARN: skipping %s: %v\n", p, err)
			continue
		}
		report := vault.SecretReport{Path: p, TTL: meta.TTL, CreatedAt: meta.CreatedAt}
		tags := audit.ParseTagsFromPath(p)
		tagged = append(tagged, audit.TaggedReport{Report: report, Tags: tags})
	}

	f := audit.TagFilter{RequiredTags: parseTagFlags(tagFilterFlags)}
	filtered := audit.ApplyTagFilter(tagged, f)

	if len(filtered) == 0 {
		fmt.Println("No secrets matched the given tags.")
		return nil
	}

	var reports []vault.SecretReport
	for _, tr := range filtered {
		reports = append(reports, tr.Report)
	}
	audit.PrintReport(reports, audit.DefaultReportOptions())
	return nil
}

func parseTagFlags(flags []string) map[string]string {
	m := make(map[string]string)
	for _, f := range flags {
		parts := strings.SplitN(f, "=", 2)
		if len(parts) == 2 {
			m[parts[0]] = parts[1]
		}
	}
	return m
}
