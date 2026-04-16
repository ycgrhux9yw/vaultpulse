package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ExportFormat defines supported output formats.
type ExportFormat string

const (
	FormatJSON ExportFormat = "json"
	FormatCSV  ExportFormat = "csv"
)

// ExportOptions configures the export behaviour.
type ExportOptions struct {
	Format   ExportFormat
	FilePath string // empty means stdout
}

// ExportReport writes audit reports in the requested format.
func ExportReport(reports []Report, opts ExportOptions) error {
	var data []byte
	var err error

	switch opts.Format {
	case FormatJSON:
		data, err = exportJSON(reports)
	case FormatCSV:
		data, err = exportCSV(reports)
	default:
		return fmt.Errorf("unsupported export format: %s", opts.Format)
	}
	if err != nil {
		return err
	}

	if opts.FilePath == "" {
		_, err = os.Stdout.Write(data)
		return err
	}

	return os.WriteFile(opts.FilePath, data, 0o644)
}

type jsonReport struct {
	GeneratedAt string   `json:"generated_at"`
	Reports     []Report `json:"reports"`
}

func exportJSON(reports []Report) ([]byte, error) {
	payload := jsonReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Reports:     reports,
	}
	return json.MarshalIndent(payload, "", "  ")
}

func exportCSV(reports []Report) ([]byte, error) {
	var sb strings.Builder
	sb.WriteString("path,status,ttl_remaining,message\n")
	for _, r := range reports {
		sb.WriteString(fmt.Sprintf("%s,%s,%s,%s\n",
			csvEscape(r.Path),
			csvEscape(string(r.Status)),
			csvEscape(r.TTLRemaining.String()),
			csvEscape(r.Message),
		))
	}
	return []byte(sb.String()), nil
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		s = strings.ReplaceAll(s, "\"", "\"\"")
		return "\"" + s + "\""
	}
	return s
}
