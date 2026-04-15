package audit

import (
	"fmt"
	"io"
	"os"
	"text/tabwriter"
)

// statusColor maps TTLStatus to ANSI color codes.
var statusColor = map[TTLStatus]string{
	StatusOK:       "\033[32m", // green
	StatusWarning:  "\033[33m", // yellow
	StatusCritical: "\033[31m", // red
	StatusExpired:  "\033[35m", // magenta
}

const colorReset = "\033[0m"

// ReportOptions controls output behavior.
type ReportOptions struct {
	Writer    io.Writer
	Colorized bool
}

// DefaultReportOptions returns options that write to stdout with color.
func DefaultReportOptions() ReportOptions {
	return ReportOptions{
		Writer:    os.Stdout,
		Colorized: true,
	}
}

// PrintReport writes a formatted TTL audit report to the configured writer.
func PrintReport(reports []SecretTTLReport, opts ReportOptions) {
	w := tabwriter.NewWriter(opts.Writer, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "PATH\tSTATUS\tEXPIRES AT\tMESSAGE")
	fmt.Fprintln(w, "----\t------\t----------\t-------")

	for _, r := range reports {
		status := string(r.Status)
		if opts.Colorized {
			if color, ok := statusColor[r.Status]; ok {
				status = color + status + colorReset
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			r.Path,
			status,
			r.ExpiresAt.Format("2006-01-02 15:04:05"),
			r.Message,
		)
	}
	w.Flush()
}

// SummaryStats returns counts of each TTL status from a set of reports.
func SummaryStats(reports []SecretTTLReport) map[TTLStatus]int {
	counts := map[TTLStatus]int{
		StatusOK:       0,
		StatusWarning:  0,
		StatusCritical: 0,
		StatusExpired:  0,
	}
	for _, r := range reports {
		counts[r.Status]++
	}
	return counts
}
