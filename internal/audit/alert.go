package audit

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// AlertChannel defines how alerts are dispatched.
type AlertChannel string

const (
	AlertChannelStdout AlertChannel = "stdout"
	AlertChannelFile   AlertChannel = "file"
)

// AlertConfig holds configuration for alert dispatch.
type AlertConfig struct {
	Channel    AlertChannel
	FilePath   string // used when Channel == AlertChannelFile
	MinStatus  string // "warning", "critical", or "expired"
	Writer     io.Writer // override for testing
}

// DefaultAlertConfig returns a sensible default AlertConfig.
func DefaultAlertConfig() AlertConfig {
	return AlertConfig{
		Channel:   AlertChannelStdout,
		MinStatus: "warning",
		Writer:    os.Stdout,
	}
}

var alertSeverity = map[string]int{
	"ok":       0,
	"warning":  1,
	"critical": 2,
	"expired":  3,
	"unknown":  1,
}

// DispatchAlerts sends alerts for reports that meet or exceed the minimum status.
func DispatchAlerts(reports []SecretReport, cfg AlertConfig) error {
	w := cfg.Writer
	if cfg.Channel == AlertChannelFile {
		f, err := os.OpenFile(cfg.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("alert: open file: %w", err)
		}
		defer f.Close()
		w = f
	}

	minSev := alertSeverity[strings.ToLower(cfg.MinStatus)]
	count := 0
	for _, r := range reports {
		sev, ok := alertSeverity[strings.ToLower(r.Status)]
		if !ok {
			sev = 1
		}
		if sev >= minSev {
			fmt.Fprintf(w, "[ALERT] path=%s status=%s ttl=%s\n", r.Path, r.Status, r.TTL)
			count++
		}
	}
	if count == 0 {
		fmt.Fprintln(w, "[ALERT] No alerts to dispatch.")
	}
	return nil
}
