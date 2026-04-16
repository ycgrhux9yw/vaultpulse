package audit

import (
	"context"
	"fmt"
	"time"
)

// WatchOptions configures the watch polling behavior.
type WatchOptions struct {
	Interval  time.Duration
	Threshold TTLThresholds
	OnAlert   func(report TTLReport)
}

// DefaultWatchOptions returns sensible defaults for watching.
var DefaultWatchOptions = WatchOptions{
	Interval:  30 * time.Second,
	Threshold: DefaultThresholds,
	OnAlert: func(r TTLReport) {
		fmt.Printf("[ALERT] %s — status: %s, TTL: %s\n", r.Path, r.Status, r.TTL)
	},
}

// SecretFetcher is a function that returns TTLReports for all monitored paths.
type SecretFetcher func(ctx context.Context) ([]TTLReport, error)

// Watch polls secrets at a given interval and fires OnAlert for non-OK statuses.
func Watch(ctx context.Context, fetcher SecretFetcher, opts WatchOptions) error {
	if opts.Interval <= 0 {
		return fmt.Errorf("watch interval must be positive")
	}
	ticker := time.NewTicker(opts.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			reports, err := fetcher(ctx)
			if err != nil {
				return fmt.Errorf("fetcher error: %w", err)
			}
			for _, r := range reports {
				if r.Status != StatusOK {
					opts.OnAlert(r)
				}
			}
		}
	}
}
