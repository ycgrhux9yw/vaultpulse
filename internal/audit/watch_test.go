package audit

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWatch_AlertsOnNonOK(t *testing.T) {
	alerted := []TTLReport{}
	opts := WatchOptions{
		Interval: 10 * time.Millisecond,
		Threshold: DefaultThresholds,
		OnAlert: func(r TTLReport) {
			alerted = append(alerted, r)
		},
	}

	calls := 0
	fetcher := func(ctx context.Context) ([]TTLReport, error) {
		calls++
		return []TTLReport{
			{Path: "secret/ok", Status: StatusOK, TTL: time.Hour},
			{Path: "secret/warn", Status: StatusWarning, TTL: 10 * time.Minute},
		}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Millisecond)
	defer cancel()

	_ = Watch(ctx, fetcher, opts)

	if calls == 0 {
		t.Fatal("expected fetcher to be called at least once")
	}
	for _, r := range alerted {
		if r.Status == StatusOK {
			t.Errorf("expected no OK alerts, got path %s", r.Path)
		}
	}
}

func TestWatch_FetcherError(t *testing.T) {
	opts := WatchOptions{
		Interval: 10 * time.Millisecond,
		OnAlert:  func(r TTLReport) {},
	}
	fetcher := func(ctx context.Context) ([]TTLReport, error) {
		return nil, errors.New("vault unavailable")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := Watch(ctx, fetcher, opts)
	if err == nil || err.Error() != "fetcher error: vault unavailable" {
		t.Errorf("expected fetcher error, got: %v", err)
	}
}

func TestWatch_InvalidInterval(t *testing.T) {
	opts := WatchOptions{Interval: 0}
	err := Watch(context.Background(), nil, opts)
	if err == nil {
		t.Fatal("expected error for zero interval")
	}
}
