package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Snapshot represents a point-in-time capture of audit reports.
type Snapshot struct {
	CapturedAt time.Time      `json:"captured_at"`
	Reports    []SecretReport `json:"reports"`
}

// SecretReport is a unified report structure used for snapshots.
type SecretReport struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	TTL    int64  `json:"ttl_seconds"`
	Note   string `json:"note,omitempty"`
}

// SaveSnapshot writes a snapshot of the provided reports to a JSON file.
func SaveSnapshot(path string, reports []SecretReport) error {
	snap := Snapshot{
		CapturedAt: time.Now().UTC(),
		Reports:    reports,
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("snapshot marshal error: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("snapshot write error: %w", err)
	}
	return nil
}

// LoadSnapshot reads and parses a snapshot file from disk.
func LoadSnapshot(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("snapshot read error: %w", err)
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("snapshot parse error: %w", err)
	}
	return &snap, nil
}

// DiffSnapshots compares two snapshots and returns paths whose status changed.
func DiffSnapshots(old, new *Snapshot) []string {
	oldMap := make(map[string]string, len(old.Reports))
	for _, r := range old.Reports {
		oldMap[r.Path] = r.Status
	}
	var changed []string
	for _, r := range new.Reports {
		if prev, ok := oldMap[r.Path]; ok && prev != r.Status {
			changed = append(changed, r.Path)
		}
	}
	return changed
}
