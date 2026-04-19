package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Baseline represents a saved reference state of secret reports.
type Baseline struct {
	CreatedAt time.Time      `json:"created_at"`
	Reports   []SecretReport `json:"reports"`
}

// BaselineDiff describes a change between baseline and current state.
type BaselineDiff struct {
	Path   string `json:"path"`
	Field  string `json:"field"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// SaveBaseline writes the current reports as a baseline to a file.
func SaveBaseline(path string, reports []SecretReport) error {
	b := Baseline{
		CreatedAt: time.Now().UTC(),
		Reports:   reports,
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// LoadBaseline reads a baseline from a file.
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("unmarshal baseline: %w", err)
	}
	return &b, nil
}

// CompareBaseline compares current reports against a baseline and returns diffs.
func CompareBaseline(baseline *Baseline, current []SecretReport) []BaselineDiff {
	index := make(map[string]SecretReport, len(baseline.Reports))
	for _, r := range baseline.Reports {
		index[r.Path] = r
	}

	var diffs []BaselineDiff
	for _, cur := range current {
		base, ok := index[cur.Path]
		if !ok {
			diffs = append(diffs, BaselineDiff{
				Path:   cur.Path,
				Field:  "existence",
				Before: "absent",
				After:  "present",
			})
			continue
		}
		if base.Status != cur.Status {
			diffs = append(diffs, BaselineDiff{
				Path:   cur.Path,
				Field:  "status",
				Before: base.Status,
				After:  cur.Status,
			})
		}
		if base.TTL != cur.TTL {
			diffs = append(diffs, BaselineDiff{
				Path:   cur.Path,
				Field:  "ttl",
				Before: fmt.Sprintf("%d", base.TTL),
				After:  fmt.Sprintf("%d", cur.TTL),
			})
		}
	}
	return diffs
}
