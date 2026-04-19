package cmd

import (
	"testing"
)

func TestParseTagFlags_Valid(t *testing.T) {
	flags := []string{"team=teamA", "env=prod"}
	m := parseTagFlags(flags)
	if m["team"] != "teamA" {
		t.Errorf("expected teamA, got %s", m["team"])
	}
	if m["env"] != "prod" {
		t.Errorf("expected prod, got %s", m["env"])
	}
}

func TestParseTagFlags_Empty(t *testing.T) {
	m := parseTagFlags(nil)
	if len(m) != 0 {
		t.Errorf("expected empty map")
	}
}

func TestParseTagFlags_MalformedSkipped(t *testing.T) {
	flags := []string{"noequalssign", "valid=yes"}
	m := parseTagFlags(flags)
	if len(m) != 1 {
		t.Errorf("expected 1 entry, got %d", len(m))
	}
	if m["valid"] != "yes" {
		t.Errorf("expected yes, got %s", m["valid"])
	}
}
