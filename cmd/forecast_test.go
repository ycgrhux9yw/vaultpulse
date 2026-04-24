package cmd

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
)

func TestRunForecast_MissingPaths(t *testing.T) {
	cmd := &cobra.Command{}
	err := runForecast(cmd, []string{})
	if err == nil {
		t.Fatal("expected error for missing --paths")
	}
	if err.Error() != "--paths is required" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunForecast_InvalidHorizon(t *testing.T) {
	forecastPaths = []string{"secret/test"}
	forecastHorizon = 0
	defer func() {
		forecastPaths = []string{}
		forecastHorizon = 7
	}()

	cmd := &cobra.Command{}
	err := runForecast(cmd, []string{})
	if err == nil {
		t.Fatal("expected error for invalid horizon")
	}
	if err.Error() != "--horizon must be a positive integer" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunForecast_InvalidVaultAddr(t *testing.T) {
	forecastPaths = []string{"secret/test"}
	forecastHorizon = 7
	vaultAddr = "http://127.0.0.1:19999"
	vaultToken = "bad-token"
	defer func() {
		forecastPaths = []string{}
		forecastHorizon = 7
		vaultAddr = ""
		vaultToken = ""
	}()

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetErr(&buf)
	// Should fail at vault client or fetch stage — not panic
	_ = runForecast(cmd, []string{})
}
