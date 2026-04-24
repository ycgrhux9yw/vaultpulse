package audit

import (
	"strings"
	"testing"
	"time"
)

func digestSample() []SecretReport {
	return []SecretReport{
		{Path: "secret/db/prod", Status: "OK", TTL: 48 * time.Hour, Message: ""},
		{Path: "secret/api/key", Status: "WARNING", TTL: 6 * time.Hour, Message: "expires soon"},
		{Path: "secret/tls/cert", Status: "CRITICAL", TTL: 1 * time.Hour, Message: "urgent rotation"},
		{Path: "secret/old/token", Status: "EXPIRED", TTL: 0, Message: "already expired"},
		{Path: "secret/svc/pass", Status: "OK", TTL: 72 * time.Hour, Message: ""},
	}
}

func TestBuildDigest_Counts(t *testing.T) {
	dr := BuildDigest(digestSample())
	if dr.OKCount != 2 {
		t.Errorf("expected 2 OK, got %d", dr.OKCount)
	}
	if dr.WarnCount != 1 {
		t.Errorf("expected 1 WARNING, got %d", dr.WarnCount)
	}
	if dr.CritCount != 1 {
		t.Errorf("expected 1 CRITICAL, got %d", dr.CritCount)
	}
	if dr.ExpCount != 1 {
		t.Errorf("expected 1 EXPIRED, got %d", dr.ExpCount)
	}
}

func TestBuildDigest_EntryCount(t *testing.T) {
	dr := BuildDigest(digestSample())
	if len(dr.Entries) != 5 {
		t.Errorf("expected 5 entries, got %d", len(dr.Entries))
	}
}

func TestBuildDigest_Empty(t *testing.T) {
	dr := BuildDigest([]SecretReport{})
	if dr.OKCount != 0 || dr.WarnCount != 0 {
		t.Error("expected all zero counts for empty input")
	}
}

func TestFormatDigest_ContainsHeader(t *testing.T) {
	dr := BuildDigest(digestSample())
	out := FormatDigest(dr)
	if !strings.Contains(out, "VaultPulse Digest") {
		t.Error("expected header in digest output")
	}
}

func TestFormatDigest_SkipsOK(t *testing.T) {
	dr := BuildDigest(digestSample())
	out := FormatDigest(dr)
	if strings.Contains(out, "secret/db/prod") {
		t.Error("OK entries should not appear in digest body")
	}
}

func TestFormatDigest_ContainsNonOK(t *testing.T) {
	dr := BuildDigest(digestSample())
	out := FormatDigest(dr)
	if !strings.Contains(out, "secret/api/key") {
		t.Error("WARNING entry should appear in digest body")
	}
	if !strings.Contains(out, "secret/old/token") {
		t.Error("EXPIRED entry should appear in digest body")
	}
}
