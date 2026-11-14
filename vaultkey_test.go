package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVaultRefusesWrongOrMissingKey(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(filepath.Join(dir, "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVault(s, dir, "file")
	if err != nil {
		t.Fatal(err)
	}
	_ = v.Set("X", "secret", false, "")
	good, _ := os.ReadFile(filepath.Join(dir, "master.key"))

	// Reopen with the right key works.
	if _, err := NewVault(s, dir, "file"); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	// Missing key must not create a new one.
	_ = os.Remove(filepath.Join(dir, "master.key"))
	if _, err := NewVault(s, dir, "file"); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("missing key should fail, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "master.key")); err == nil {
		t.Fatal("a new key file must not be written")
	}
	// Wrong key is detected.
	_ = os.WriteFile(filepath.Join(dir, "master.key"), []byte(strings.Repeat("ab", 32)), 0o600)
	if _, err := NewVault(s, dir, "file"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong key should fail, got %v", err)
	}
	_ = os.WriteFile(filepath.Join(dir, "master.key"), good, 0o600)
	v2, err := NewVault(s, dir, "file")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := v2.Get("X"); got != "secret" {
		t.Fatalf("got %q", got)
	}
}
