package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// setPasswordCmd reads the admin password from stdin (first line) so that
// install scripts can pipe it in without it appearing in argv.
func setPasswordCmd(args []string) {
	c, f := parseCommon("set-password", args)
	_ = f.Parse(args)
	if err := os.MkdirAll(c.dataDir, 0o700); err != nil {
		fatal(err)
	}
	if fi, _ := os.Stdin.Stat(); fi != nil && fi.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprint(os.Stderr, "New panel password (at least 8 characters, shown on screen): ")
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		fatal(err)
	}
	pw := strings.TrimRight(line, "\r\n")
	if err := SetPassword(c.dataDir, pw); err != nil {
		fatal(err)
	}
	fmt.Fprintln(os.Stderr, "panel password saved")
}

// migrateExport writes a consistent copy of the database plus the master key
// into -out so another (isolated) installation can take over the data.
func migrateExport(args []string) {
	c, f := parseCommon("migrate-export", args)
	out := f.String("out", "", "output directory (created with 0700)")
	reset := f.Bool("reset-secrets", false, "export WITHOUT vault values (when the master key is lost): servers, agents, catalog and history are kept; secrets and OAuth sessions must be re-entered")
	_ = f.Parse(args)
	if *out == "" {
		fatal(fmt.Errorf("-out is required"))
	}
	store, err := OpenStore(filepath.Join(c.dataDir, "gateway.db"))
	if err != nil {
		fatal(err)
	}
	var key []byte
	src := "new key (secrets reset)"
	if *reset {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			fatal(err)
		}
	} else {
		// NewVault verifies the key against the database before anything is written.
		vault, err := NewVault(store, c.dataDir, c.keyMode)
		if err != nil {
			fatal(fmt.Errorf("%v\n(if the master key is gone for good, re-run with -reset-secrets)", err))
		}
		key, src = vault.key, vault.KeySource
	}
	// Only create the output once we know the export will be complete.
	if err := os.MkdirAll(*out, 0o700); err != nil {
		fatal(err)
	}
	_ = os.Chmod(*out, 0o700)
	dst := filepath.Join(*out, "gateway.db")
	_ = os.Remove(dst)
	if _, err := store.db.Exec(`VACUUM INTO ?`, dst); err != nil {
		fatal(fmt.Errorf("snapshot db: %w", err))
	}
	_ = os.Chmod(dst, 0o600)
	if *reset {
		snap, err := OpenStore(dst)
		if err != nil {
			fatal(err)
		}
		rows, _ := snap.db.Query(`SELECT name FROM secrets ORDER BY system, name`)
		var lost []string
		for rows != nil && rows.Next() {
			var n string
			_ = rows.Scan(&n)
			lost = append(lost, n)
		}
		if rows != nil {
			rows.Close()
		}
		if _, err := snap.db.Exec(`DELETE FROM secrets; DELETE FROM meta WHERE k='vault_check'`); err != nil {
			fatal(err)
		}
		snap.db.Close()
		fmt.Fprintf(os.Stderr, "secrets dropped (re-enter them / sign in again after migrating): %s\n", strings.Join(lost, ", "))
	}
	if err := os.WriteFile(filepath.Join(*out, "master.key"), []byte(hex.EncodeToString(key)), 0o600); err != nil {
		fatal(err)
	}
	for _, name := range []string{"claude-directory.json"} {
		if b, err := os.ReadFile(filepath.Join(c.dataDir, name)); err == nil {
			_ = os.WriteFile(filepath.Join(*out, name), b, 0o600)
		}
	}
	fmt.Fprintf(os.Stderr, "exported database and master key (from %s) to %s\n", src, *out)
}
