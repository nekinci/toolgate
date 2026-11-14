package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// Vault stores secrets encrypted with AES-256-GCM. The master key lives in the
// macOS Keychain (or a 0600 file as fallback). Agents can never read values.
type Vault struct {
	store *Store
	aead  cipher.AEAD
	// KeySource describes where the master key came from (keychain/file).
	KeySource string
	key       []byte
}

// Keychain item for the master key (per-user installs on macOS). Vaults
// created before the rename to toolgate keep theirs under the old service
// name; it is read as-is, never moved or replaced.
const (
	keychainService       = "toolgate"
	legacyKeychainService = "agent-gateway"
	keychainAccount       = "master-key"
)

// loadMasterKey returns the vault master key. A new key is only generated
// when mayCreate is true (empty vault); otherwise a missing or unreadable key
// is an error, never a silent replacement.
func loadMasterKey(dataDir, mode string, mayCreate bool) ([]byte, string, error) {
	if mode == "" {
		mode = "keychain"
		if runtime.GOOS != "darwin" {
			mode = "file"
		}
	}
	newKey := func() ([]byte, error) {
		k := make([]byte, 32)
		_, err := rand.Read(k)
		return k, err
	}
	if mode == "keychain" {
		var err error
		for _, svc := range []string{keychainService, legacyKeychainService} {
			out, ferr := exec.Command("security", "find-generic-password", "-s", svc, "-a", keychainAccount, "-w").Output()
			if ferr == nil {
				k, derr := hex.DecodeString(strings.TrimSpace(string(out)))
				if derr != nil || len(k) != 32 {
					return nil, "", fmt.Errorf("keychain item %s/%s is corrupt", svc, keychainAccount)
				}
				return k, "keychain", nil
			}
			var ee *exec.ExitError
			if !(errors.As(ferr, &ee) && ee.ExitCode() == 44) { // 44 = errSecItemNotFound
				return nil, "", fmt.Errorf("could not read the master key from the macOS Keychain (it may be locked; run from a logged-in session): %v", ferr)
			}
		}
		k, _, ferr := readKeyFile(dataDir)
		if ferr != nil {
			if !mayCreate {
				return nil, "", errors.New("the vault has encrypted data but no master key was found in the Keychain or master.key; refusing to create a new key")
			}
			if k, err = newKey(); err != nil {
				return nil, "", err
			}
		}
		if err := exec.Command("security", "add-generic-password", "-U", "-s", keychainService, "-a", keychainAccount, "-w", hex.EncodeToString(k)).Run(); err == nil {
			if ferr == nil {
				_ = os.Remove(filepath.Join(dataDir, "master.key"))
			}
			return k, "keychain", nil
		}
		if ferr == nil {
			return k, "file", nil
		}
		fmt.Fprintln(os.Stderr, "warning: keychain unavailable for a new vault, storing master.key in the data directory")
		return k, "file", os.WriteFile(filepath.Join(dataDir, "master.key"), []byte(hex.EncodeToString(k)), 0o600)
	}
	k, _, err := readKeyFile(dataDir)
	if err == nil {
		return k, "file", nil
	}
	if !mayCreate {
		return nil, "", fmt.Errorf("the vault has encrypted data but %s is missing; refusing to create a new key", filepath.Join(dataDir, "master.key"))
	}
	if k, err = newKey(); err != nil {
		return nil, "", err
	}
	return k, "file", os.WriteFile(filepath.Join(dataDir, "master.key"), []byte(hex.EncodeToString(k)), 0o600)
}

func readKeyFile(dataDir string) ([]byte, string, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, "master.key"))
	if err != nil {
		return nil, "", err
	}
	k, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) != 32 {
		return nil, "", errors.New("corrupt master.key")
	}
	return k, "file", nil
}

func NewVault(store *Store, dataDir, mode string) (*Vault, error) {
	var nSecrets int
	_ = store.db.QueryRow(`SELECT count(*) FROM secrets`).Scan(&nSecrets)
	check := store.Meta("vault_check")
	key, src, err := loadMasterKey(dataDir, mode, nSecrets == 0 && check == "")
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	v := &Vault{store: store, aead: aead, KeySource: src, key: key}
	if err := v.verifyKey(check, nSecrets); err != nil {
		return nil, err
	}
	return v, nil
}

const vaultCheckPlain = "agent-gateway vault check"

// verifyKey makes sure the loaded key matches this database, so a wrong key
// is detected at startup instead of corrupting or hiding secrets.
func (v *Vault) verifyKey(check string, nSecrets int) error {
	if check != "" {
		b, err := hex.DecodeString(check)
		ns := v.aead.NonceSize()
		if err != nil || len(b) <= ns {
			return errors.New("vault check record is corrupt")
		}
		if pt, err := v.aead.Open(nil, b[:ns], b[ns:], []byte("vault-check")); err != nil || string(pt) != vaultCheckPlain {
			return errors.New("the master key does not match this vault (wrong key?) — refusing to start")
		}
		return nil
	}
	if nSecrets > 0 {
		var name string
		var nonce, ct []byte
		if err := v.store.db.QueryRow(`SELECT name,nonce,ct FROM secrets LIMIT 1`).Scan(&name, &nonce, &ct); err == nil {
			if _, err := v.aead.Open(nil, nonce, ct, []byte(name)); err != nil {
				return errors.New("the master key does not match this vault (wrong key?) — refusing to start")
			}
		}
	}
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	v.store.SetMeta("vault_check", hex.EncodeToString(append(nonce, v.aead.Seal(nil, nonce, []byte(vaultCheckPlain), []byte("vault-check"))...)))
	return nil
}

var secretNameRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

type SecretMeta struct {
	Name      string `json:"name"`
	System    bool   `json:"system"`
	Note      string `json:"note"`
	UpdatedAt string `json:"updated_at"`
	HasValue  bool   `json:"has_value"`
}

func (v *Vault) Set(name, value string, system bool, note string) error {
	if !secretNameRe.MatchString(name) {
		return fmt.Errorf("invalid secret name %q (allowed: letters, digits, _ . : -)", name)
	}
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := v.aead.Seal(nil, nonce, []byte(value), []byte(name))
	sys := 0
	if system {
		sys = 1
	}
	_, err := v.store.db.Exec(`INSERT INTO secrets(name,nonce,ct,system,note,updated_at) VALUES(?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET nonce=excluded.nonce, ct=excluded.ct, system=excluded.system,
		note=CASE WHEN excluded.note='' THEN secrets.note ELSE excluded.note END, updated_at=excluded.updated_at`,
		name, nonce, ct, sys, note, now())
	return err
}

func (v *Vault) Get(name string) (string, error) {
	var nonce, ct []byte
	err := v.store.db.QueryRow(`SELECT nonce,ct FROM secrets WHERE name=?`, name).Scan(&nonce, &ct)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("secret %q is not set", name)
	}
	if err != nil {
		return "", err
	}
	pt, err := v.aead.Open(nil, nonce, ct, []byte(name))
	if err != nil {
		return "", fmt.Errorf("secret %q could not be decrypted", name)
	}
	return string(pt), nil
}

func (v *Vault) Has(name string) bool {
	var n int
	_ = v.store.db.QueryRow(`SELECT count(*) FROM secrets WHERE name=?`, name).Scan(&n)
	return n > 0
}

func (v *Vault) Delete(name string) error {
	_, err := v.store.db.Exec(`DELETE FROM secrets WHERE name=?`, name)
	return err
}

func (v *Vault) List(includeSystem bool) ([]SecretMeta, error) {
	rows, err := v.store.db.Query(`SELECT name,system,note,updated_at FROM secrets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SecretMeta
	for rows.Next() {
		var m SecretMeta
		var sys int
		if err := rows.Scan(&m.Name, &sys, &m.Note, &m.UpdatedAt); err != nil {
			return nil, err
		}
		m.System = sys == 1
		m.HasValue = true
		if m.System && !includeSystem {
			continue
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

var secretRefRe = regexp.MustCompile(`\$\{secret:([A-Za-z0-9_.:-]+)\}`)

// SecretRefs returns all secret names referenced in s.
func SecretRefs(s string) []string {
	var out []string
	for _, m := range secretRefRe.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// Resolve replaces ${secret:NAME} references. Missing secrets are collected
// into a MissingSecretsError.
func (v *Vault) Resolve(s string, missing map[string]bool) string {
	return secretRefRe.ReplaceAllStringFunc(s, func(m string) string {
		name := secretRefRe.FindStringSubmatch(m)[1]
		val, err := v.Get(name)
		if err != nil {
			missing[name] = true
			return ""
		}
		return val
	})
}

// RequiredSecrets lists all secrets a server config references.
func RequiredSecrets(c *ServerConfig) []string {
	set := map[string]bool{}
	add := func(s string) {
		for _, n := range SecretRefs(s) {
			set[n] = true
		}
	}
	add(c.Command)
	add(c.URL)
	for _, a := range c.Args {
		add(a)
	}
	for _, e := range c.Env {
		add(e)
	}
	for _, h := range c.Headers {
		add(h)
	}
	if c.OAuthClientSecretRef != "" {
		set[c.OAuthClientSecretRef] = true
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

type MissingSecretsError struct {
	Server string
	Names  []string
}

func (e *MissingSecretsError) Error() string {
	return fmt.Sprintf("server %q is missing secrets: %s", e.Server, strings.Join(e.Names, ", "))
}
