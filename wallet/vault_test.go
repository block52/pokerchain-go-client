package wallet

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// fakeKeychain stands in for Electron safeStorage: it "encrypts" by prefixing,
// so a test can both seal and open without a real OS keychain.
type fakeKeychain struct{ secure bool }

func (f fakeKeychain) IsSecure() bool { return f.secure }
func (f fakeKeychain) Encrypt(plain string) ([]byte, error) {
	return append([]byte("os:"), plain...), nil
}
func (f fakeKeychain) Decrypt(c []byte) (string, error) {
	return string(c[len("os:"):]), nil
}

const lowCost = 16 // scrypt cost for fast tests

func tempVault(t *testing.T) *Vault {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wallet.json")
	return NewVault(path, fakeKeychain{secure: true}, lowCost)
}

func TestSaveThenReadMnemonicViaKeychain(t *testing.T) {
	v := tempVault(t)
	if err := v.SaveMnemonic(goldenMnemonic); err != nil {
		t.Fatal(err)
	}
	// A fresh handle on the same file, unlocked by the keychain alone (no password).
	v2 := NewVault(v.path, fakeKeychain{secure: true}, lowCost)
	if err := v2.OpenWithKeychainIfPasswordless(); err != nil {
		t.Fatal(err)
	}
	got, err := v2.Mnemonic()
	if err != nil {
		t.Fatal(err)
	}
	if got != goldenMnemonic {
		t.Fatalf("got %q", got)
	}
}

func TestPasswordLockUnlock(t *testing.T) {
	v := tempVault(t)
	if err := v.SaveMnemonic(goldenMnemonic); err != nil {
		t.Fatal(err)
	}
	if err := v.SetPassword("hunter2hunter2"); err != nil {
		t.Fatal(err)
	}

	// Setting a password (no Touch ID) drops the keychain copy: a fresh handle is locked.
	v2 := NewVault(v.path, fakeKeychain{secure: true}, lowCost)
	if err := v2.OpenWithKeychainIfPasswordless(); err != nil {
		t.Fatal(err)
	}
	if _, err := v2.Mnemonic(); err != errLocked {
		t.Fatalf("expected locked, got %v", err)
	}

	ok, err := v2.UnlockWithPassword("wrong-password")
	if err != nil || ok {
		t.Fatalf("wrong password accepted (ok=%v err=%v)", ok, err)
	}
	ok, err = v2.UnlockWithPassword("hunter2hunter2")
	if err != nil || !ok {
		t.Fatalf("correct password rejected (ok=%v err=%v)", ok, err)
	}
	got, err := v2.Mnemonic()
	if err != nil || got != goldenMnemonic {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestShortPasswordRejected(t *testing.T) {
	v := tempVault(t)
	if err := v.SaveMnemonic(goldenMnemonic); err != nil {
		t.Fatal(err)
	}
	if err := v.SetPassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
}

func TestStatusAndClear(t *testing.T) {
	v := tempVault(t)
	st, _ := v.Status()
	if st.Exists {
		t.Fatal("status says exists before save")
	}
	if err := v.SaveMnemonic(goldenMnemonic); err != nil {
		t.Fatal(err)
	}
	st, _ = v.Status()
	if !st.Exists || st.Locked || st.HasPassword || !st.OsProtected {
		t.Fatalf("unexpected status %+v", st)
	}
	if err := v.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(v.path); !os.IsNotExist(err) {
		t.Fatal("vault file still present after Clear")
	}
}

// TestOnDiskFormatMatchesTSVault asserts the JSON shape the desktop's
// TypeScript WalletVault reads: version 1, a seed {iv,tag,data} of base64, an
// osKey string, and no passwordKey until one is set.
func TestOnDiskFormatMatchesTSVault(t *testing.T) {
	v := tempVault(t)
	if err := v.SaveMnemonic(goldenMnemonic); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(v.path)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Version int `json:"version"`
		Seed    struct{ IV, Tag, Data string } `json:"seed"`
		OsKey       *string     `json:"osKey"`
		PasswordKey interface{} `json:"passwordKey"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Version != 1 {
		t.Fatalf("version %d", f.Version)
	}
	if f.PasswordKey != nil {
		t.Fatal("passwordKey should be null before a password is set")
	}
	if f.OsKey == nil {
		t.Fatal("osKey should be present for a password-less vault")
	}
	for name, s := range map[string]string{"iv": f.Seed.IV, "tag": f.Seed.Tag, "data": f.Seed.Data} {
		if _, err := base64.StdEncoding.DecodeString(s); err != nil {
			t.Fatalf("seed.%s is not base64: %v", name, err)
		}
	}
}
