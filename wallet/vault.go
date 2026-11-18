package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/scrypt"
)

// Vault holds the wallet mnemonic encrypted at rest, in the exact on-disk
// format the desktop app's TypeScript WalletVault uses (src/wallet/vault.ts),
// so the two are interchangeable:
//
//	{ version:1, seed:{iv,tag,data}, osKey, passwordKey:{salt,iv,tag,data},
//	  touchId, autoLockMinutes }
//
// The mnemonic is sealed with a random 32-byte vault key (AES-256-GCM). That
// vault key is itself kept by the OS keychain (osKey) and/or wrapped by a
// scrypt key derived from the user's password (passwordKey). The OS keychain
// is injected (OsKeyStore) because it lives in the Electron main process; Go
// tests supply a fake.
type Vault struct {
	path   string
	osKeys OsKeyStore
	cost   int

	file     *vaultFile
	loaded   bool
	vaultKey []byte
}

// OsKeyStore is the OS keychain (Electron safeStorage), injected so the vault
// can be used and tested without Electron.
type OsKeyStore interface {
	IsSecure() bool
	Encrypt(plain string) ([]byte, error)
	Decrypt(ciphertext []byte) (string, error)
}

const (
	vaultKeyBytes       = 32
	scryptCost          = 32768
	scryptR             = 8
	scryptP             = 1
	minPasswordLen      = 8
	defaultAutoLockMins = 15
)

var errLocked = errors.New("wallet is locked")

type sealed struct {
	IV   string `json:"iv"`
	Tag  string `json:"tag"`
	Data string `json:"data"`
}

type passwordWrap struct {
	Salt string `json:"salt"`
	sealed
}

type vaultFile struct {
	Version         int           `json:"version"`
	Seed            sealed        `json:"seed"`
	OsKey           *string       `json:"osKey"`
	PasswordKey     *passwordWrap `json:"passwordKey"`
	TouchID         bool          `json:"touchId"`
	AutoLockMinutes int           `json:"autoLockMinutes"`
}

// NewVault opens (lazily) the vault at path, using osKeys for OS-keychain
// wrapping. cost overrides the scrypt cost (pass 0 for the default; tests lower it).
func NewVault(path string, osKeys OsKeyStore, cost int) *Vault {
	if cost == 0 {
		cost = scryptCost
	}
	return &Vault{path: path, osKeys: osKeys, cost: cost}
}

// Status reports whether a vault exists, is locked, and how it is protected.
type Status struct {
	Exists          bool
	Locked          bool
	HasPassword     bool
	TouchIDEnabled  bool
	AutoLockMinutes int
	OsProtected     bool
}

func (v *Vault) Status() (Status, error) {
	f, err := v.read()
	if err != nil {
		return Status{}, err
	}
	if f == nil {
		return Status{AutoLockMinutes: defaultAutoLockMins, OsProtected: v.osKeys.IsSecure()}, nil
	}
	return Status{
		Exists:          true,
		Locked:          v.vaultKey == nil,
		HasPassword:     f.PasswordKey != nil,
		TouchIDEnabled:  f.TouchID,
		AutoLockMinutes: f.AutoLockMinutes,
		OsProtected:     v.osKeys.IsSecure(),
	}, nil
}

// OpenWithKeychainIfPasswordless unlocks a password-less vault from the OS
// keychain alone (as at app start).
func (v *Vault) OpenWithKeychainIfPasswordless() error {
	f, err := v.read()
	if err != nil || f == nil || f.PasswordKey != nil || f.OsKey == nil || v.vaultKey != nil {
		return err
	}
	key, err := v.unsealOsKey(*f.OsKey)
	if err != nil {
		return err
	}
	v.vaultKey = key
	return nil
}

// UnlockWithKeychain unlocks via the OS keychain (Touch ID already verified by the caller).
func (v *Vault) UnlockWithKeychain() (bool, error) {
	f, err := v.read()
	if err != nil || f == nil || !f.TouchID || f.OsKey == nil {
		return false, err
	}
	key, err := v.unsealOsKey(*f.OsKey)
	if err != nil {
		return false, err
	}
	v.vaultKey = key
	return true, nil
}

// UnlockWithPassword unlocks the vault with the user's password.
func (v *Vault) UnlockWithPassword(password string) (bool, error) {
	key, err := v.keyFromPassword(password)
	if err != nil || key == nil {
		return false, err
	}
	v.vaultKey = key
	return true, nil
}

// VerifyPassword checks the password without changing the locked state.
func (v *Vault) VerifyPassword(password string) (bool, error) {
	key, err := v.keyFromPassword(password)
	return key != nil, err
}

// Lock forgets the in-memory vault key.
func (v *Vault) Lock() { v.vaultKey = nil }

// Mnemonic returns the decrypted mnemonic, or an error while locked.
func (v *Vault) Mnemonic() (string, error) {
	f, err := v.read()
	if err != nil {
		return "", err
	}
	if f == nil {
		return "", errors.New("no wallet saved")
	}
	if v.vaultKey == nil {
		return "", errLocked
	}
	plain, err := open(v.vaultKey, f.Seed)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// SaveMnemonic creates the vault (first save) or re-seals the mnemonic under
// the existing vault key.
func (v *Vault) SaveMnemonic(mnemonic string) error {
	f, err := v.read()
	if err != nil {
		return err
	}
	if f == nil {
		key := make([]byte, vaultKeyBytes)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		v.vaultKey = key
		seed, err := seal(key, []byte(mnemonic))
		if err != nil {
			return err
		}
		osKey, err := v.sealOsKey(key)
		if err != nil {
			return err
		}
		return v.write(&vaultFile{Version: 1, Seed: seed, OsKey: &osKey, AutoLockMinutes: defaultAutoLockMins})
	}
	if v.vaultKey == nil {
		return errLocked
	}
	seed, err := seal(v.vaultKey, []byte(mnemonic))
	if err != nil {
		return err
	}
	nf := *f
	nf.Seed = seed
	return v.write(&nf)
}

// SetPassword wraps the vault key with a password (and drops the keychain copy
// unless Touch ID is on, matching the TS vault).
func (v *Vault) SetPassword(password string) error {
	if len(password) < minPasswordLen {
		return fmt.Errorf("use at least %d characters", minPasswordLen)
	}
	f, err := v.requireFile()
	if err != nil {
		return err
	}
	if v.vaultKey == nil {
		return errLocked
	}
	wrap, err := v.wrapWithPassword(v.vaultKey, password)
	if err != nil {
		return err
	}
	nf := *f
	nf.PasswordKey = wrap
	if !f.TouchID {
		nf.OsKey = nil
	}
	return v.write(&nf)
}

// Clear deletes the vault file and forgets the key.
func (v *Vault) Clear() error {
	v.vaultKey = nil
	v.file = nil
	v.loaded = true
	err := os.Remove(v.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// --- internals ------------------------------------------------------------

func (v *Vault) keyFromPassword(password string) ([]byte, error) {
	f, err := v.read()
	if err != nil || f == nil || f.PasswordKey == nil {
		return nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(f.PasswordKey.Salt)
	if err != nil {
		return nil, err
	}
	derived, err := scrypt.Key([]byte(password), salt, v.cost, scryptR, scryptP, vaultKeyBytes)
	if err != nil {
		return nil, err
	}
	key, err := open(derived, f.PasswordKey.sealed)
	if err != nil {
		return nil, nil // wrong password
	}
	if len(key) != vaultKeyBytes {
		return nil, nil
	}
	return key, nil
}

func (v *Vault) wrapWithPassword(key []byte, password string) (*passwordWrap, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	derived, err := scrypt.Key([]byte(password), salt, v.cost, scryptR, scryptP, vaultKeyBytes)
	if err != nil {
		return nil, err
	}
	s, err := seal(derived, key)
	if err != nil {
		return nil, err
	}
	return &passwordWrap{Salt: base64.StdEncoding.EncodeToString(salt), sealed: s}, nil
}

func (v *Vault) sealOsKey(key []byte) (string, error) {
	enc, err := v.osKeys.Encrypt(hex.EncodeToString(key))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(enc), nil
}

func (v *Vault) unsealOsKey(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	hexKey, err := v.osKeys.Decrypt(raw)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil || len(key) != vaultKeyBytes {
		return nil, errors.New("the wallet key could not be read from the OS keychain")
	}
	return key, nil
}

func (v *Vault) requireFile() (*vaultFile, error) {
	f, err := v.read()
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, errors.New("no wallet saved")
	}
	return f, nil
}

func (v *Vault) read() (*vaultFile, error) {
	if v.loaded {
		return v.file, nil
	}
	data, err := os.ReadFile(v.path)
	if errors.Is(err, os.ErrNotExist) {
		v.loaded = true
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f vaultFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	if f.Version != 1 {
		return nil, errors.New("the wallet file is not in a format this version understands")
	}
	v.file = &f
	v.loaded = true
	return v.file, nil
}

func (v *Vault) write(f *vaultFile) error {
	if err := os.MkdirAll(filepath.Dir(v.path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, v.path); err != nil {
		return err
	}
	v.file = f
	v.loaded = true
	return nil
}

// seal/open are AES-256-GCM with a 12-byte IV, matching the TS vault's
// {iv,tag,data} base64 fields (GCM appends the tag, which TS splits out via
// getAuthTag; Go keeps it on the ciphertext, so we split it here to stay
// byte-compatible on disk).
func seal(key, plain []byte) (sealed, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return sealed{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return sealed{}, err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return sealed{}, err
	}
	ct := gcm.Seal(nil, iv, plain, nil)
	tag := ct[len(ct)-gcm.Overhead():]
	body := ct[:len(ct)-gcm.Overhead()]
	return sealed{
		IV:   base64.StdEncoding.EncodeToString(iv),
		Tag:  base64.StdEncoding.EncodeToString(tag),
		Data: base64.StdEncoding.EncodeToString(body),
	}, nil
}

func open(key []byte, s sealed) ([]byte, error) {
	iv, err := base64.StdEncoding.DecodeString(s.IV)
	if err != nil {
		return nil, err
	}
	tag, err := base64.StdEncoding.DecodeString(s.Tag)
	if err != nil {
		return nil, err
	}
	body, err := base64.StdEncoding.DecodeString(s.Data)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, append(body, tag...), nil)
}
