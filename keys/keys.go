// Package keys generates, seals and opens player signing keys, and signs with them.
//
// A key is stored as AES-256-GCM ciphertext (private_key_enc), sealed with a
// key-encryption key (KEK) that comes from the function's environment, never
// from the database. The ciphertext is bound to its row (the user id and the
// address are the GCM additional data), so a ciphertext copied into another
// row fails to open. The key exists in memory only inside Vault.With.
package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"

	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // the chain's address derivation is ripemd160(sha256(pubkey))
	"golang.org/x/crypto/sha3"
)

// Sealed is a key as stored: everything needed to open it except the KEK.
type Sealed struct {
	UserID     string
	Address    string
	PublicKey  []byte // compressed, 33 bytes
	Ciphertext []byte // AES-256-GCM ciphertext || tag
	Nonce      []byte // 12 bytes
	KEKVersion int
}

// Vault holds the KEKs by version. The current version seals new keys.
type Vault struct {
	keks    map[int][]byte
	current int
	prefix  string
}

// NewVault checks that every KEK is 32 bytes and that the current version exists.
func NewVault(keks map[int][]byte, current int, bech32Prefix string) (*Vault, error) {
	for v, k := range keks {
		if len(k) != 32 {
			return nil, fmt.Errorf("KEK v%d is %d bytes, want 32", v, len(k))
		}
	}
	if _, ok := keks[current]; !ok {
		return nil, fmt.Errorf("current KEK v%d is not set", current)
	}
	return &Vault{keks: keks, current: current, prefix: bech32Prefix}, nil
}

func aad(userID, address string) []byte { return []byte("custody|" + userID + "|" + address) }

func (v *Vault) aead(version int) (cipher.AEAD, error) {
	kek, ok := v.keks[version]
	if !ok {
		return nil, fmt.Errorf("KEK v%d is not set", version)
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Address derives the chain address: bech32(prefix, ripemd160(sha256(compressed pubkey))).
func Address(prefix string, compressedPub []byte) (string, error) {
	s := sha256.Sum256(compressedPub)
	r := ripemd160.New()
	r.Write(s[:])
	return bech32.EncodeFromBase256(prefix, r.Sum(nil))
}

// New generates a key for userID and returns it sealed. The signer does not make accounts (the club API does, in
// service/src/auth/accounts.ts, with this same format: see testdata/sealed.json); this is for tests and for generating that vector.
func (v *Vault) New(userID string) (Sealed, error) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return Sealed{}, err
	}
	defer priv.Zero()
	return v.seal(userID, priv)
}

func (v *Vault) seal(userID string, priv *secp256k1.PrivateKey) (Sealed, error) {
	pub := priv.PubKey().SerializeCompressed()
	address, err := Address(v.prefix, pub)
	if err != nil {
		return Sealed{}, err
	}
	gcm, err := v.aead(v.current)
	if err != nil {
		return Sealed{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Sealed{}, err
	}
	raw := priv.Serialize()
	defer zero(raw)
	return Sealed{UserID: userID, Address: address, PublicKey: pub, Nonce: nonce, KEKVersion: v.current,
		Ciphertext: gcm.Seal(nil, nonce, raw, aad(userID, address))}, nil
}

// With opens the key for the duration of fn, then zeroes it. fn must not keep, return or log the key.
func (v *Vault) With(s Sealed, fn func(*secp256k1.PrivateKey) error) error {
	gcm, err := v.aead(s.KEKVersion)
	if err != nil {
		return err
	}
	raw, err := gcm.Open(nil, s.Nonce, s.Ciphertext, aad(s.UserID, s.Address))
	if err != nil {
		return errors.New("keys: cannot open key") // wrong KEK, or the ciphertext was moved to another row
	}
	defer zero(raw)
	priv := secp256k1.PrivKeyFromBytes(raw)
	defer priv.Zero()
	return fn(priv)
}

// Sign64 signs msg the way the chain verifies SIGN_MODE_DIRECT: ECDSA over sha256(msg), RFC 6979,
// low-S, returned as 64 bytes r || s.
func Sign64(priv *secp256k1.PrivateKey, msg []byte) []byte {
	h := sha256.Sum256(msg)
	sig := ecdsa.Sign(priv, h[:])
	r, s := sig.R(), sig.S()
	var out [64]byte
	var rb, sb [32]byte
	r.PutBytes(&rb)
	s.PutBytes(&sb)
	copy(out[:32], rb[:])
	copy(out[32:], sb[:])
	return out[:]
}

// PersonalSign signs message as an Ethereum personal_sign (EIP-191) message and returns the
// 65-byte signature r || s || v (v = 27 or 28) that ethers' signMessage produces. The table
// WebSocket checks it to decide whose hole cards to reveal.
func PersonalSign(priv *secp256k1.PrivateKey, message string) []byte {
	k := sha3.NewLegacyKeccak256()
	k.Write([]byte("\x19Ethereum Signed Message:\n" + strconv.Itoa(len(message)) + message))
	compact := ecdsa.SignCompact(priv, k.Sum(nil), false) // v || r || s, v = 27 + recovery id
	return append(append([]byte{}, compact[1:]...), compact[0])
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
