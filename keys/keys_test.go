package keys

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

func testVault(t *testing.T) *Vault {
	t.Helper()
	v, err := NewVault(map[int][]byte{1: bytes.Repeat([]byte{7}, 32), 2: bytes.Repeat([]byte{9}, 32)}, 1, "b52")
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestNewVaultRejectsBadKEKs(t *testing.T) {
	if _, err := NewVault(map[int][]byte{1: {1, 2}}, 1, "b52"); err == nil {
		t.Fatal("a short KEK must be refused")
	}
	if _, err := NewVault(map[int][]byte{1: bytes.Repeat([]byte{1}, 32)}, 2, "b52"); err == nil {
		t.Fatal("a missing current KEK must be refused")
	}
}

func TestSealOpenRoundTripAndAddress(t *testing.T) {
	v := testVault(t)
	s, err := v.New("user-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s.Address, "b521") {
		t.Fatalf("address %q does not look like b52...", s.Address)
	}
	if bytes.Contains(s.Ciphertext, s.PublicKey) {
		t.Fatal("ciphertext must not contain the key in the clear")
	}
	err = v.With(s, func(priv *secp256k1.PrivateKey) error {
		got := hex.EncodeToString(priv.PubKey().SerializeCompressed())
		if got != hex.EncodeToString(s.PublicKey) {
			t.Fatalf("opened key has pubkey %s, want %s", got, hex.EncodeToString(s.PublicKey))
		}
		addr, _ := Address("b52", priv.PubKey().SerializeCompressed())
		if addr != s.Address {
			t.Fatalf("address %s, want %s", addr, s.Address)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestOpenFailsWhenMovedToAnotherRowOrWrongKEK(t *testing.T) {
	v := testVault(t)
	s, _ := v.New("user-1")

	moved := s
	moved.UserID = "user-2"
	if err := v.With(moved, func(*secp256k1.PrivateKey) error { return nil }); err == nil {
		t.Fatal("a ciphertext moved to another user's row must not open")
	}
	other := s
	other.Address = "b521other"
	if err := v.With(other, func(*secp256k1.PrivateKey) error { return nil }); err == nil {
		t.Fatal("a ciphertext moved to another address must not open")
	}
	wrongKEK := s
	wrongKEK.KEKVersion = 2
	if err := v.With(wrongKEK, func(*secp256k1.PrivateKey) error { return nil }); err == nil {
		t.Fatal("the wrong KEK must not open it")
	}
	tampered := s
	tampered.Ciphertext = append([]byte{}, s.Ciphertext...)
	tampered.Ciphertext[0] ^= 1
	if err := v.With(tampered, func(*secp256k1.PrivateKey) error { return nil }); err == nil {
		t.Fatal("a tampered ciphertext must not open")
	}
}

func TestKeyIsZeroedAfterWith(t *testing.T) {
	v := testVault(t)
	s, _ := v.New("u")
	var leaked *secp256k1.PrivateKey
	_ = v.With(s, func(p *secp256k1.PrivateKey) error { leaked = p; return nil })
	if leaked.Key.IsZero() == false {
		t.Fatal("the private scalar must be zeroed once With returns")
	}
}

func TestSign64IsLowSAndVerifies(t *testing.T) {
	priv := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{3}, 32))
	msg := []byte("sign doc")
	sig := Sign64(priv, msg)
	if len(sig) != 64 {
		t.Fatalf("len %d", len(sig))
	}
	var r, s secp256k1.ModNScalar
	r.SetByteSlice(sig[:32])
	s.SetByteSlice(sig[32:])
	h := sha256.Sum256(msg)
	if !ecdsa.NewSignature(&r, &s).Verify(h[:], priv.PubKey()) {
		t.Fatal("signature does not verify")
	}
	if s.IsOverHalfOrder() {
		t.Fatal("signature must be low-S")
	}
}

func TestPersonalSignRecoversToTheSigner(t *testing.T) {
	priv := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{5}, 32))
	msg := "pokerchain-query:1800000000"
	sig := PersonalSign(priv, msg)
	if len(sig) != 65 || (sig[64] != 27 && sig[64] != 28) {
		t.Fatalf("want r||s||v with v 27 or 28, got len %d v %d", len(sig), sig[64])
	}
	k := sha3.NewLegacyKeccak256()
	k.Write([]byte("\x19Ethereum Signed Message:\n" + "27" + msg))
	compact := append([]byte{sig[64]}, sig[:64]...)
	pub, _, err := ecdsa.RecoverCompact(compact, k.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !pub.IsEqual(priv.PubKey()) {
		t.Fatal("the signature does not recover to the signing key")
	}
}

// sealedVector pins the stored-key format shared with the club API, which makes accounts (service/src/auth/accounts.ts):
// the API seals with its TypeScript code, this package opens with Go. The same file is read by the API's tests, which
// must open it AND reproduce it byte for byte from the same nonce. Regenerate only if the format changes on purpose:
// UPDATE_SEALED_VECTOR=1 go test ./internal/keys -run SealedVector
type sealedVector struct {
	KEKHex     string `json:"kekHex"`
	KEKVersion int    `json:"kekVersion"`
	UserID     string `json:"userId"`
	PrivateKey string `json:"privateKeyHex"`
	Address    string `json:"address"`
	PublicKey  string `json:"publicKeyHex"`
	NonceHex   string `json:"nonceHex"`
	Ciphertext string `json:"ciphertextHex"` // AES-256-GCM ciphertext || 16-byte tag
	AAD        string `json:"aad"`           // "custody|<userId>|<address>"
}

const sealedVectorPath = "testdata/sealed.json"

func TestSealedVectorOpensAndMatches(t *testing.T) {
	v := testVault(t)
	if os.Getenv("UPDATE_SEALED_VECTOR") == "1" {
		priv, _ := hex.DecodeString("00000000000000000000000000000000000000000000000000000000000000a1")
		s, err := v.seal("9b2f1d3e-0000-4000-8000-0000000000aa", secp256k1.PrivKeyFromBytes(priv))
		if err != nil {
			t.Fatal(err)
		}
		out, _ := json.MarshalIndent(sealedVector{KEKHex: strings.Repeat("07", 32), KEKVersion: 1, UserID: s.UserID, PrivateKey: hex.EncodeToString(priv),
			Address: s.Address, PublicKey: hex.EncodeToString(s.PublicKey), NonceHex: hex.EncodeToString(s.Nonce), Ciphertext: hex.EncodeToString(s.Ciphertext),
			AAD: "custody|" + s.UserID + "|" + s.Address}, "", "  ")
		if err := os.WriteFile(sealedVectorPath, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(sealedVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var vec sealedVector
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatal(err)
	}
	pub, _ := hex.DecodeString(vec.PublicKey)
	nonce, _ := hex.DecodeString(vec.NonceHex)
	ct, _ := hex.DecodeString(vec.Ciphertext)
	want, _ := hex.DecodeString(vec.PrivateKey)
	sealed := Sealed{UserID: vec.UserID, Address: vec.Address, PublicKey: pub, Nonce: nonce, Ciphertext: ct, KEKVersion: vec.KEKVersion}
	opened := false
	if err := v.With(sealed, func(k *secp256k1.PrivateKey) error {
		opened = bytes.Equal(k.Serialize(), want)
		return nil
	}); err != nil || !opened {
		t.Fatalf("the vector must open to its private key: %v opened=%v", err, opened)
	}
	if addr, _ := Address("b52", pub); addr != vec.Address {
		t.Fatalf("address %s, vector says %s", addr, vec.Address)
	}
}
