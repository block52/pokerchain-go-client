package wallet

import "testing"

// Golden vector from the TypeScript SDK (the source of truth):
//
//	getAddressFromMnemonic("abandon…about", "b52") -> this address
//
// Derivation must match @cosmjs/crypto exactly, or an imported seed would land
// on a different address and lose access to existing funds.
const (
	goldenMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	goldenPrefix   = "b52"
	goldenAddress  = "b5219rl4cm2hmr8afy4kldpxz3fka4jguq0avffg09"
)

func TestAddressMatchesSDKGoldenVector(t *testing.T) {
	got, err := Address(goldenMnemonic, goldenPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if got != goldenAddress {
		t.Fatalf("derived %q, want %q (derivation must match @cosmjs)", got, goldenAddress)
	}
}

func TestPrivateKeyIsDeterministic(t *testing.T) {
	a, err := PrivateKey(goldenMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	b, err := PrivateKey(goldenMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Serialize()) != string(b.Serialize()) {
		t.Fatal("same mnemonic derived two different keys")
	}
}

func TestNewMnemonicRoundTrips(t *testing.T) {
	for _, bits := range []int{128, 256} {
		m, err := NewMnemonic(bits)
		if err != nil {
			t.Fatalf("bits=%d: %v", bits, err)
		}
		if !IsValidMnemonic(m) {
			t.Fatalf("bits=%d: generated an invalid mnemonic %q", bits, m)
		}
		// A generated mnemonic must derive an address without error.
		if _, err := Address(m, goldenPrefix); err != nil {
			t.Fatalf("bits=%d: derive: %v", bits, err)
		}
	}
	words12, _ := NewMnemonic(128)
	words24, _ := NewMnemonic(256)
	if countWords(words12) != 12 || countWords(words24) != 24 {
		t.Fatalf("word counts: 128->%d (want 12), 256->%d (want 24)", countWords(words12), countWords(words24))
	}
}

func TestInvalidMnemonicRejected(t *testing.T) {
	if IsValidMnemonic("not a real mnemonic phrase at all") {
		t.Fatal("garbage accepted as a mnemonic")
	}
	if _, err := PrivateKey("not a real mnemonic phrase at all"); err == nil {
		t.Fatal("PrivateKey accepted a garbage mnemonic")
	}
}

func countWords(s string) int {
	n, inWord := 0, false
	for _, r := range s {
		if r == ' ' {
			inWord = false
		} else if !inWord {
			inWord = true
			n++
		}
	}
	return n
}
