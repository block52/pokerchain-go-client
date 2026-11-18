// Package wallet is a self-custodial BIP39/BIP44 wallet for pokerchain: it
// generates a mnemonic, derives the chain key at the Cosmos path
// m/44'/118'/0'/0/0, and derives the bech32 address. It is the local,
// seed-phrase counterpart to the custodial keys.Vault.
//
// Derivation matches @cosmjs/crypto (what the TypeScript SDK's
// getAddressFromMnemonic uses), so an existing seed yields the same address:
// BIP39 seed with no passphrase, BIP32 secp256k1, hardened 44'/118'/0', then
// 0/0. Verified against a golden vector in wallet_test.go.
package wallet

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	bip39 "github.com/cosmos/go-bip39"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/block52/pokerchain-go-client/keys"
)

// CosmosHDPath is the standard Cosmos derivation path (coin type 118).
const CosmosHDPath = "m/44'/118'/0'/0/0"

// hardened is BIP32's hardened-child offset.
const hardened = hdkeychain.HardenedKeyStart

// cosmosPath is CosmosHDPath as BIP32 child indices: 44', 118', 0', 0, 0.
var cosmosPath = []uint32{hardened + 44, hardened + 118, hardened + 0, 0, 0}

// NewMnemonic returns a fresh BIP39 mnemonic. bits is the entropy size:
// 128 → 12 words, 256 → 24 words.
func NewMnemonic(bits int) (string, error) {
	entropy, err := bip39.NewEntropy(bits)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

// IsValidMnemonic reports whether m is a valid BIP39 mnemonic.
func IsValidMnemonic(m string) bool { return bip39.IsMnemonicValid(m) }

// PrivateKey derives the chain's secp256k1 private key from a mnemonic
// (no BIP39 passphrase), at m/44'/118'/0'/0/0.
func PrivateKey(mnemonic string) (*secp256k1.PrivateKey, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("wallet: invalid mnemonic")
	}
	seed := bip39.NewSeed(mnemonic, "") // no passphrase, matching @cosmjs

	key, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}
	for _, idx := range cosmosPath {
		key, err = key.Derive(idx)
		if err != nil {
			return nil, err
		}
	}
	ecPriv, err := key.ECPrivKey()
	if err != nil {
		return nil, err
	}
	return secp256k1.PrivKeyFromBytes(ecPriv.Serialize()), nil
}

// Address derives the bech32 address for a mnemonic under prefix (e.g. "b52").
func Address(mnemonic, prefix string) (string, error) {
	priv, err := PrivateKey(mnemonic)
	if err != nil {
		return "", err
	}
	defer priv.Zero()
	return keys.Address(prefix, priv.PubKey().SerializeCompressed())
}
