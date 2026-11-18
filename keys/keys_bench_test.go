package keys

import (
	"bytes"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// What does opening the sealed key cost, next to signing with it? (It decides whether caching an opened key is worth any risk.)
func benchVault(b *testing.B) (*Vault, Sealed) {
	v, err := NewVault(map[int][]byte{1: bytes.Repeat([]byte{7}, 32)}, 1, "b52")
	if err != nil {
		b.Fatal(err)
	}
	s, err := v.New("9b2f1d3e-0000-4000-8000-000000000001")
	if err != nil {
		b.Fatal(err)
	}
	return v, s
}

func BenchmarkOpenKey(b *testing.B) {
	v, s := benchVault(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = v.With(s, func(*secp256k1.PrivateKey) error { return nil })
	}
}

func BenchmarkOpenAndSign(b *testing.B) {
	v, s := benchVault(b)
	msg := bytes.Repeat([]byte{1}, 300)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = v.With(s, func(p *secp256k1.PrivateKey) error { Sign64(p, msg); return nil })
	}
}
