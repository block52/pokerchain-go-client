package wire

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestAuthInfoSeqCarriesSequence(t *testing.T) {
	pub := make([]byte, 33)
	pub[0] = 0x02
	auth := AuthInfoSeq(pub, 250000, 7)

	// AuthInfo field 1 is the SignerInfo; its field 3 is the sequence.
	signer, err := firstBytes(auth, 1)
	if err != nil {
		t.Fatal(err)
	}
	var seq uint64
	found := false
	if err := walk(signer, func(num protowire.Number, typ protowire.Type, _ []byte, v uint64) {
		if num == 3 && typ == protowire.VarintType {
			seq, found = v, true
		}
	}); err != nil {
		t.Fatal(err)
	}
	if !found || seq != 7 {
		t.Fatalf("sequence in AuthInfo = %d found=%v, want 7", seq, found)
	}
}

func TestTxBodyOrderedHasNoUnorderedOrTimeout(t *testing.T) {
	body := TxBodyOrdered([]byte("msg"))
	// Ordered body must not set the unordered flag (field 4) or timeout (field 5).
	if err := walk(body, func(num protowire.Number, _ protowire.Type, _ []byte, _ uint64) {
		if num == 4 || num == 5 {
			t.Fatalf("ordered TxBody unexpectedly set field %d", num)
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeAccountNumberAndSequence(t *testing.T) {
	// QueryAccountInfoResponse{ info: BaseAccount{ account_number=42 (f3), sequence=9 (f4) } }
	var base []byte
	base = protowire.AppendTag(base, 3, protowire.VarintType)
	base = protowire.AppendVarint(base, 42)
	base = protowire.AppendTag(base, 4, protowire.VarintType)
	base = protowire.AppendVarint(base, 9)
	var resp []byte
	resp = protowire.AppendTag(resp, 1, protowire.BytesType)
	resp = protowire.AppendBytes(resp, base)

	num, seq, err := DecodeAccountNumberAndSequence(resp)
	if err != nil {
		t.Fatal(err)
	}
	if num != 42 || seq != 9 {
		t.Fatalf("got number=%d sequence=%d, want 42/9", num, seq)
	}
}
