package wire

import (
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestZeroValuesAreOmitted(t *testing.T) {
	// proto3: a field holding its zero value is not written, which the golden vectors depend on
	got := PerformAction("p", "g", "call", 0, "")
	var a []byte
	a = protowire.AppendTag(a, 1, protowire.BytesType)
	a = protowire.AppendString(a, "p")
	a = protowire.AppendTag(a, 2, protowire.BytesType)
	a = protowire.AppendString(a, "g")
	a = protowire.AppendTag(a, 3, protowire.BytesType)
	a = protowire.AppendString(a, "call")
	want := any(typePerformAction, a)
	if string(got) != string(want) {
		t.Fatalf("got %x want %x", got, want)
	}
}

func TestTxBodyCarriesUnorderedAndTimeout(t *testing.T) {
	body := TxBody(PerformAction("p", "g", "call", 0, ""), time.Unix(1_800_000_000, 5_000_000))
	var unordered, ts bool
	if err := walk(body, func(num protowire.Number, typ protowire.Type, v []byte, n uint64) {
		switch {
		case num == 4 && typ == protowire.VarintType && n == 1:
			unordered = true
		case num == 5 && typ == protowire.BytesType:
			ts = true
		}
	}); err != nil {
		t.Fatal(err)
	}
	if !unordered || !ts {
		t.Fatalf("unordered=%v timeout=%v", unordered, ts)
	}
}

func TestDecodeBroadcastTxResponse(t *testing.T) {
	var inner []byte
	inner = protowire.AppendTag(inner, 2, protowire.BytesType)
	inner = protowire.AppendString(inner, "HASH")
	inner = protowire.AppendTag(inner, 4, protowire.VarintType)
	inner = protowire.AppendVarint(inner, 32)
	inner = protowire.AppendTag(inner, 6, protowire.BytesType)
	inner = protowire.AppendString(inner, "bad sequence")
	var outer []byte
	outer = protowire.AppendTag(outer, 1, protowire.BytesType)
	outer = protowire.AppendBytes(outer, inner)

	got, err := DecodeBroadcastTxResponse(outer)
	if err != nil || got.TxHash != "HASH" || got.Code != 32 || got.RawLog != "bad sequence" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := DecodeBroadcastTxResponse(nil); err == nil {
		t.Fatal("an empty response must be an error")
	}
	if _, err := DecodeBroadcastTxResponse([]byte{0x0a, 0xff}); err == nil {
		t.Fatal("a truncated response must be an error")
	}
}

func TestDecodeAccountNumber(t *testing.T) {
	var info []byte
	info = protowire.AppendTag(info, 3, protowire.VarintType)
	info = protowire.AppendVarint(info, 99)
	var outer []byte
	outer = protowire.AppendTag(outer, 1, protowire.BytesType)
	outer = protowire.AppendBytes(outer, info)
	if n, err := DecodeAccountNumber(outer); err != nil || n != 99 {
		t.Fatalf("%d %v", n, err)
	}
	if _, err := DecodeAccountNumber(nil); err == nil {
		t.Fatal("a missing account must be an error")
	}
}
