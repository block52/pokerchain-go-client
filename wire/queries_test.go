package wire

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestBalanceRequestRoundTrip(t *testing.T) {
	b := BalanceRequest("b52addr", "usdc")
	var addr, denom string
	if err := walk(b, func(num protowire.Number, typ protowire.Type, v []byte, _ uint64) {
		switch num {
		case 1:
			addr = string(v)
		case 2:
			denom = string(v)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if addr != "b52addr" || denom != "usdc" {
		t.Fatalf("got address=%q denom=%q", addr, denom)
	}
}

func TestDecodeBalance(t *testing.T) {
	// QueryBalanceResponse{ balance: Coin{ denom:"usdc", amount:"12345" } }
	var coin []byte
	coin = protowire.AppendTag(coin, 1, protowire.BytesType)
	coin = protowire.AppendString(coin, "usdc")
	coin = protowire.AppendTag(coin, 2, protowire.BytesType)
	coin = protowire.AppendString(coin, "12345")
	var resp []byte
	resp = protowire.AppendTag(resp, 1, protowire.BytesType)
	resp = protowire.AppendBytes(resp, coin)

	c, err := DecodeBalance(resp)
	if err != nil {
		t.Fatal(err)
	}
	if c.Denom != "usdc" || c.Amount != "12345" {
		t.Fatalf("got %+v", c)
	}
}

func TestDecodeBalanceAbsentCoinIsZeroValue(t *testing.T) {
	c, err := DecodeBalance(nil) // no balance field (a zero balance)
	if err != nil {
		t.Fatal(err)
	}
	if c.Denom != "" || c.Amount != "" {
		t.Fatalf("want zero Coin, got %+v", c)
	}
}

func TestDecodeJSONStringResponses(t *testing.T) {
	// Each of these responses carries its JSON in string field 1.
	mk := func(s string) []byte {
		var b []byte
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendString(b, s)
		return b
	}
	for _, tc := range []struct {
		name   string
		decode func([]byte) (string, error)
		json   string
	}{
		{"list games", DecodeListGames, `[{"id":"0x1"}]`},
		{"game state", DecodeGameStatePublic, `{"round":"preflop"}`},
		{"player games", DecodePlayerGames, `["0x1","0x2"]`},
	} {
		got, err := tc.decode(mk(tc.json))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.json {
			t.Fatalf("%s: got %q want %q", tc.name, got, tc.json)
		}
	}
}

func TestDecodeJSONStringResponseAbsentIsEmpty(t *testing.T) {
	got, err := DecodeListGames(nil)
	if err != nil || got != "" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestRequestEncoders(t *testing.T) {
	if ListGamesRequest() != nil {
		t.Fatal("ListGamesRequest should be empty")
	}
	readString := func(b []byte) string {
		var s string
		_ = walk(b, func(num protowire.Number, typ protowire.Type, v []byte, _ uint64) {
			if num == 1 {
				s = string(v)
			}
		})
		return s
	}
	if s := readString(GameStatePublicRequest("0xabc")); s != "0xabc" {
		t.Fatalf("game id %q", s)
	}
	if s := readString(PlayerGamesRequest("b52me")); s != "b52me" {
		t.Fatalf("player %q", s)
	}
}
