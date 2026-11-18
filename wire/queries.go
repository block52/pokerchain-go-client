package wire

import "google.golang.org/protobuf/encoding/protowire"

// Read-query request encoders and response decoders. Like the rest of this
// package these are hand-rolled against the proto field numbers and checked by
// wire_test.go, so the client needs no generated chain types.
//
// gRPC methods (pass to conn.Invoke):
//
//	/cosmos.bank.v1beta1.Query/Balance
//	/pokerchain.poker.v1.Query/ListGames
//	/pokerchain.poker.v1.Query/GameStatePublic
//	/pokerchain.poker.v1.Query/PlayerGames

// --- cosmos.bank.v1beta1 Balance ------------------------------------------

// BalanceRequest is cosmos.bank.v1beta1.QueryBalanceRequest{address, denom}.
func BalanceRequest(address, denom string) []byte {
	b := stringField(nil, 1, address)
	return stringField(b, 2, denom)
}

// Coin is cosmos.base.v1beta1.Coin.
type Coin struct {
	Denom  string
	Amount string // an integer as a decimal string (cosmossdk.io/math.Int)
}

// DecodeBalance reads QueryBalanceResponse{balance: Coin{denom, amount}}.
// A zero balance can come back as an absent coin; the zero Coin is returned then.
func DecodeBalance(b []byte) (Coin, error) {
	coinBytes, err := firstBytes(b, 1)
	if err == errNotFound {
		return Coin{}, nil
	}
	if err != nil {
		return Coin{}, err
	}
	var c Coin
	err = walk(coinBytes, func(num protowire.Number, typ protowire.Type, v []byte, _ uint64) {
		if typ != protowire.BytesType {
			return
		}
		switch num {
		case 1:
			c.Denom = string(v)
		case 2:
			c.Amount = string(v)
		}
	})
	return c, err
}

// --- pokerchain.poker.v1 read queries (responses are JSON strings) --------

// ListGamesRequest is QueryListGamesRequest{} — an empty message.
func ListGamesRequest() []byte { return nil }

// GameStatePublicRequest is QueryGameStatePublicRequest{game_id}.
func GameStatePublicRequest(gameID string) []byte { return stringField(nil, 1, gameID) }

// PlayerGamesRequest is QueryPlayerGamesRequest{player_address}.
func PlayerGamesRequest(playerAddress string) []byte { return stringField(nil, 1, playerAddress) }

// DecodeListGames reads QueryListGamesResponse{games} — a JSON string.
func DecodeListGames(b []byte) (string, error) { return firstString(b, 1) }

// DecodeGameStatePublic reads QueryGameStatePublicResponse{game_state} — a JSON string.
func DecodeGameStatePublic(b []byte) (string, error) { return firstString(b, 1) }

// DecodePlayerGames reads QueryPlayerGamesResponse{games} — a JSON string.
func DecodePlayerGames(b []byte) (string, error) { return firstString(b, 1) }

// firstString returns the string value of the first occurrence of a bytes
// field. An absent field is the empty string, which for these JSON-string
// responses means "no data" rather than an error.
func firstString(b []byte, want protowire.Number) (string, error) {
	v, err := firstBytes(b, want)
	if err == errNotFound {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return string(v), nil
}
