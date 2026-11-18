// Package wire encodes and decodes the few protobuf messages the signer needs
// by hand, with google.golang.org/protobuf/encoding/protowire.
//
// Why by hand: a DigitalOcean Function is built remotely (2 minute limit, 48 MB
// result), and importing the chain's Go module and cosmos-sdk pulls in a very
// large dependency tree. These messages are small and stable, and every encoder
// here is checked byte for byte against cosmos-sdk's own encoding by the golden
// vectors in testdata/ (see wire_test.go).
//
// Proto3 rules apply: fields are written in field-number order and a field
// holding its zero value is omitted, exactly as the chain's codec does.
package wire

import (
	"errors"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	typePerformAction = "/pokerchain.poker.v1.MsgPerformAction"
	typeJoinGame      = "/pokerchain.poker.v1.MsgJoinGame"
	typeLeaveGame     = "/pokerchain.poker.v1.MsgLeaveGame"
	typeTopUp         = "/pokerchain.poker.v1.MsgTopUp"
	typeSecpPubKey    = "/cosmos.crypto.secp256k1.PubKey"

	signModeDirect = 1
)

func bytesField(b []byte, num protowire.Number, v []byte) []byte {
	if len(v) == 0 {
		return b
	}
	b = protowire.AppendTag(b, num, protowire.BytesType)
	return protowire.AppendBytes(b, v)
}

func stringField(b []byte, num protowire.Number, v string) []byte {
	return bytesField(b, num, []byte(v))
}

func varintField(b []byte, num protowire.Number, v uint64) []byte {
	if v == 0 {
		return b
	}
	b = protowire.AppendTag(b, num, protowire.VarintType)
	return protowire.AppendVarint(b, v)
}

// ---- The four poker messages, as google.protobuf.Any ----

func any(typeURL string, value []byte) []byte {
	var b []byte
	b = stringField(b, 1, typeURL)
	b = bytesField(b, 2, value)
	return b
}

// PerformAction is MsgPerformAction{player, game_id, action, amount, data} as an Any.
func PerformAction(player, gameID, action string, amount uint64, data string) []byte {
	var m []byte
	m = stringField(m, 1, player)
	m = stringField(m, 2, gameID)
	m = stringField(m, 3, action)
	m = varintField(m, 4, amount)
	m = stringField(m, 5, data)
	return any(typePerformAction, m)
}

// JoinGame is MsgJoinGame{player, game_id, seat, buy_in_amount} as an Any.
func JoinGame(player, gameID string, seat, buyIn uint64) []byte {
	var m []byte
	m = stringField(m, 1, player)
	m = stringField(m, 2, gameID)
	m = varintField(m, 3, seat)
	m = varintField(m, 4, buyIn)
	return any(typeJoinGame, m)
}

// LeaveGame is MsgLeaveGame{creator, game_id} as an Any. finishing_order is never set by a player.
func LeaveGame(player, gameID string) []byte {
	var m []byte
	m = stringField(m, 1, player)
	m = stringField(m, 2, gameID)
	return any(typeLeaveGame, m)
}

// TopUp is MsgTopUp{player, game_id, amount} as an Any.
func TopUp(player, gameID string, amount uint64) []byte {
	var m []byte
	m = stringField(m, 1, player)
	m = stringField(m, 2, gameID)
	m = varintField(m, 3, amount)
	return any(typeTopUp, m)
}

// ---- Transaction ----

func timestamp(t time.Time) []byte {
	var b []byte
	if s := t.Unix(); s != 0 {
		b = protowire.AppendTag(b, 1, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(s))
	}
	b = varintField(b, 2, uint64(t.Nanosecond()))
	return b
}

// TxBody is cosmos.tx.v1beta1.TxBody with one message, unordered=true and a timeout timestamp
// (cosmos-sdk 0.53: fields 4 and 5). msgAny is an Any from the functions above.
func TxBody(msgAny []byte, timeout time.Time) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendBytes(b, msgAny)
	b = varintField(b, 4, 1)
	b = protowire.AppendTag(b, 5, protowire.BytesType)
	b = protowire.AppendBytes(b, timestamp(timeout))
	return b
}

// AuthInfo is cosmos.tx.v1beta1.AuthInfo for one SIGN_MODE_DIRECT signer, sequence 0, an empty fee and the given gas limit.
func AuthInfo(compressedPubKey []byte, gasLimit uint64) []byte {
	key := bytesField(nil, 1, compressedPubKey)
	pub := any(typeSecpPubKey, key)

	single := varintField(nil, 1, signModeDirect)
	modeInfo := bytesField(nil, 1, single)

	var signer []byte
	signer = bytesField(signer, 1, pub)
	signer = bytesField(signer, 2, modeInfo)
	// sequence (field 3) is 0 for an unordered transaction, so it is omitted

	fee := varintField(nil, 2, gasLimit)

	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendBytes(b, signer)
	b = bytesField(b, 2, fee)
	return b
}

// SignDoc is cosmos.tx.v1beta1.SignDoc: the bytes a SIGN_MODE_DIRECT signer hashes and signs.
func SignDoc(bodyBytes, authInfoBytes []byte, chainID string, accountNumber uint64) []byte {
	var b []byte
	b = bytesField(b, 1, bodyBytes)
	b = bytesField(b, 2, authInfoBytes)
	b = stringField(b, 3, chainID)
	b = varintField(b, 4, accountNumber)
	return b
}

// TxRaw is cosmos.tx.v1beta1.TxRaw: what is broadcast.
func TxRaw(bodyBytes, authInfoBytes, signature []byte) []byte {
	var b []byte
	b = bytesField(b, 1, bodyBytes)
	b = bytesField(b, 2, authInfoBytes)
	b = protowire.AppendTag(b, 3, protowire.BytesType)
	b = protowire.AppendBytes(b, signature)
	return b
}

// ---- gRPC requests and responses ----

// BroadcastTxRequest is cosmos.tx.v1beta1.BroadcastTxRequest with mode BROADCAST_MODE_SYNC.
func BroadcastTxRequest(txBytes []byte) []byte {
	var b []byte
	b = bytesField(b, 1, txBytes)
	b = varintField(b, 2, 2)
	return b
}

// TxResult is the part of cosmos.base.abci.v1beta1.TxResponse the signer reports.
type TxResult struct {
	TxHash string
	Code   uint32
	RawLog string
}

// DecodeBroadcastTxResponse reads BroadcastTxResponse{tx_response{txhash, code, raw_log}}.
func DecodeBroadcastTxResponse(b []byte) (TxResult, error) {
	var out TxResult
	inner, err := firstBytes(b, 1)
	if err != nil {
		return out, err
	}
	err = walk(inner, func(num protowire.Number, typ protowire.Type, v []byte, n uint64) {
		switch {
		case num == 2 && typ == protowire.BytesType:
			out.TxHash = string(v)
		case num == 4 && typ == protowire.VarintType:
			out.Code = uint32(n)
		case num == 6 && typ == protowire.BytesType:
			out.RawLog = string(v)
		}
	})
	return out, err
}

// AccountInfoRequest is cosmos.auth.v1beta1.QueryAccountInfoRequest{address}.
func AccountInfoRequest(address string) []byte { return stringField(nil, 1, address) }

// DecodeAccountNumber reads QueryAccountInfoResponse{info{account_number}}.
func DecodeAccountNumber(b []byte) (uint64, error) {
	info, err := firstBytes(b, 1)
	if err != nil {
		return 0, err
	}
	var n uint64
	err = walk(info, func(num protowire.Number, typ protowire.Type, _ []byte, v uint64) {
		if num == 3 && typ == protowire.VarintType {
			n = v
		}
	})
	return n, err
}

var errNotFound = errors.New("wire: field not found")

func firstBytes(b []byte, want protowire.Number) ([]byte, error) {
	var found []byte
	ok := false
	if err := walk(b, func(num protowire.Number, typ protowire.Type, v []byte, _ uint64) {
		if num == want && typ == protowire.BytesType && !ok {
			found, ok = v, true
		}
	}); err != nil {
		return nil, err
	}
	if !ok {
		return nil, errNotFound
	}
	return found, nil
}

// walk calls fn for every top-level field; v is set for bytes fields, n for varints.
func walk(b []byte, fn func(num protowire.Number, typ protowire.Type, v []byte, n uint64)) error {
	for len(b) > 0 {
		num, typ, tagLen := protowire.ConsumeTag(b)
		if tagLen < 0 {
			return protowire.ParseError(tagLen)
		}
		b = b[tagLen:]
		switch typ {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(b)
			if n < 0 {
				return protowire.ParseError(n)
			}
			fn(num, typ, nil, v)
			b = b[n:]
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return protowire.ParseError(n)
			}
			fn(num, typ, v, 0)
			b = b[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return protowire.ParseError(n)
			}
			b = b[n:]
		}
	}
	return nil
}
