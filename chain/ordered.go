package chain

import (
	"context"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/block52/pokerchain-go-client/keys"
	"github.com/block52/pokerchain-go-client/wire"
)

// Ordered (account-sequence) signing — byte-for-byte parity with the TypeScript
// SDK's performActionSync, which uses the classic cosmos account-sequence model
// rather than the unordered one Build/Broadcast use. The desktop app routes its
// game actions here so the on-chain behaviour (and the code-32 sequence-retry
// handling the caller already does) is unchanged.

// sequenceMismatchCode is the cosmos ABCI error for an unexpected account
// sequence (sdkerrors.ErrWrongSequence).
const sequenceMismatchCode = 32

// IsSequenceMismatch reports whether err is a cosmos account-sequence mismatch
// (code 32): a prior tx from this account is still pending, so the sequence we
// signed is stale. The caller clears any cached sequence, waits, and retries.
func IsSequenceMismatch(err error) bool {
	var r *ErrRejected
	if errors.As(err, &r) {
		return r.Code == sequenceMismatchCode
	}
	return false
}

// accountInfo returns the account number and current sequence over gRPC.
func (c *Client) accountInfo(ctx context.Context, address string) (number, sequence uint64, err error) {
	conn, err := c.connect()
	if err != nil {
		return 0, 0, err
	}
	var res []byte
	if err := conn.Invoke(ctx, "/cosmos.auth.v1beta1.Query/AccountInfo", wire.AccountInfoRequest(address), &res); err != nil {
		if status.Code(err) == codes.NotFound {
			return 0, 0, ErrNoAccount
		}
		return 0, 0, fmt.Errorf("account info: %w", err)
	}
	number, sequence, err = wire.DecodeAccountNumberAndSequence(res)
	if err != nil {
		return 0, 0, fmt.Errorf("account info: %w", err)
	}
	return number, sequence, nil
}

// BuildOrdered returns the signed TxRaw bytes for one message as an ordered
// (account-sequence) transaction. Pure: no network, so it is golden-testable.
func BuildOrdered(priv *secp256k1.PrivateKey, chainID string, accountNumber, sequence uint64, msgAny []byte) []byte {
	body := wire.TxBodyOrdered(msgAny)
	authInfo := wire.AuthInfoSeq(priv.PubKey().SerializeCompressed(), gasLimit, sequence)
	signature := keys.Sign64(priv, wire.SignDoc(body, authInfo, chainID, accountNumber))
	return wire.TxRaw(body, authInfo, signature)
}

// BroadcastOrdered looks up the account number and sequence, signs an ordered
// transaction and broadcasts it. On a chain rejection it returns an *ErrRejected
// (check IsSequenceMismatch / IsRejected); it does NOT retry — the caller owns
// the sequence-mismatch retry policy.
func (c *Client) BroadcastOrdered(ctx context.Context, priv *secp256k1.PrivateKey, address string, msgAny []byte) (string, error) {
	number, sequence, err := c.accountInfo(ctx, address)
	if err != nil {
		return "", err
	}
	conn, err := c.connect()
	if err != nil {
		return "", err
	}
	tx := BuildOrdered(priv, c.chainID, number, sequence, msgAny)
	var res []byte
	if err := conn.Invoke(ctx, "/cosmos.tx.v1beta1.Service/BroadcastTx", wire.BroadcastTxRequest(tx), &res); err != nil {
		return "", fmt.Errorf("broadcast: %w", err)
	}
	out, err := wire.DecodeBroadcastTxResponse(res)
	if err != nil {
		return "", fmt.Errorf("broadcast: %w", err)
	}
	if out.Code == 0 {
		return out.TxHash, nil
	}
	return out.TxHash, &ErrRejected{Code: out.Code, Log: out.RawLog, TxHash: out.TxHash}
}
