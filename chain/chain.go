// Package chain builds, signs and broadcasts one unordered gameplay transaction.
//
// It mirrors the TypeScript SDK's performActionSync (poker-vm#2619) and
// pokerchain's cmd/perform-action: SIGN_MODE_DIRECT, gas limit 250,000, no fee, and an UNORDERED
// transaction (no account sequence; the chain de-duplicates on signer + timeout_timestamp).
// It talks to the node over gRPC with raw bytes, so it needs no generated chain types.
package chain

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/mem"
	"google.golang.org/grpc/status"

	"github.com/block52/pokerchain-go-client/keys"
	"github.com/block52/pokerchain-go-client/wire"
)

const (
	gasLimit   = 250_000
	timeoutTTL = 120 * time.Second // how far ahead timeout_timestamp is set; must be within the chain's max unordered TTL (10 minutes)
	// timeoutJitter spreads the timeout over a further second, in nanoseconds. See Timeout.
	timeoutJitter = time.Second
	// maxTimeoutRetries is how many times Broadcast retries after the chain reports a timeout collision.
	maxTimeoutRetries = 2
)

// Build returns the signed TxRaw bytes for one message. Pure: no network, so it is testable against golden vectors.
func Build(priv *secp256k1.PrivateKey, chainID string, accountNumber uint64, msgAny []byte, timeout time.Time) []byte {
	body := wire.TxBody(msgAny, timeout)
	authInfo := wire.AuthInfo(priv.PubKey().SerializeCompressed(), gasLimit)
	signature := keys.Sign64(priv, wire.SignDoc(body, authInfo, chainID, accountNumber))
	return wire.TxRaw(body, authInfo, signature)
}

// Node is the part of the chain client the service needs; tests replace it.
type Node interface {
	// AccountNumber is the account's number on the chain. It is assigned once, when the account is first seen, and never changes.
	AccountNumber(ctx context.Context, address string) (uint64, error)
	// Broadcast signs msgAny as priv's account (whose number is accountNumber) and returns the transaction hash.
	Broadcast(ctx context.Context, priv *secp256k1.PrivateKey, address string, accountNumber uint64, msgAny []byte) (string, error)
}

// ErrNoAccount means the address has no account on the chain yet: nothing has been sent to it.
var ErrNoAccount = errors.New("the address has no account on the chain yet (fund it first)")

// ErrRejected means the chain accepted the request but refused the transaction (CheckTx failed).
type ErrRejected struct {
	Code   uint32
	Log    string
	TxHash string
}

func (e *ErrRejected) Error() string {
	return fmt.Sprintf("chain rejected the transaction (code %d): %s", e.Code, e.Log)
}

// Client is the gRPC node client. Safe for concurrent use; a warm function container reuses it.
type Client struct {
	target  string
	chainID string
	useTLS  bool
	now     func() time.Time

	mu      sync.Mutex
	conn    *grpc.ClientConn
	accNums map[string]uint64 // a per-container cache; the durable copy is the signer_accounts row
}

// New does not connect; the connection is made on first use.
func New(target, chainID string, useTLS bool) *Client {
	return &Client{target: target, chainID: chainID, useTLS: useTLS, now: time.Now, accNums: map[string]uint64{}}
}

// Timeout returns the timeout_timestamp for a new unordered transaction.
//
// The chain's unordered "nonce" is the exact timeout, in nanoseconds, per signer: a second transaction from the
// same account with the same timeout is refused ("sender ... has already used timeout ..."). The TypeScript SDK
// only has millisecond clocks, so it keeps a per-process counter. That cannot work here: a function runs in
// many containers at once, and two of them serving the same player in the same millisecond would both pick the
// same value. So the timeout is the TTL plus a random offset of up to a second, in nanoseconds: no shared
// state (no Redis, no database row), and two transactions collide with probability about 1 in 10^9.
func Timeout(now time.Time) time.Time {
	return now.Add(timeoutTTL + time.Duration(rand.Int64N(int64(timeoutJitter))))
}

func (c *Client) connect() (*grpc.ClientConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn, nil
	}
	creds := insecure.NewCredentials()
	if c.useTLS {
		creds = credentials.NewTLS(nil)
	}
	conn, err := grpc.NewClient(c.target, grpc.WithTransportCredentials(creds), grpc.WithDefaultCallOptions(grpc.ForceCodecV2(rawCodec{})))
	if err != nil {
		return nil, err
	}
	c.conn = conn
	return conn, nil
}

// AccountNumber implements Node. It caches in memory; the signer also keeps the number in the account's row.
func (c *Client) AccountNumber(ctx context.Context, address string) (uint64, error) {
	c.mu.Lock()
	n, ok := c.accNums[address]
	c.mu.Unlock()
	if ok {
		return n, nil
	}
	conn, err := c.connect()
	if err != nil {
		return 0, err
	}
	var res []byte
	if err := conn.Invoke(ctx, "/cosmos.auth.v1beta1.Query/AccountInfo", wire.AccountInfoRequest(address), &res); err != nil {
		if status.Code(err) == codes.NotFound {
			return 0, ErrNoAccount
		}
		return 0, fmt.Errorf("account number: %w", err)
	}
	n, err = wire.DecodeAccountNumber(res)
	if err != nil {
		return 0, fmt.Errorf("account number: %w", err)
	}
	c.mu.Lock()
	c.accNums[address] = n
	c.mu.Unlock()
	return n, nil
}

// Broadcast implements Node.
func (c *Client) Broadcast(ctx context.Context, priv *secp256k1.PrivateKey, _ string, accountNumber uint64, msgAny []byte) (string, error) {
	conn, err := c.connect()
	if err != nil {
		return "", err
	}
	// A random timeout collides with another of this player's transactions with probability about 1 in 10^9, and the
	// chain refuses that cleanly at CheckTx. Try again with a fresh timeout instead of failing the player's action.
	for attempt := 0; ; attempt++ {
		tx := Build(priv, c.chainID, accountNumber, msgAny, Timeout(c.now()))
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
		if attempt < maxTimeoutRetries && strings.Contains(out.RawLog, "has already used timeout") {
			continue
		}
		return out.TxHash, &ErrRejected{Code: out.Code, Log: out.RawLog, TxHash: out.TxHash}
	}
}

// IsRejected reports whether err is a chain refusal.
func IsRejected(err error) bool { var r *ErrRejected; return errors.As(err, &r) }

// rawCodec passes already-encoded protobuf bytes through gRPC unchanged.
type rawCodec struct{}

func (rawCodec) Name() string { return "proto" }

func (rawCodec) Marshal(v any) (mem.BufferSlice, error) {
	b, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("rawCodec: want []byte, got %T", v)
	}
	return mem.BufferSlice{mem.SliceBuffer(b)}, nil
}

func (rawCodec) Unmarshal(data mem.BufferSlice, v any) error {
	p, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("rawCodec: want *[]byte, got %T", v)
	}
	*p = data.Materialize()
	return nil
}

var _ encoding.CodecV2 = rawCodec{}
