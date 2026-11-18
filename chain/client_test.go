package chain

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/block52/pokerchain-go-client/keys"
	"github.com/block52/pokerchain-go-client/wire"
)

// fakeNode serves the two gRPC methods the client calls, with raw bytes, so the client's codec,
// account-number cache and response decoding are exercised over a real gRPC connection.
type fakeNode struct {
	missing                      bool // AccountInfo answers NotFound
	accountCalls, broadcastCalls int
	lastTx                       []byte
	code                         uint32
	log                          string
	codeFor                      func(call int) (uint32, string) // overrides code and log per broadcast call, from 1
}

func (f *fakeNode) handler(_ any, stream grpc.ServerStream) error {
	method, _ := grpc.MethodFromServerStream(stream)
	var in []byte
	if err := stream.RecvMsg(&in); err != nil {
		return err
	}
	switch method {
	case "/cosmos.auth.v1beta1.Query/AccountInfo":
		f.accountCalls++
		if f.missing {
			return status.Error(codes.NotFound, "account not found")
		}
		var base []byte
		base = protowire.AppendTag(base, 3, protowire.VarintType) // account_number = 42
		base = protowire.AppendVarint(base, 42)
		var out []byte
		out = protowire.AppendTag(out, 1, protowire.BytesType)
		out = protowire.AppendBytes(out, base)
		return stream.SendMsg(out)
	case "/cosmos.tx.v1beta1.Service/BroadcastTx":
		f.broadcastCalls++
		var txBytes []byte
		b := in
		for len(b) > 0 {
			num, typ, n := protowire.ConsumeTag(b)
			b = b[n:]
			if num == 1 && typ == protowire.BytesType {
				v, n := protowire.ConsumeBytes(b)
				txBytes, b = v, b[n:]
			} else {
				n := protowire.ConsumeFieldValue(num, typ, b)
				b = b[n:]
			}
		}
		f.lastTx = txBytes
		code, log := f.code, f.log
		if f.codeFor != nil {
			code, log = f.codeFor(f.broadcastCalls)
		}
		var resp []byte
		resp = protowire.AppendTag(resp, 2, protowire.BytesType)
		resp = protowire.AppendString(resp, "HASH42")
		if code != 0 {
			resp = protowire.AppendTag(resp, 4, protowire.VarintType)
			resp = protowire.AppendVarint(resp, uint64(code))
			resp = protowire.AppendTag(resp, 6, protowire.BytesType)
			resp = protowire.AppendString(resp, log)
		}
		var out []byte
		out = protowire.AppendTag(out, 1, protowire.BytesType)
		out = protowire.AppendBytes(out, resp)
		return stream.SendMsg(out)
	}
	return grpc.ErrServerStopped
}

func startFake(t *testing.T) (*fakeNode, string) {
	t.Helper()
	f := &fakeNode{}
	srv := grpc.NewServer(grpc.UnknownServiceHandler(f.handler), grpc.ForceServerCodecV2(rawCodec{}))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return f, lis.Addr().String()
}

func testKey() (*secp256k1.PrivateKey, string) {
	priv := secp256k1.PrivKeyFromBytes([]byte("0123456789abcdef0123456789abcdef"))
	addr, _ := keys.Address("b52", priv.PubKey().SerializeCompressed())
	return priv, addr
}

func TestBroadcastOverGRPC(t *testing.T) {
	node, target := startFake(t)
	c := New(target, "pokerchain", false)
	priv, addr := testKey()
	game := "0x" + strings.Repeat("ab", 32)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	n, err := c.AccountNumber(ctx, addr)
	if err != nil || n != 42 {
		t.Fatalf("account number %d %v", n, err)
	}
	hash, err := c.Broadcast(ctx, priv, addr, n, wire.PerformAction(addr, game, "call", 0, ""))
	if err != nil || hash != "HASH42" {
		t.Fatalf("hash %q err %v", hash, err)
	}
	n2, _ := c.AccountNumber(ctx, addr)
	if _, err := c.Broadcast(ctx, priv, addr, n2, wire.PerformAction(addr, game, "fold", 0, "")); err != nil {
		t.Fatal(err)
	}
	if node.accountCalls != 1 {
		t.Fatalf("account number looked up %d times, want 1 (it is cached)", node.accountCalls)
	}
	if node.broadcastCalls != 2 || len(node.lastTx) == 0 {
		t.Fatalf("broadcast calls %d", node.broadcastCalls)
	}
	if len(node.lastTx) == 0 {
		t.Fatal("no transaction bytes reached the node")
	}
}

func TestBroadcastReportsAChainRejection(t *testing.T) {
	node, target := startFake(t)
	node.code, node.log = 18, "not your turn"
	c := New(target, "pokerchain", false)
	priv, addr := testKey()
	_, err := c.Broadcast(context.Background(), priv, addr, 42, wire.LeaveGame(addr, "0x"+strings.Repeat("ab", 32)))
	if !IsRejected(err) || !strings.Contains(err.Error(), "not your turn") {
		t.Fatalf("got %v", err)
	}
}

func TestAccountNumberOfAnUnfundedAddressIsErrNoAccount(t *testing.T) {
	node, target := startFake(t)
	node.missing = true
	c := New(target, "pokerchain", false)
	_, err := c.AccountNumber(context.Background(), "b521nobody")
	if !errors.Is(err, ErrNoAccount) {
		t.Fatalf("got %v", err)
	}
}

func TestBroadcastRetriesATimeoutCollisionWithAFreshTimeout(t *testing.T) {
	node, target := startFake(t)
	node.codeFor = func(call int) (uint32, string) {
		if call == 1 {
			return 18, "failed to add unordered nonce: sender b521x has already used timeout 123: invalid request"
		}
		return 0, ""
	}
	c := New(target, "pokerchain", false)
	priv, addr := testKey()
	hash, err := c.Broadcast(context.Background(), priv, addr, 42, wire.LeaveGame(addr, "0x"+strings.Repeat("ab", 32)))
	if err != nil || hash != "HASH42" {
		t.Fatalf("%q %v", hash, err)
	}
	if node.broadcastCalls != 2 {
		t.Fatalf("broadcast %d times, want 2", node.broadcastCalls)
	}

	// a collision that keeps happening is reported, after the retries
	node.broadcastCalls = 0
	node.codeFor = func(int) (uint32, string) { return 18, "sender b521x has already used timeout 9" }
	if _, err := c.Broadcast(context.Background(), priv, addr, 42, wire.LeaveGame(addr, "0x"+strings.Repeat("ab", 32))); !IsRejected(err) {
		t.Fatalf("got %v", err)
	}
	if node.broadcastCalls != 1+maxTimeoutRetries {
		t.Fatalf("broadcast %d times, want %d", node.broadcastCalls, 1+maxTimeoutRetries)
	}
}

func TestBroadcastUnreachableNodeIsNotARejection(t *testing.T) {
	c := New("127.0.0.1:1", "pokerchain", false)
	priv, addr := testKey()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := c.Broadcast(ctx, priv, addr, 42, wire.LeaveGame(addr, "g"))
	if err == nil || IsRejected(err) {
		t.Fatalf("want a transport error, got %v", err)
	}
}
