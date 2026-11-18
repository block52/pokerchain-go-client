package chain

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/block52/pokerchain-go-client/keys"
	"github.com/block52/pokerchain-go-client/wire"
)

// orderedNode serves AccountInfo (with a sequence) and BroadcastTx, capturing
// the broadcast tx so the test can confirm it is an ordered (sequence-bearing)
// transaction.
type orderedNode struct {
	sequence       uint64
	lastTx         []byte
	broadcastCalls int
	rejectCode     uint32
}

func (f *orderedNode) handler(_ any, stream grpc.ServerStream) error {
	method, _ := grpc.MethodFromServerStream(stream)
	var in []byte
	if err := stream.RecvMsg(&in); err != nil {
		return err
	}
	switch method {
	case "/cosmos.auth.v1beta1.Query/AccountInfo":
		var base []byte
		base = protowire.AppendTag(base, 3, protowire.VarintType) // account_number = 42
		base = protowire.AppendVarint(base, 42)
		base = protowire.AppendTag(base, 4, protowire.VarintType) // sequence
		base = protowire.AppendVarint(base, f.sequence)
		var out []byte
		out = protowire.AppendTag(out, 1, protowire.BytesType)
		out = protowire.AppendBytes(out, base)
		return stream.SendMsg(out)
	case "/cosmos.tx.v1beta1.Service/BroadcastTx":
		f.broadcastCalls++
		// field 1 of BroadcastTxRequest is tx_bytes
		b := in
		for len(b) > 0 {
			num, typ, n := protowire.ConsumeTag(b)
			b = b[n:]
			if num == 1 && typ == protowire.BytesType {
				v, n := protowire.ConsumeBytes(b)
				f.lastTx, b = v, b[n:]
			} else {
				b = b[protowire.ConsumeFieldValue(num, typ, b):]
			}
		}
		var resp []byte
		resp = protowire.AppendTag(resp, 2, protowire.BytesType)
		resp = protowire.AppendString(resp, "HASHSEQ")
		if f.rejectCode != 0 {
			resp = protowire.AppendTag(resp, 4, protowire.VarintType)
			resp = protowire.AppendVarint(resp, uint64(f.rejectCode))
			resp = protowire.AppendTag(resp, 6, protowire.BytesType)
			resp = protowire.AppendString(resp, "account sequence mismatch")
		}
		var out []byte
		out = protowire.AppendTag(out, 1, protowire.BytesType)
		out = protowire.AppendBytes(out, resp)
		return stream.SendMsg(out)
	}
	return grpc.ErrServerStopped
}

func startOrdered(t *testing.T, f *orderedNode) string {
	t.Helper()
	srv := grpc.NewServer(grpc.UnknownServiceHandler(f.handler), grpc.ForceServerCodecV2(rawCodec{}))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

func orderedKey() (*secp256k1.PrivateKey, string) {
	priv := secp256k1.PrivKeyFromBytes([]byte("0123456789abcdef0123456789abcdef"))
	addr, _ := keys.Address("b52", priv.PubKey().SerializeCompressed())
	return priv, addr
}

func TestBroadcastOrderedSignsWithSequence(t *testing.T) {
	node := &orderedNode{sequence: 5}
	c := New(startOrdered(t, node), "pokerchain", false)
	priv, addr := orderedKey()
	game := "0x" + strings.Repeat("ab", 32)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hash, err := c.BroadcastOrdered(ctx, priv, addr, wire.PerformAction(addr, game, "call", 0, ""))
	if err != nil || hash != "HASHSEQ" {
		t.Fatalf("hash %q err %v", hash, err)
	}
	if node.broadcastCalls != 1 || len(node.lastTx) == 0 {
		t.Fatalf("broadcast calls %d, tx len %d", node.broadcastCalls, len(node.lastTx))
	}
	// The broadcast tx's AuthInfo must carry sequence 5.
	authInfo := txRawAuthInfo(t, node.lastTx)
	if seq := signerSequence(t, authInfo); seq != 5 {
		t.Fatalf("broadcast tx signed with sequence %d, want 5", seq)
	}
}

func TestBroadcastOrderedSurfacesSequenceMismatch(t *testing.T) {
	node := &orderedNode{sequence: 5, rejectCode: 32}
	c := New(startOrdered(t, node), "pokerchain", false)
	priv, addr := orderedKey()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := c.BroadcastOrdered(ctx, priv, addr, wire.PerformAction(addr, "0x"+strings.Repeat("ab", 32), "call", 0, ""))
	if !IsRejected(err) || !IsSequenceMismatch(err) {
		t.Fatalf("expected a sequence-mismatch rejection, got %v", err)
	}
}

// txRawAuthInfo pulls field 2 (auth_info_bytes) out of a TxRaw.
func txRawAuthInfo(t *testing.T, tx []byte) []byte {
	t.Helper()
	var auth []byte
	b := tx
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		b = b[n:]
		if num == 2 && typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(b)
			auth, b = v, b[n:]
		} else {
			b = b[protowire.ConsumeFieldValue(num, typ, b):]
		}
	}
	return auth
}

// signerSequence reads field 3 of the first SignerInfo in an AuthInfo.
func signerSequence(t *testing.T, authInfo []byte) uint64 {
	t.Helper()
	var signer []byte
	b := authInfo
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		b = b[n:]
		if num == 1 && typ == protowire.BytesType && signer == nil {
			v, n := protowire.ConsumeBytes(b)
			signer, b = v, b[n:]
		} else {
			b = b[protowire.ConsumeFieldValue(num, typ, b):]
		}
	}
	var seq uint64
	s := signer
	for len(s) > 0 {
		num, typ, n := protowire.ConsumeTag(s)
		s = s[n:]
		if num == 3 && typ == protowire.VarintType {
			v, n := protowire.ConsumeVarint(s)
			seq, s = v, s[n:]
		} else {
			s = s[protowire.ConsumeFieldValue(num, typ, s):]
		}
	}
	return seq
}
