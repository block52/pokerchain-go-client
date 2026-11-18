package chain

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"
)

// readNode serves the four read RPCs over real gRPC with raw bytes, so the
// client's codec, method routing and response decoding are exercised end to end.
type readNode struct {
	lastMethod  string
	lastRequest []byte
}

func (f *readNode) handler(_ any, stream grpc.ServerStream) error {
	method, _ := grpc.MethodFromServerStream(stream)
	f.lastMethod = method
	var in []byte
	if err := stream.RecvMsg(&in); err != nil {
		return err
	}
	f.lastRequest = in

	str := func(field protowire.Number, s string) []byte {
		var b []byte
		b = protowire.AppendTag(b, field, protowire.BytesType)
		b = protowire.AppendString(b, s)
		return b
	}

	switch method {
	case "/cosmos.bank.v1beta1.Query/Balance":
		var coin []byte
		coin = protowire.AppendTag(coin, 1, protowire.BytesType)
		coin = protowire.AppendString(coin, "usdc")
		coin = protowire.AppendTag(coin, 2, protowire.BytesType)
		coin = protowire.AppendString(coin, "999")
		var out []byte
		out = protowire.AppendTag(out, 1, protowire.BytesType)
		out = protowire.AppendBytes(out, coin)
		return stream.SendMsg(out)
	case "/pokerchain.poker.v1.Query/ListGames":
		return stream.SendMsg(str(1, `[{"id":"0x1"}]`))
	case "/pokerchain.poker.v1.Query/GameStatePublic":
		return stream.SendMsg(str(1, `{"round":"flop"}`))
	case "/pokerchain.poker.v1.Query/PlayerGames":
		return stream.SendMsg(str(1, `["0x1"]`))
	}
	return grpc.ErrServerStopped
}

func startReadNode(t *testing.T) (*readNode, string) {
	t.Helper()
	f := &readNode{}
	srv := grpc.NewServer(grpc.UnknownServiceHandler(f.handler), grpc.ForceServerCodecV2(rawCodec{}))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return f, lis.Addr().String()
}

func TestReadQueriesOverGRPC(t *testing.T) {
	node, target := startReadNode(t)
	c := New(target, "pokerchain", false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	amount, err := c.Balance(ctx, "b52me", "usdc")
	if err != nil || amount != "999" {
		t.Fatalf("balance %q err %v", amount, err)
	}
	if node.lastMethod != "/cosmos.bank.v1beta1.Query/Balance" {
		t.Fatalf("balance hit %s", node.lastMethod)
	}

	games, err := c.ListGames(ctx)
	if err != nil || games != `[{"id":"0x1"}]` {
		t.Fatalf("list games %q err %v", games, err)
	}

	state, err := c.GameState(ctx, "0xabc")
	if err != nil || state != `{"round":"flop"}` {
		t.Fatalf("game state %q err %v", state, err)
	}
	// the game id reached the node
	var gotID string
	_ = walkTop(node.lastRequest, func(num protowire.Number, typ protowire.Type, v []byte) {
		if num == 1 && typ == protowire.BytesType {
			gotID = string(v)
		}
	})
	if gotID != "0xabc" {
		t.Fatalf("game id sent %q", gotID)
	}

	pg, err := c.PlayerGames(ctx, "b52me")
	if err != nil || pg != `["0x1"]` {
		t.Fatalf("player games %q err %v", pg, err)
	}
}

// walkTop is a tiny top-level field reader for the test (the wire package's own
// walk is unexported).
func walkTop(b []byte, fn func(num protowire.Number, typ protowire.Type, v []byte)) error {
	for len(b) > 0 {
		num, typ, tagLen := protowire.ConsumeTag(b)
		if tagLen < 0 {
			return protowire.ParseError(tagLen)
		}
		b = b[tagLen:]
		if typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return protowire.ParseError(n)
			}
			fn(num, typ, v)
			b = b[n:]
			continue
		}
		n := protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
	}
	return nil
}
