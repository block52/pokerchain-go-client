package chain

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/block52/pokerchain-go-client/keys"
	"github.com/block52/pokerchain-go-client/wire"
)

// Runs against a real node. Start a local pokerchain devnet, fund the address printed by
// TestDevnetAddress (the golden-vector test key), and run:
//
//	SIGNER_TEST_NODE=127.0.0.1:9090 go test ./internal/chain -run Devnet -v
//
// Skipped without SIGNER_TEST_NODE, so `go test ./...` needs no chain.
func devnetKey(t *testing.T) (*secp256k1.PrivateKey, string, string) {
	t.Helper()
	node := os.Getenv("SIGNER_TEST_NODE")
	if node == "" {
		t.Skip("SIGNER_TEST_NODE not set")
	}
	g := loadGolden(t)
	raw, _ := hex.DecodeString(g.Privkey)
	priv := secp256k1.PrivKeyFromBytes(raw)
	addr, _ := keys.Address("b52", priv.PubKey().SerializeCompressed())
	return priv, addr, node
}

func TestDevnetAddress(t *testing.T) {
	_, addr, _ := devnetKey(t)
	t.Logf("fund this address on the devnet: %s", addr)
}

// Forty warm containers serving the same player in the same millisecond. The chain's unordered nonce is the
// exact timeout (nanoseconds) per signer, so equal timeouts collide and the second transaction is refused.
func TestDevnetTwoContainersSameInstant(t *testing.T) {
	priv, addr, node := devnetKey(t)
	instant := time.Now()

	const containers = 40
	var wg sync.WaitGroup
	results := make([]error, containers)
	for i := range results {
		c := New(node, "pokerchain", false) // each Client is one container's in-memory state
		c.now = func() time.Time { return instant }
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			// different games, so the transactions differ and only the nonce can collide
			game := "0x" + strings.Repeat(fmt.Sprintf("%02x", i), 32)
			n, err := c.AccountNumber(ctx, addr)
			if err != nil {
				results[i] = err
				return
			}
			_, results[i] = c.Broadcast(ctx, priv, addr, n, wire.LeaveGame(addr, game))
		}(i)
	}
	wg.Wait()
	for i, err := range results {
		if err != nil {
			t.Errorf("container %d: %v", i, err)
		}
	}
}
