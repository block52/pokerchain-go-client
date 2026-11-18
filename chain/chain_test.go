package chain

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/block52/pokerchain-go-client/keys"
	"github.com/block52/pokerchain-go-client/wire"
)

type golden struct {
	Player        string `json:"player"`
	Game          string `json:"game"`
	Pubkey        string `json:"pubkey"`
	Privkey       string `json:"privkey"`
	TimeoutMs     int64  `json:"timeoutMs"`
	ChainID       string `json:"chainId"`
	AccountNumber uint64 `json:"accountNumber"`
	Cases         map[string]struct {
		SignBytes string `json:"signBytes"`
		Signature string `json:"signature"`
		Tx        string `json:"tx"`
	} `json:"cases"`
}

func loadGolden(t *testing.T) golden {
	t.Helper()
	raw, err := os.ReadFile("../wire/testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

// The vectors were produced by cosmos-sdk v0.53.6's own tx builder, signer and encoder
// (see testdata/README.md). Byte equality proves the hand-written encoders and the
// signing path match what the chain verifies.
func TestBuildMatchesCosmosSDK(t *testing.T) {
	g := loadGolden(t)
	keyBytes, _ := hex.DecodeString(g.Privkey)
	priv := secp256k1.PrivKeyFromBytes(keyBytes)

	if got := hex.EncodeToString(priv.PubKey().SerializeCompressed()); got != g.Pubkey {
		t.Fatalf("pubkey %s, want %s", got, g.Pubkey)
	}
	if addr, err := keys.Address("b52", priv.PubKey().SerializeCompressed()); err != nil || addr != g.Player {
		t.Fatalf("address %q (%v), want %q", addr, err, g.Player)
	}

	msgs := map[string][]byte{
		"performAction": wire.PerformAction(g.Player, g.Game, "raise", 1500000, "method=post-now"),
		"performCall":   wire.PerformAction(g.Player, g.Game, "call", 0, ""),
		"join":          wire.JoinGame(g.Player, g.Game, 3, 5000000),
		"leave":         wire.LeaveGame(g.Player, g.Game),
		"topUp":         wire.TopUp(g.Player, g.Game, 2000000),
	}
	for name, want := range g.Cases {
		t.Run(name, func(t *testing.T) {
			tx := Build(priv, g.ChainID, g.AccountNumber, msgs[name], time.UnixMilli(g.TimeoutMs))
			if got := hex.EncodeToString(tx); got != want.Tx {
				t.Fatalf("tx bytes differ\n got %s\nwant %s", got, want.Tx)
			}
		})
	}
}

func TestTimeoutIsSpreadAcrossTheWindowInNanoseconds(t *testing.T) {
	// The same instant, as if many containers served the same player in the same millisecond. The chain's nonce is the
	// exact timeout in nanoseconds, so the value must not be a whole millisecond (the old scheme's collision) and must spread out.
	now := time.Unix(1_800_000_000, 123_000_000)
	lo, hi := now.Add(timeoutTTL), now.Add(timeoutTTL+timeoutJitter)
	min, max := hi, lo
	wholeMs := 0
	for i := 0; i < 300; i++ {
		got := Timeout(now)
		if got.Before(lo) || !got.Before(hi) {
			t.Fatalf("timeout %v outside [%v, %v)", got, lo, hi)
		}
		if got.Before(min) {
			min = got
		}
		if got.After(max) {
			max = got
		}
		if got.Nanosecond()%1_000_000 == 0 {
			wholeMs++
		}
	}
	if max.Sub(min) < 500*time.Millisecond {
		t.Fatalf("300 timeouts spanned only %v of the 1 s window", max.Sub(min))
	}
	if wholeMs > 3 {
		t.Fatalf("%d of 300 timeouts were whole milliseconds: the nanoseconds are not random", wholeMs)
	}
	if !hi.Before(now.Add(10 * time.Minute)) {
		t.Fatal("the window must stay inside the chain's 10 minute maximum")
	}
}
