package lightnode

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// fakeRPC serves /status and /blockchain for a chain whose tip is `tip`.
func fakeRPC(tip *int64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/status"):
			fmt.Fprintf(w, `{"result":{"sync_info":{"latest_block_height":"%d"}}}`, *tip)
		case strings.HasPrefix(r.URL.Path, "/blockchain"):
			q, _ := url.ParseQuery(r.URL.RawQuery)
			lo, _ := strconv.ParseInt(q.Get("minHeight"), 10, 64)
			hi, _ := strconv.ParseInt(q.Get("maxHeight"), 10, 64)
			var metas []string
			for h := hi; h >= lo; h-- { // Tendermint returns newest first
				metas = append(metas, fmt.Sprintf(
					`{"block_id":{"hash":"H%d"},"header":{"height":"%d","time":"t%d","proposer_address":"P"},"num_txs":"%d"}`,
					h, h, h, h%3))
			}
			fmt.Fprintf(w, `{"result":{"block_metas":[%s]}}`, strings.Join(metas, ","))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestColdStartBackfillsCapacity(t *testing.T) {
	tip := int64(500)
	srv := fakeRPC(&tip)
	defer srv.Close()

	w := NewWindow(srv.URL, 100, srv.Client())
	if err := w.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	blocks := w.Blocks(0)
	if len(blocks) != 100 {
		t.Fatalf("cached %d blocks, want 100 (capacity)", len(blocks))
	}
	// Newest first, and the newest is the tip.
	if blocks[0].Height != 500 || blocks[99].Height != 401 {
		t.Fatalf("window is %d..%d, want 500..401", blocks[0].Height, blocks[99].Height)
	}
	if w.Latest() != 500 {
		t.Fatalf("latest %d, want 500", w.Latest())
	}
	if blocks[0].Hash != "H500" || blocks[0].NumTxs != int(500%3) {
		t.Fatalf("unexpected block %+v", blocks[0])
	}
}

func TestIncrementalRefreshAddsNewAndTrims(t *testing.T) {
	tip := int64(50)
	srv := fakeRPC(&tip)
	defer srv.Close()

	w := NewWindow(srv.URL, 30, srv.Client())
	if err := w.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := w.Blocks(0); got[0].Height != 50 || len(got) != 30 {
		t.Fatalf("initial window wrong: head %d len %d", got[0].Height, len(got))
	}

	// Chain advances; refresh should pull only the new blocks and keep capacity.
	tip = 55
	if err := w.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := w.Blocks(0)
	if got[0].Height != 55 || len(got) != 30 {
		t.Fatalf("after advance: head %d len %d, want 55 / 30", got[0].Height, len(got))
	}
	if got[29].Height != 26 {
		t.Fatalf("oldest cached %d, want 26 (trimmed to 30)", got[29].Height)
	}
}

func TestBlocksN(t *testing.T) {
	tip := int64(20)
	srv := fakeRPC(&tip)
	defer srv.Close()
	w := NewWindow(srv.URL, 50, srv.Client())
	_ = w.Refresh(context.Background())
	if n := len(w.Blocks(5)); n != 5 {
		t.Fatalf("Blocks(5) returned %d", n)
	}
	if n := len(w.Blocks(0)); n != 20 {
		t.Fatalf("Blocks(0) returned %d, want all 20", n)
	}
}

func TestNoopWhenTipUnchanged(t *testing.T) {
	tip := int64(10)
	srv := fakeRPC(&tip)
	defer srv.Close()
	w := NewWindow(srv.URL, 50, srv.Client())
	_ = w.Refresh(context.Background())
	first := w.Blocks(0)
	// No change in tip → window identical.
	_ = w.Refresh(context.Background())
	if len(w.Blocks(0)) != len(first) {
		t.Fatal("window changed with no new blocks")
	}
}
