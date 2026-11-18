// Package lightnode keeps a rolling in-memory window of the most recent blocks
// from a pokerchain (Tendermint) node, so a client can read recent chain
// activity locally and fast instead of hitting the node per query.
//
// It polls Tendermint RPC over HTTP: /status for the latest height, then
// /blockchain?minHeight=&maxHeight= for block metadata in bulk (newest first,
// up to 20 per call). It holds block headers only — height, time, hash, proposer
// and tx count — which is enough for a recent-activity view; fetch a full block
// from the node when a detail view needs one.
package lightnode

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Block is the summary the window keeps for each recent block.
type Block struct {
	Height   int64  `json:"height"`
	Time     string `json:"time"`
	Hash     string `json:"hash"`
	Proposer string `json:"proposer"`
	NumTxs   int    `json:"numTxs"`
}

// Window is a rolling, newest-first cache of the last Capacity blocks.
type Window struct {
	rpc      string
	capacity int
	client   *http.Client

	mu     sync.RWMutex
	blocks []Block // newest first
	latest int64
}

// NewWindow caches the last `capacity` blocks from the Tendermint RPC endpoint
// (e.g. https://node1.block52.xyz/rpc/). capacity <= 0 defaults to 1000.
func NewWindow(rpcEndpoint string, capacity int, client *http.Client) *Window {
	if capacity <= 0 {
		capacity = 1000
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &Window{rpc: strings.TrimRight(rpcEndpoint, "/"), capacity: capacity, client: client}
}

// Blocks returns up to n of the most recent cached blocks, newest first
// (all of them when n <= 0 or n exceeds the cache).
func (w *Window) Blocks(n int) []Block {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if n <= 0 || n > len(w.blocks) {
		n = len(w.blocks)
	}
	out := make([]Block, n)
	copy(out, w.blocks[:n])
	return out
}

// Latest is the highest block height currently cached (0 if empty).
func (w *Window) Latest() int64 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.latest
}

// Refresh pulls any blocks newer than what is cached and trims to capacity.
// On the first call it backfills the whole window. Safe to call on a timer.
func (w *Window) Refresh(ctx context.Context) error {
	tip, err := w.status(ctx)
	if err != nil {
		return err
	}
	w.mu.RLock()
	have := w.latest
	w.mu.RUnlock()
	if tip == have {
		return nil
	}

	// Fetch (have, tip], or the last `capacity` on a cold start, newest first.
	from := tip - int64(w.capacity) + 1
	if have > 0 && have+1 > from {
		from = have + 1
	}
	if from < 1 {
		from = 1
	}
	fetched, err := w.fetchRange(ctx, from, tip)
	if err != nil {
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	// Merge newest-first, dedupe by height, trim to capacity.
	seen := make(map[int64]bool, len(fetched)+len(w.blocks))
	merged := make([]Block, 0, w.capacity)
	for _, b := range append(fetched, w.blocks...) {
		if seen[b.Height] {
			continue
		}
		seen[b.Height] = true
		merged = append(merged, b)
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].Height > merged[j].Height })
	if len(merged) > w.capacity {
		merged = merged[:w.capacity]
	}
	w.blocks = merged
	if len(merged) > 0 {
		w.latest = merged[0].Height
	}
	return nil
}

// --- Tendermint RPC ---

func (w *Window) status(ctx context.Context) (int64, error) {
	var out struct {
		Result struct {
			SyncInfo struct {
				LatestBlockHeight string `json:"latest_block_height"`
			} `json:"sync_info"`
		} `json:"result"`
	}
	if err := w.get(ctx, "/status", &out); err != nil {
		return 0, err
	}
	return strconv.ParseInt(out.Result.SyncInfo.LatestBlockHeight, 10, 64)
}

// fetchRange pulls [from, to] via /blockchain (max 20 per call, newest first).
func (w *Window) fetchRange(ctx context.Context, from, to int64) ([]Block, error) {
	var all []Block
	for hi := to; hi >= from; hi -= 20 {
		lo := hi - 19
		if lo < from {
			lo = from
		}
		var out struct {
			Result struct {
				BlockMetas []struct {
					BlockID struct {
						Hash string `json:"hash"`
					} `json:"block_id"`
					Header struct {
						Height          string `json:"height"`
						Time            string `json:"time"`
						ProposerAddress string `json:"proposer_address"`
					} `json:"header"`
					NumTxs string `json:"num_txs"`
				} `json:"block_metas"`
			} `json:"result"`
		}
		path := fmt.Sprintf("/blockchain?minHeight=%d&maxHeight=%d", lo, hi)
		if err := w.get(ctx, path, &out); err != nil {
			return nil, err
		}
		for _, m := range out.Result.BlockMetas {
			height, _ := strconv.ParseInt(m.Header.Height, 10, 64)
			numTxs, _ := strconv.Atoi(m.NumTxs)
			all = append(all, Block{
				Height:   height,
				Time:     m.Header.Time,
				Hash:     m.BlockID.Hash,
				Proposer: m.Header.ProposerAddress,
				NumTxs:   numTxs,
			})
		}
	}
	return all, nil
}

func (w *Window) get(ctx context.Context, path string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.rpc+path, nil)
	if err != nil {
		return err
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("lightnode: %s -> HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(into)
}
