# pokerchain-go-client

A small, dependency-light Go client for the [Block52](https://block52.xyz) **pokerchain** node.
It talks gRPC to the node with raw protobuf bytes — no generated chain types, no cosmos-sdk —
so it stays tiny and embeddable (a DigitalOcean Function, a CLI, or a Wails desktop core).

Three packages:

| Package | What it does |
|---------|--------------|
| [`chain`](./chain) | Builds, signs and broadcasts one **unordered** gameplay transaction over gRPC (`SIGN_MODE_DIRECT`, gas 250k, no fee). Looks up an account number. Mirrors the TS SDK's `performActionSync` (poker-vm#2619) and pokerchain's `cmd/perform-action`. |
| [`wire`](./wire) | Hand-rolled protobuf encode/decode for the handful of messages used (`MsgPerformAction`, `MsgJoinGame`, `MsgLeaveGame`, `MsgTopUp`, `AccountInfo`, `BroadcastTx`). Every encoder is checked byte-for-byte against cosmos-sdk's own output by golden vectors in `wire/testdata`. |
| [`keys`](./keys) | secp256k1 key generation, bech32 address derivation (`Address`), transaction signing (`Sign64`), EIP-191 personal-sign (`PersonalSign`), and an optional KEK-sealed keystore (`Vault`) for custodial use. |

## Install

```bash
go get github.com/block52/pokerchain-go-client
```

## Use

```go
import (
    "github.com/block52/pokerchain-go-client/chain"
    "github.com/block52/pokerchain-go-client/keys"
)

c := chain.New("127.0.0.1:9090", "pokerchain-1", false /* useTLS */)
num, err := c.AccountNumber(ctx, addr)          // gRPC read
txHash, err := c.Broadcast(ctx, priv, addr, num, msgAny) // sign + broadcast
```

## Test

```bash
go test ./...                                   # no chain needed (fake gRPC node + golden vectors)
SIGNER_TEST_NODE=127.0.0.1:9090 go test ./chain -run Devnet -v   # against a real devnet
```

## Provenance & scope

Extracted from the Block52 club signer (which Block52 authored) so the chain client can be
shared across the club backend and the desktop app instead of living in one repo. Some package
doc comments still describe the original signer/DigitalOcean-Function context — the behaviour is
unchanged and golden-tested; the prose will be generalised over time.

Transaction scope is deliberately narrow — the four gameplay messages above and a query-auth
signature. There is no generic "sign anything"; withdrawals, bank sends and bridge messages are
out of scope by construction.

## License

[MIT](./LICENSE)
