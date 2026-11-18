package chain

import (
	"context"
	"fmt"

	"github.com/block52/pokerchain-go-client/wire"
)

// Read queries against the node. These are public reads (no signature), unlike
// the signed GameState query; they are what a lobby or a spectator view needs.

// Balance returns the amount of denom held by address, as an integer decimal
// string (micro-denomination). A zero balance returns "0".
func (c *Client) Balance(ctx context.Context, address, denom string) (string, error) {
	conn, err := c.connect()
	if err != nil {
		return "", err
	}
	var res []byte
	if err := conn.Invoke(ctx, "/cosmos.bank.v1beta1.Query/Balance", wire.BalanceRequest(address, denom), &res); err != nil {
		return "", fmt.Errorf("balance: %w", err)
	}
	coin, err := wire.DecodeBalance(res)
	if err != nil {
		return "", fmt.Errorf("balance: %w", err)
	}
	if coin.Amount == "" {
		return "0", nil
	}
	return coin.Amount, nil
}

// ListGames returns the node's games as the JSON string the chain emits.
func (c *Client) ListGames(ctx context.Context) (string, error) {
	conn, err := c.connect()
	if err != nil {
		return "", err
	}
	var res []byte
	if err := conn.Invoke(ctx, "/pokerchain.poker.v1.Query/ListGames", wire.ListGamesRequest(), &res); err != nil {
		return "", fmt.Errorf("list games: %w", err)
	}
	games, err := wire.DecodeListGames(res)
	if err != nil {
		return "", fmt.Errorf("list games: %w", err)
	}
	return games, nil
}

// GameState returns the public state of a table as the JSON string the chain
// emits. This is the unsigned, public projection (hole cards hidden); the
// signed, per-player view is a separate query the signer owns.
func (c *Client) GameState(ctx context.Context, gameID string) (string, error) {
	conn, err := c.connect()
	if err != nil {
		return "", err
	}
	var res []byte
	if err := conn.Invoke(ctx, "/pokerchain.poker.v1.Query/GameStatePublic", wire.GameStatePublicRequest(gameID), &res); err != nil {
		return "", fmt.Errorf("game state: %w", err)
	}
	state, err := wire.DecodeGameStatePublic(res)
	if err != nil {
		return "", fmt.Errorf("game state: %w", err)
	}
	return state, nil
}

// PlayerGames returns the games a player is in, as the JSON string the chain emits.
func (c *Client) PlayerGames(ctx context.Context, playerAddress string) (string, error) {
	conn, err := c.connect()
	if err != nil {
		return "", err
	}
	var res []byte
	if err := conn.Invoke(ctx, "/pokerchain.poker.v1.Query/PlayerGames", wire.PlayerGamesRequest(playerAddress), &res); err != nil {
		return "", fmt.Errorf("player games: %w", err)
	}
	games, err := wire.DecodePlayerGames(res)
	if err != nil {
		return "", fmt.Errorf("player games: %w", err)
	}
	return games, nil
}
