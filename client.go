package locket

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"testing"
)

// ClientSigningPubkey is the environment variable name for
// the client's signing public key.
var ClientSigningPubkey = "LOCKET_CLIENT_PUBKEY_SIGNING"

type Client struct {
	serverAddress     string // server URL
	serverPubkey      string // server encryption public key
	keyRsaPublic      string // encryption public key
	keyRsaPrivate     string // encryption private key
	keyEd25519Public  string // signing public key
	keyEd25519Private string // signing private key
}

func NewClient(serverURL string) (*Client, error) {
	var client Client
	var err error
	client.keyRsaPublic, client.keyRsaPrivate, err = newPairRSA(2048)
	if err != nil {
		return nil, fmt.Errorf("generate key pair (RSA): %w", err)
	}
	client.keyEd25519Public, client.keyEd25519Private, err = newPairEd25519()
	if err != nil {
		return nil, fmt.Errorf("generate key pair (ed25519): %w", err)
	}
	client.serverAddress = serverURL
	err = client.fetchServerPubkey()
	if err != nil || client.serverPubkey == "" {
		return nil, fmt.Errorf("failed to fetch server pubkey: %w", err)
	}
	// TODO use another method to distribute?
	if testing.Testing() {
		err = os.Setenv(ClientSigningPubkey, client.keyEd25519Public)
		if err != nil {
			return nil, fmt.Errorf("setenv: %w", err)
		}
	}
	return &client, nil
}

// fetchServerPubkey fetches the server's encryption public key
func (c *Client) fetchServerPubkey() error {
	slog.Debug("fetching server encryption pubkey", "url", c.serverAddress)
	req, err := http.NewRequest(http.MethodGet, c.serverAddress, nil)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("not ok, status: %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	c.serverPubkey = string(b)
	return nil
}

func (c *Client) fetchSecret(name string) (string, error) {
	slog.Debug("fetching secret", "name", name)
	var request kvRequest
	cypher, err := encryptRSA(c.serverPubkey, name)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	request.Payload = cypher
	request.ClientPubKey = c.keyRsaPublic
	sig, err := signEd25519(c.keyEd25519Private, cypher)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	request.PayloadSignature = sig
	jsonRequest, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}

	url := c.serverAddress + "/kv"
	slog.Debug("sending request", "name", name, "payload", string(jsonRequest), "url", url)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(jsonRequest))
	if err != nil {
		return "", fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("post request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("not ok, status: %d", resp.StatusCode)
	}
	var response kvRequest
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	plaintext, err := decryptRSA(c.keyRsaPrivate, response.Payload)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	slog.Debug("fetched secret", "name", name, "value_len", len(plaintext))
	return plaintext, nil
}
