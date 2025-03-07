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

var (
	// ClientSigningPubkey is the environment variable name for
	// the client's signing public key. The sever should already have this
	// via side channel before the client makes a request, and uses this
	// to verify the authenticity of the requestor.
	// In testing, this is set to the client's signing public key.
	ClientSigningPubkey = "LOCKET_CLIENT_PUBKEY_SIGNING"
)

// Client makes reqeuests to a locket server, and must know the server address.
// serverPubkey is the server's encryption public key, and will be fetched
// on creation of NewClient().
// Rsa and Ed25519 key pairs are also generated on creation of NewClient().
type Client struct {
	serverAddress     string // server URL
	serverPubkey      string // server encryption public key
	keyRsaPublic      string // encryption public key
	keyRsaPrivate     string // encryption private key
	keyEd25519Public  string // signing public key
	keyEd25519Private string // signing private key
}

// kvRequest is the request format for the client to send to the server.
type kvRequest struct {
	Payload          string `json:"payload"`       // key for which cilent requests a value
	PayloadSignature string `json:"signature"`     // ed25519 signature of payload
	ClientPubKey     string `json:"client_pubkey"` // public key used to encrypt payload
}

// NewClient creates a new client, fetches the server's encryption public key,
// and generates RSA and Ed25519 key pairs for future requests.
func NewClient(serverURL, keyPub, keyPriv string) (*Client, error) {
	rsaPublic, rsaPrivate, err := newPairRSA(Defaults.BitsizeRSA)
	if err != nil {
		return nil, fmt.Errorf("generate key pair (RSA): %w", err)
	}
	client := Client{
		serverAddress:     serverURL,
		keyRsaPublic:      rsaPublic,
		keyRsaPrivate:     rsaPrivate,
		keyEd25519Public:  keyPub,
		keyEd25519Private: keyPriv,
	}
	client.serverAddress = serverURL
	client.keyEd25519Public = keyPub
	client.keyEd25519Private = keyPriv
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

// fetchServerPubkey fetches the server's encryption public key.
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

// fetchSecret produces an ecrypted and signed request to the server,
// containing the name of the secret to fetch and the client's own public key
// (to be used for encrypting the response).
func (c *Client) fetchSecret(name string) (string, error) {
	slog.Debug("fetching secret", "name", name)
	var request kvRequest
	cypher, err := encryptRSA(c.serverPubkey, name)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	request.Payload = cypher
	request.ClientPubKey = c.keyRsaPublic
	sig, err := signEd25519(c.keyEd25519Private, name)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	request.PayloadSignature = sig
	jsonRequest, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}

	slog.Debug("sending request",
		"name", name,
		"payload", string(jsonRequest),
		"url", c.serverAddress,
	)
	req, err := http.NewRequest(
		http.MethodPost,
		c.serverAddress,
		bytes.NewReader(jsonRequest),
	)
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
	slog.Debug("fetched secret", "name", name)
	return plaintext, nil
}
