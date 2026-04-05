package locket

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// RemoteRegistry is a Registry backed by an HTTP API.
// URL is the base URL (e.g. "http://api:8888") to which
// PathRegistry is appended for all operations.
// Token, if set, is sent as an X-Auth-Token header.
type RemoteRegistry struct {
	URL   string
	Token string
}

// endpoint returns the full URL to the registry API.
func (r RemoteRegistry) endpoint() string {
	return r.URL + PathRegistry
}

// Entries fetches all authorized clients from the remote API.
func (r RemoteRegistry) Entries() ([]RegEntry, error) {
	req, err := http.NewRequest(
		http.MethodGet, r.endpoint(), nil,
	)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	r.setHeaders(req)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var entries []RegEntry
	err = json.NewDecoder(resp.Body).Decode(&entries)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return entries, nil
}

// Upsert creates or updates an authorized client via the remote API.
func (r RemoteRegistry) Upsert(entry RegEntry) error {
	b, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequest(
		http.MethodPost, r.endpoint(), bytes.NewReader(b),
	)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	r.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// Delete removes an authorized client by name via the remote API.
func (r RemoteRegistry) Delete(name string) error {
	b, err := json.Marshal(RegEntry{Name: name})
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequest(
		http.MethodDelete, r.endpoint(), bytes.NewReader(b),
	)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	r.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// Register generates a new ed25519 signing keypair, upserts the
// public key via the remote API, and returns the keypair.
func (r RemoteRegistry) Register(name string) (string, string, error) {
	pub, priv, err := NewPairEd25519()
	if err != nil {
		return "", "", fmt.Errorf("generate key pair: %w", err)
	}
	err = r.Upsert(RegEntry{Name: name, KeyPub: pub})
	if err != nil {
		return "", "", fmt.Errorf("upsert: %w", err)
	}
	return pub, priv, nil
}

// setHeaders applies auth headers to the request.
func (r RemoteRegistry) setHeaders(req *http.Request) {
	if r.Token != "" {
		req.Header.Set("X-Auth-Token", r.Token)
	}
}
