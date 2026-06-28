package locket

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

/*
Registry is the process by which pre-computed signing keys (ed25519)
are created before deploying either server or client.
  - Public signing keys for all allowed services are provided to the server.
  - Public and private keys are provided to the client for signing requests.
  - Separately, both client and server create encryption keys on startup.
*/

// RegEntry is a single registry item,
// representing a single client which
// the server should recognize and authorize.
type RegEntry struct {
	Name   string `yaml:"name"   json:"name"`
	KeyPub string `yaml:"keypub" json:"keypub"`
}

// Registry reads and writes authorized client entries.
// Implementations include FileRegistry (local YAML) and
// RemoteRegistry (HTTP API).
type Registry interface {
	// Entries returns all authorized clients.
	Entries() ([]RegEntry, error)
	// Upsert inserts or updates a client entry by name.
	Upsert(RegEntry) error
	// Delete removes a client entry by name.
	Delete(name string) error
}

// FileRegistry is a Registry backed by a local YAML file.
type FileRegistry struct {
	Path string
}

// Entries reads all authorized clients from the YAML file.
func (f FileRegistry) Entries() ([]RegEntry, error) {
	b, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	var out []RegEntry
	err = yaml.Unmarshal(b, &out)
	if err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return out, nil
}

// Upsert inserts or updates a client entry in the YAML file.
// If the file does not exist, it is created. The name is stored verbatim
// (exact-match, case-sensitive) to match the RemoteRegistry / cloud contract;
// derive a clean service name before calling if needed.
func (f FileRegistry) Upsert(entry RegEntry) error {
	var entries []RegEntry
	_, err := os.Stat(f.Path)
	switch {
	case err == nil:
		entries, err = f.Entries()
		if err != nil {
			return fmt.Errorf("read existing: %w", err)
		}
	case !os.IsNotExist(err):
		return fmt.Errorf("stat file: %w", err)
	}

	replaced := false
	for i, e := range entries {
		if e.Name == entry.Name {
			entries[i].KeyPub = entry.KeyPub
			replaced = true
			break
		}
	}
	if !replaced {
		entries = append(entries, entry)
	}

	return f.write(entries)
}

// Delete removes a client entry by name from the YAML file.
func (f FileRegistry) Delete(name string) error {
	entries, err := f.Entries()
	if err != nil {
		return fmt.Errorf("read existing: %w", err)
	}
	filtered := entries[:0]
	for _, e := range entries {
		if e.Name != name {
			filtered = append(filtered, e)
		}
	}
	return f.write(filtered)
}

// Register generates a new ed25519 signing keypair, upserts the
// public key into the YAML file, and returns the keypair.
func (f FileRegistry) Register(name string) (string, string, error) {
	pub, priv, err := NewPairEd25519()
	if err != nil {
		return "", "", fmt.Errorf("generate key pair: %w", err)
	}
	err = f.Upsert(RegEntry{Name: name, KeyPub: pub})
	if err != nil {
		return "", "", fmt.Errorf("upsert: %w", err)
	}
	return pub, priv, nil
}

// write serializes entries to the YAML file, creating or
// truncating it as needed.
func (f FileRegistry) write(entries []RegEntry) error {
	file, err := os.Create(f.Path)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer file.Close()

	b, err := yaml.Marshal(entries)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	_, err = file.Write(b)
	if err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	return nil
}
