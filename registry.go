package locket

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

/*
Registry is the process by which pre-computed signing keys (ed25519)
are created before deploying either server or client.
	- Public signing keys for all allowed services are provided to the server via .yml
	- Public and private keys are provided to the client for signing requests.
	- Separately, both client and server create encryption keys on startup.
*/

// RegEntry is a single registry item,
// representing a single client which
// the server should recognize and authorize
type RegEntry struct {
	Name   string `yaml:"name"`
	KeyPub string `yaml:"keypub"`
}

// WriteRegistry creates a yaml file with a registry of allowed clients.
func WriteRegistry(path string, data []RegEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}

	for i, item := range data {
		data[i].Name = strings.TrimSuffix(filepath.Base(item.Name), ".env")
	}

	b, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	_, err = f.Write(b)
	if err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	return nil
}

// ReadRegistryFile turns a yaml file into a list of RegEntry
// for use in server authenticating client requests.
func ReadRegistryFile(filepath string) ([]RegEntry, error) {
	f, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	var out []RegEntry
	err = yaml.Unmarshal(f, &out)
	if err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return out, nil
}

// UnmarshalRegistry turns a byte slice into a list of RegEntry
// for use in server authenticating client requests.
// Bytes format easier for embed.FS
func UnmarshalRegistry(bytes []byte) ([]RegEntry, error) {
	var out []RegEntry
	err := yaml.Unmarshal(bytes, &out)
	if err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return out, nil
}

// Register reads the existing registry file, upserts service key, and rewrites.
// If the registry file does not exist, it will be created.
// If no registry for the named service exists, a new entry will be created.
// An existing entry for the named service will be updated with new public key.
// Each new call of Register will generate new key pair, returning:
// public key, private key, or any error.
func Register(name string, registryPath string) (string, string, error) {
	publicKey, privateKey, err := NewPairEd25519()
	if err != nil {
		return "", "", fmt.Errorf("generate key pair: %w", err)
	}

	var registry []RegEntry
	_, err = os.Stat(registryPath)
	if err == nil {
		registry, err = ReadRegistryFile(registryPath)
		if err != nil {
			return "", "", fmt.Errorf("read registry file: %w", err)
		}
	} else {
		log.Debug(
			"registry file does not exist (or other err); will create new one",
			"registryPath", registryPath,
			"statError", err,
		)
	}

	// check if the service already exists in the registry
	replaced := false
	for i, entry := range registry {
		if entry.Name == name {
			log.Debug("updating existing service in registry",
				"service", name,
				"publicKey", publicKey,
			)
			registry[i].KeyPub = publicKey
			replaced = true
		}
	}
	if !replaced {
		log.Debug("adding new service to registry",
			"service", name,
			"publicKey", publicKey,
		)
		registry = append(registry, RegEntry{
			Name:   name,
			KeyPub: publicKey,
		})
	}

	// write the updated registry
	err = WriteRegistry(registryPath, registry)
	if err != nil {
		return "", "", fmt.Errorf("write updated registry: %w", err)
	}
	return publicKey, privateKey, nil
}
