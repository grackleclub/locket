package locket

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// regEntry is a single registry item,
// representing a single client which
// the server should recognize and authorize
type regEntry struct {
	Name   string `yaml:"name"`
	Ip     string `yaml:"ip"`
	KeyPub string `yaml:"keypub"`
}

// WriteRegistry creates a yaml file with a registry of allowed clients:
//   - name
//   - ip
//   - public signing key (for authenticating with server)
func WriteRegistry(filepath string, data []regEntry) error {
	f, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
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

// ReadRegistry turns a yaml file into a list of registryItem
// for use in server authenticating client requests.
func ReadRegistry(filepath string) ([]regEntry, error) {
	f, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	var out []regEntry
	err = yaml.Unmarshal(f, &out)
	if err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return out, nil
}
