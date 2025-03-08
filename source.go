package locket

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// source represents a valid source for secrets.
// examples include:
//   - dotenv: e.g. *.env files
//   - env: environment variables
//   - 1password: 1password vault
type source interface {
	load() (map[string]string, error)
}

type env struct{}

// load k=v pairs from local environment
func (e env) load() (map[string]string, error) {
	env := os.Environ()
	secrets := make(map[string]string)
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		secrets[parts[0]] = parts[1]
	}
	return secrets, nil
}

type dotenv struct {
	path string
}

// load k=v pairs from a .env file, ignoring any #comments
func (d dotenv) load() (map[string]string, error) {
	delimiter := "="
	f, err := os.Open(d.path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	secrets := make(map[string]string)
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// skip line comments
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// remove trailing comments
		if idx := strings.Index(line, " #"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		// separate key and value
		parts := strings.SplitN(line, delimiter, 2)
		if len(parts) != 2 {
			slog.Debug("skipping invalid line", "line_num", lineNum, "file", d.path)
			return nil, fmt.Errorf("invalid line: %s", line)
		}
		// strip leading and trailing quotes
		value := parts[1]
		value = strings.Trim(value, `"'`)

		secrets[parts[0]] = value
		slog.Debug("loaded secret", "name", parts[0])
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan file: %w", err)
	}

	return secrets, nil
}
