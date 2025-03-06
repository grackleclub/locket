package locket

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

func loadFile(filepath string) (map[string]string, error) {
	delimiter := "="
	f, err := os.Open(filepath)
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

		parts := strings.SplitN(line, delimiter, 2)
		if len(parts) != 2 {
			slog.Debug("skipping invalid line", "line_num", lineNum, "file", filepath)
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

func loadEnv() (map[string]string, error) {
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
