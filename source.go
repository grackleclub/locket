package locket

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"time"

	"github.com/1password/onepassword-sdk-go"
)

// 1password service account token environment variable name
var OnePasswordVar = "LOCKET_OP_SERVICE_ACCOUNT_TOKEN"

type Secrets map[string]string // all key/value secrets for a single service

// source represents a valid source for secrets.
// examples include:
//   - dotenv: service-name.env files
//   - env: environment variables
//   - onepass: 1password vault
type source interface {
	Load() (map[string]Secrets, error)
}

// Env satisfies the source interface,
// loading secrets from the local environment.
type Env struct {
	ServiceSecrets map[string][]string // service name mapped to list of service secret names
}

// Load k=v pairs from local environment.
//
// Expect environment variables to be prefixed with the service name.
// e.g. SERVICE1_FOO=bar will be interpreted as:
//   - service name: SERVICE1
//   - secret name: SERVICE1_FOO
//   - secret value: bar
func (e Env) Load() (map[string]Secrets, error) {
	environment := os.Environ()
	log.Debug("loaded all environment vars", "qty", len(environment))
	// parent has all services keyed on name (lowercase) and a secrets object.
	parent := make(map[string]Secrets)
	for _, env := range environment {
		// secrets := make(Secrets)
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			log.Warn("skipping invalid env", "env", env, "len", len(parts))
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(parts[1], `"'`)
		for serviceName, secretNames := range e.ServiceSecrets {
			// Is this secret one that's called for by the service?
			for _, name := range secretNames {
				if key == name {
					jitter := rand.Int() % 10
					log.Debug("loaded secret",
						"service", serviceName,
						"key", key,
						"value", strings.Repeat("*", len(value)+jitter),
					)
					nameLower := strings.ToLower(serviceName)
					if _, ok := parent[serviceName]; !ok {
						// if service not yet in parent, add it
						parent[nameLower] = make(Secrets)
					}
					parent[nameLower][key] = value
				}
			}
		}
	}
	return parent, nil
}

// Dotenv satisfies the source interface,
// loading secrets from a specified path to .env file.
type Dotenv struct {
	Path           string              // path to .env file to read
	ServiceSecrets map[string][]string // service names and a list of their secrets
}

// Load k=v pairs from a .env file, ignoring any #comments.
// Service name will be set by the keys in ServiceSecrets map.
func (d Dotenv) Load() (map[string]Secrets, error) {
	pwd, _ := os.Getwd()
	log.Debug("loading file", "path", d.Path, "pwd", pwd)
	f, err := os.Open(d.Path)
	if err != nil {
		return nil, fmt.Errorf("open file %q: %w", d.Path, err)
	}
	defer f.Close()

	delimiter := "="
	allSecrets := make(map[string]Secrets)
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
			log.Debug("skipping invalid line", "line_num", lineNum)
			return nil, fmt.Errorf("invalid line: %s", line)
		}
		key := parts[0]
		// strip leading and trailing quotes
		// value := parts[1]
		value := strings.ReplaceAll(parts[1], `\n`, "\n")
		value = strings.Trim(value, `"'`)

		// load only secrets specified by serviceSecrets
		for serviceName, secretsList := range d.ServiceSecrets {
			nameLower := strings.ToLower(serviceName)
			for _, secret := range secretsList {
				if key == secret {
					log.Debug("loaded secret",
						"service", nameLower,
						"key", key,
					)
					_, ok := allSecrets[nameLower]
					if !ok {
						allSecrets[nameLower] = make(Secrets)
					}
					allSecrets[nameLower][key] = value
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan file: %w", err)
	}

	return allSecrets, nil
}

// Onepass satisfies the source interface,
// loading secrets from a 1password vault over the net with 1password API.
// Service account token must be set environment as locket.OnePasswordVar.
type Onepass struct {
	Vault string // name of the vault containig service secrets
}

// Load all service secrets from a named 1password vault,
// returning a map of service names to their set of k/v secrets.
func (o Onepass) Load() (map[string]Secrets, error) {
	// load client
	ctx := context.Background()
	now := time.Now().UTC()
	token, ok := os.LookupEnv(OnePasswordVar)
	if !ok {
		return nil, fmt.Errorf("required %q not set", OnePasswordVar)
	}
	log.Debug("found token", "name", OnePasswordVar)

	client, err := onepassword.NewClient(ctx,
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo(
			onepassword.DefaultIntegrationName,
			onepassword.DefaultIntegrationVersion,
		),
	)
	if err != nil {
		return nil, fmt.Errorf("init client: %w", err)
	}
	log.Debug("client created", "elapsed", time.Since(now))

	// use the client
	allSecrets := make(map[string]Secrets)
	start := time.Now().UTC()
	vault, err := client.VaultsAPI.ListAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("list vaults: %w", err)
	}
	var found bool
	for {
		vlt, err := vault.Next()
		if errors.Is(err, onepassword.ErrorIteratorDone) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("iterate vaults: %w", err)
		}
		if vlt.Title == o.Vault {
			log.Debug("loading selected vault", "id", vlt.ID, "title", vlt.Title)
			found = true
			services, err := client.ItemsAPI.ListAll(ctx, vlt.ID)
			if err != nil {
				return nil, fmt.Errorf("list items: %w", err)
			}
			for {
				serviceSecrects := make(Secrets)
				service, err := services.Next()
				if err != nil {
					if errors.Is(err, onepassword.ErrorIteratorDone) {
						break
					} else {
						return nil, fmt.Errorf("iterate items: %w", err)
					}
				}
				log.Debug("loading service",
					"id", service.ID,
					"title", service.Title,
				)
				serviceDetail, err := client.ItemsAPI.Get(ctx, vlt.ID, service.ID)
				if err != nil {
					return nil, fmt.Errorf("get item: %w", err)
				}
				for _, secret := range serviceDetail.Fields {
					serviceSecrects[secret.Title] = secret.Value
				}
				allSecrets[service.Title] = serviceSecrects
				log.Debug("loaded secrets for service", "qty", len(serviceSecrects), "service", service.Title)
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("vault %q not found", o.Vault)
	}
	if len(allSecrets) == 0 {
		return nil, fmt.Errorf("no services/items found in vault %q", o.Vault)
	}
	log.Debug("vault load complete",
		"elapsed", time.Since(start),
		"vault", o.Vault,
		"services", len(allSecrets),
	)
	return allSecrets, nil
}
