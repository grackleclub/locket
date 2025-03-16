  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
	modified:   cmd/infra/infra/config.go
# 🔐 locket ❤️

[![Go - Test](https://github.com/grackleclub/locket/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/grackleclub/locket/actions/workflows/go.yml)

secrets management service

## Purpose
Locket is a secrets cache for production services. It stores secrets in memory, loaded from external secrets cache, environment, or .env file as source. Why? Because the 1password GUI is great for business use, but the sacntioned 1password cache was flaky, and I wanted a go based soluton that abstracts away secret origin while providing tight access control and integration with existing deployment.

## Overview
```mermaid
sequenceDiagram
    autonumber

    box rgb(0, 40, 0) External 
    participant CI
    participant source
    end

    box rgb(40, 0, 0) Locket Server
    participant secrets
    participant registry
    participant handler
    end

    box rgb(0, 0, 40) Locket Client
    participant client
    end

    activate CI
    CI->>registry: public signing keys
    CI->>client: private signing key
    CI->>secrets: source access key (or source files)
    note over CI: depoy complete
    deactivate CI

    secrets->>source: request all secrets
    activate secrets
    source->>secrets: all secrets
    note over secrets: server init complete
    deactivate secrets

    client->>handler: GET - public key
    activate client
    handler->>client: server public encryption key
    note over client: client init complete
    deactivate client

    client->>handler: GET - public key
    activate client
    handler->>client: server public encryption key
    client->>handler: POST - secret (encrypted & signed)
    handler->>registry: authenticate signing key
    activate handler
    registry->>handler: verify identity
    note over handler: auth & access control
    handler--x client: forbidden
    deactivate handler
    handler->>secrets: request secret
    secrets->>handler: secret value
    handler-->>client: encrypted secret
    note over client: secret fetched
    deactivate client
```

### 1-3 Deploy
Create [registry](./registry.go) and distribute signing keys.

### 4-5 Init Server
Load secrets using any struct that satisfies the `source` interface.

struct | source
--- | ---
`env` | local environment
`dotenv` | `.env` file
`onepass` | 1password server


### 6-7 Init Client
Fetch server public encryption key.

### 8-9 Refetch public encryption key
Server may generate a new public key upon restart. No caching is currently implemented. 🤷

### 10-12 Enforce Access Control
- clients must encrypt and sign every request
- clients can only requeest their own secrets

### 13-15 Fetch & Return Secret
- responses are encrypted

 ## Examples
See [tests](./locket_test.go) for examples, and checkout docstings for extensive descriptions.
