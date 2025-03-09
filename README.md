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

    client->>handler: POST - secret (encrypted & signed)
    activate client
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

### 4-


## design outline
1. init `secrets` server
    - read secrets
        - prod: external source
        - dev: from env
    - read config for each service
        - allowed service and IP(s)
        - associated client ed25519 public key(s)
        - allowed vars
3. init `secrets` client
    - get server's public key
    - encrypt request with public key
    - sign request with ed25519
    - send request:
        - encrypted payload
        - payload's ed25519 signature
        - own public RSA key
4. `secrets` server
    - verifies ed25519 signature
    - decrypts payload
    - checks ACL
    - ecrypts response of allowed secrets with requestor's public key
5. `secrets` client
    - decrypts

 
