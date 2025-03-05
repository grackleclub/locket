# 🔐 locket ❤️

[![Go - Test](https://github.com/grackleclub/locket/actions/workflows/go.yml/badge.svg)](https://github.com/grackleclub/locket/actions/workflows/go.yml)

secrets management service

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

 

## endpoints
route | method(s) | purpose
--- | --- | ---
`/` | `GET` | provide server public key
`/` | `POST` | make encrypted signed request for values
