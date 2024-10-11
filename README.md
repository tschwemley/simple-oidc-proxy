# Simple OIDC Proxy

## Running

`./oidc-sso`

## Building

### Nix

`nix build`

### Go

`go build -o oidc-sso main.go auth.go`

## Config

All configuration is done via environment variables

```environment
CLIENT_ID=
CLIENT_SECRET=

ISSUER_URL=
REDIRECT_URL=

COOKIE_DOMAIN=
COOKIE_AUTH_KEY=
COOKIE_ENCRYPT_KEY=
```
