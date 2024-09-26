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
OIDC_SSO_LISTEN_PORT=1337

OIDC_SSO_CLIENT_ID=
OIDC_SSO_CLIENT_SECRET=

OIDC_SSO_ISSUER_URL=
OIDC_SSO_REDIRECT_URL=

OIDC_SSO_COOKIE_DOMAIN
OIDC_SSO_HASH_KEY=
OIDC_SSO_ENCRYPT_KEY=
```
