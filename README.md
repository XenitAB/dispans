# DEPRECATED

This module is deprecated. Please use `optest` in [github.com/XenitAB/go-oidc-middleware](https://github.com/XenitAB/go-oidc-middleware) instead.

# dispans

Go library providing in-memory implementation of an OAuth2 Authorization Server / OpenID Provider. The name comes from the Swedish word `dispens` (pronounced: `dis` like in `disconnect` and `pans` like in `pansar` - `dis-pans`) meaning `exemption` in English.

# Mission statement

The purpose of this library is to make it easy to test OAuth2 / OIDC clients, providing an easy way to run an OAuth2.0 Authorization Server (AS) / OpenID Provider (OIDC / OpenID Connect).

This is not supposed to be a certified provider, or a secure one for that matter. It will implement the bare minimum to make it easy to get tokens with the claims you need.

**NEVER** use this library for any kind of production code. It's supposed to be used in tests to validate client implementations.

# Go compatibility

This package is only supported for go 1.17 or above (from v0.0.10 and above)

# Running tidy

```
go mod tidy -compat=1.17
```
