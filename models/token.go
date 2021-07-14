package models

import (
	"context"

	asoauth2 "github.com/go-oauth2/oauth2/v4"
)

type AccessTokenGetter interface {
	Token(ctx context.Context, data *asoauth2.GenerateBasic, isGenRefresh bool) (string, string, error)
}

type ExtensionsFieldsGetter interface {
	ExtensionFieldsHandler(ti asoauth2.TokenInfo) map[string]interface{}
}

type TokenGetter interface {
	AccessTokenGetter
	ExtensionsFieldsGetter
}
