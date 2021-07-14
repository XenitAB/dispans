package models

import (
	"context"

	asoauth2 "github.com/go-oauth2/oauth2/v4"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token"`
}

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
