package server

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	asoauth2 "github.com/go-oauth2/oauth2/v4"
	aserrors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

type jwtAccessClaims struct {
	token []byte
	jwks  jwk.Set
}

func (a *jwtAccessClaims) Valid() error {
	token, err := jwt.Parse(a.token, jwt.WithKeySet(a.jwks))
	if err != nil {
		return err
	}

	if token.Expiration().Before(time.Now()) {
		return aserrors.ErrInvalidAccessToken
	}

	return nil
}

func newjwtHandler(issuer string, key jwk.Key, method jwa.SignatureAlgorithm) *jwtHandler {
	return &jwtHandler{
		Issuer:       issuer,
		SignedKey:    key,
		SignedMethod: method,
	}
}

type jwtHandler struct {
	Issuer       string
	SignedKey    jwk.Key
	SignedMethod jwa.SignatureAlgorithm
}

// Token creates a signed access token
func (a *jwtHandler) Token(ctx context.Context, data *asoauth2.GenerateBasic, isGenRefresh bool) (string, string, error) {
	token := jwt.New()
	token.Set(jwt.IssuerKey, a.Issuer)
	token.Set(jwt.AudienceKey, data.Client.GetID())
	token.Set(jwt.SubjectKey, data.UserID)
	token.Set(jwt.ExpirationKey, data.TokenInfo.GetAccessCreateAt().Add(data.TokenInfo.GetAccessExpiresIn()).Unix())
	token.Set(jwt.NotBeforeKey, data.TokenInfo.GetAccessCreateAt().Unix())

	headers := jws.NewHeaders()
	headers.Set(jws.KeyIDKey, a.SignedKey.KeyID())
	headers.Set(jws.TypeKey, "JWT+AT")

	signedToken, err := jwt.Sign(token, a.SignedMethod, a.SignedKey, jwt.WithHeaders(headers))
	if err != nil {
		return "", "", err
	}

	access := string(signedToken)
	refresh := ""

	if isGenRefresh {
		t := uuid.NewSHA1(uuid.Must(uuid.NewRandom()), []byte(access)).String()
		refresh = base64.URLEncoding.EncodeToString([]byte(t))
		refresh = strings.ToUpper(strings.TrimRight(refresh, "="))
	}

	return access, refresh, nil
}

// IDToklen creates a signed id token
func (a *jwtHandler) IDToken(ti asoauth2.TokenInfo) map[string]interface{} {
	if !strings.Contains(ti.GetScope(), "openid") {
		return nil
	}

	token := jwt.New()
	token.Set(jwt.IssuerKey, a.Issuer)
	token.Set(jwt.AudienceKey, ti.GetClientID())
	token.Set(jwt.SubjectKey, ti.GetUserID())
	token.Set(jwt.ExpirationKey, ti.GetAccessCreateAt().Add(ti.GetAccessExpiresIn()).Unix())
	token.Set(jwt.NotBeforeKey, ti.GetAccessCreateAt().Unix())

	user, err := GetUserByID(ti.GetUserID())
	if err != nil {
		return nil
	}

	if strings.Contains(ti.GetScope(), "profile") {
		token.Set("name", user.Name)
		token.Set("given_name", user.GivenName)
		token.Set("family_name", user.FamilyName)
		token.Set("locale", user.Locale)
	}

	if strings.Contains(ti.GetScope(), "email") {
		token.Set("email", user.Email)
		token.Set("email_verified", user.EmailVerified)
	}

	headers := jws.NewHeaders()
	headers.Set(jws.KeyIDKey, a.SignedKey.KeyID())
	headers.Set(jws.TypeKey, "JWT")

	signedToken, err := jwt.Sign(token, a.SignedMethod, a.SignedKey, jwt.WithHeaders(headers))
	if err != nil {
		return nil
	}

	response := make(map[string]interface{})
	response["id_token"] = string(signedToken)

	return response
}

func (a *jwtHandler) SetIssuer(newIssuer string) {
	a.Issuer = newIssuer
}
