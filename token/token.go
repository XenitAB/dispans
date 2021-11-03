package token

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	asoauth2 "github.com/go-oauth2/oauth2/v4"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/xenitab/dispans/models"
)

type Options struct {
	UserHandler       models.UserGetter
	IssuerHandler     models.IssuerGetter
	PrivateKeyHandler models.PrivateKeyGetter
	SigningMethod     jwa.SignatureAlgorithm
}

func (opts Options) Validate() error {
	if opts.UserHandler == nil {
		return fmt.Errorf("UserHandler is nil")
	}

	if opts.IssuerHandler == nil {
		return fmt.Errorf("IssuerHandler is nil")
	}

	if opts.PrivateKeyHandler == nil {
		return fmt.Errorf("PrivateKeyHandler is nil")
	}

	if opts.SigningMethod == "" {
		return fmt.Errorf("SigningMethod is empty")
	}

	return nil
}

func NewHandler(opts Options) (*handler, error) {
	err := opts.Validate()
	if err != nil {
		return nil, err
	}

	return &handler{
		userHandler:       opts.UserHandler,
		issuerHandler:     opts.IssuerHandler,
		privateKeyHandler: opts.PrivateKeyHandler,
		signingMethod:     opts.SigningMethod,
	}, nil
}

type handler struct {
	userHandler       models.UserGetter
	issuerHandler     models.IssuerGetter
	privateKeyHandler models.PrivateKeyGetter
	signingMethod     jwa.SignatureAlgorithm
}

// Token creates a signed access token
func (h *handler) Token(ctx context.Context, data *asoauth2.GenerateBasic, isGenRefresh bool) (string, string, error) {
	return h.getAccessToken(ctx, data, isGenRefresh)
}

func (h *handler) getAccessToken(ctx context.Context, data *asoauth2.GenerateBasic, isGenRefresh bool) (string, string, error) {
	issuer := h.issuerHandler.GetIssuer()

	token := jwt.New()
	token.Set(jwt.IssuerKey, issuer)
	token.Set(jwt.AudienceKey, data.Client.GetID())
	token.Set(jwt.SubjectKey, data.UserID)
	token.Set(jwt.ExpirationKey, data.TokenInfo.GetAccessCreateAt().Add(data.TokenInfo.GetAccessExpiresIn()).Unix())
	token.Set(jwt.NotBeforeKey, data.TokenInfo.GetAccessCreateAt().Unix())
	token.Set("sid", uuid.NewString())

	key := h.privateKeyHandler.GetPrivateKey()

	headers := jws.NewHeaders()
	headers.Set(jws.KeyIDKey, key.KeyID())
	headers.Set(jws.TypeKey, "JWT+AT")

	signedToken, err := jwt.Sign(token, h.signingMethod, key, jwt.WithHeaders(headers))
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

func (h *handler) ExtensionFieldsHandler(ti asoauth2.TokenInfo) map[string]interface{} {
	response := make(map[string]interface{})

	if strings.Contains(ti.GetScope(), "openid") {
		idToken, err := h.getIDToken(ti)
		if err == nil {
			response["id_token"] = idToken
		}
	}

	return response
}

// IDToken creates a signed id token
func (h *handler) getIDToken(ti asoauth2.TokenInfo) (string, error) {
	issuer := h.issuerHandler.GetIssuer()

	token := jwt.New()
	token.Set(jwt.IssuerKey, issuer)
	token.Set(jwt.AudienceKey, ti.GetClientID())
	token.Set(jwt.SubjectKey, ti.GetUserID())
	token.Set(jwt.ExpirationKey, ti.GetAccessCreateAt().Add(ti.GetAccessExpiresIn()).Unix())
	token.Set(jwt.NotBeforeKey, ti.GetAccessCreateAt().Unix())

	user, err := h.userHandler.GetUserByID(ti.GetUserID())
	if err != nil {
		return "", err
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

	key := h.privateKeyHandler.GetPrivateKey()

	headers := jws.NewHeaders()
	headers.Set(jws.KeyIDKey, key.KeyID())
	headers.Set(jws.TypeKey, "JWT")

	signedToken, err := jwt.Sign(token, h.signingMethod, key, jwt.WithHeaders(headers))
	if err != nil {
		return "", err
	}

	return string(signedToken), nil
}
