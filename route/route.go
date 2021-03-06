package route

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	asserver "github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-session/session"
	"github.com/xenitab/dispans/models"
)

type Options struct {
	AuthorizationServer *asserver.Server
	PublicKeyHandler    models.PublicKeyGetter
	IssuerHandler       models.IssuerGetter
}

func (opts Options) Validate() error {
	if opts.AuthorizationServer == nil {
		return fmt.Errorf("AuthorizationServer is nil")
	}

	if opts.PublicKeyHandler == nil {
		return fmt.Errorf("PublicKeyHandler is nil")
	}

	if opts.IssuerHandler == nil {
		return fmt.Errorf("IssuerHandler is nil")
	}

	return nil
}

type handler struct {
	as               *asserver.Server
	publicKeyHandler models.PublicKeyGetter
	issuerHandler    models.IssuerGetter
}

func NewHandler(opts Options) (*handler, error) {
	err := opts.Validate()
	if err != nil {
		return nil, err
	}

	return &handler{
		as:               opts.AuthorizationServer,
		publicKeyHandler: opts.PublicKeyHandler,
		issuerHandler:    opts.IssuerHandler,
	}, nil
}

func (h *handler) Authorize(w http.ResponseWriter, r *http.Request) {
	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var form url.Values
	if v, ok := store.Get("ReturnUri"); ok {
		form = v.(url.Values)
	}
	r.Form = form

	store.Delete("ReturnUri")
	store.Save()

	err = h.as.HandleAuthorizeRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func (h *handler) Login(w http.ResponseWriter, r *http.Request) {
	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if r.Method == "POST" {
		if r.Form == nil {
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		username := r.Form.Get("username")
		password := r.Form.Get("password")
		userID, err := h.as.PasswordAuthorizationHandler(username, password)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		store.Set("LoggedInUserID", userID)
		store.Save()

		w.Header().Set("Location", "/oauth/authorize")
		w.WriteHeader(http.StatusFound)
		return
	}

	serveHTML(w, r, "static/login.html")
}

func (h *handler) Token(w http.ResponseWriter, r *http.Request) {
	err := h.as.HandleTokenRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handler) Test(w http.ResponseWriter, r *http.Request) {
	token, err := h.as.ValidationBearerToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	data := map[string]interface{}{
		"expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
		"client_id":  token.GetClientID(),
		"user_id":    token.GetUserID(),
	}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(data)
}

func (h *handler) Jwks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	pubKey := h.publicKeyHandler.GetPublicKeySet()

	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(pubKey)
}

func (h *handler) Discovery(w http.ResponseWriter, r *http.Request) {
	issuer := h.issuerHandler.GetIssuer()

	discoveryData := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth/authorize",
		"token_endpoint":                        issuer + "/oauth/token",
		"jwks_uri":                              issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES384"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		"claims_supported": []string{
			"aud", "email", "email_verified", "exp",
			"family_name", "given_name", "iat", "iss",
			"locale", "name", "sub",
		},
	}

	w.Header().Set("Content-Type", "application/json")

	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(discoveryData)
}

//go:embed static/*
var content embed.FS

func serveHTML(w http.ResponseWriter, req *http.Request, filename string) {
	handler := http.FileServer(http.FS(content))
	req.URL.Path = filename
	handler.ServeHTTP(w, req)
}
