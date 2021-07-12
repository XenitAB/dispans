package authorizationserver

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-session/session"
	"github.com/lestrrat-go/jwx/jwk"
)

type HandlersOptions struct {
	AuthorizationServer *server.Server
	PublicKey           jwk.Key
	Issuer              string
}

func (opts HandlersOptions) Validate() error {
	if opts.AuthorizationServer == nil {
		return fmt.Errorf("AuthorizationServer is nil")
	}

	if opts.PublicKey == nil {
		return fmt.Errorf("PublicKey is nil")
	}

	if opts.Issuer == "" {
		return fmt.Errorf("Issuer is empty")
	}

	return nil
}

type handlers struct {
	as        *server.Server
	publicKey jwk.Key
	issuer    string
}

func newHandlers(opts HandlersOptions) (*handlers, error) {
	err := opts.Validate()
	if err != nil {
		return nil, err
	}

	return &handlers{
		as:        opts.AuthorizationServer,
		publicKey: opts.PublicKey,
		issuer:    opts.Issuer,
	}, nil
}

func (h *handlers) authorize(w http.ResponseWriter, r *http.Request) {
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

func (h *handlers) login(w http.ResponseWriter, r *http.Request) {
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
	h.serveHTML(w, r, "static/login.html")
}

func (h *handlers) token(w http.ResponseWriter, r *http.Request) {
	err := h.as.HandleTokenRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handlers) test(w http.ResponseWriter, r *http.Request) {
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

func (h *handlers) jwk(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(h.publicKey)
}

func (h *handlers) discovery(w http.ResponseWriter, r *http.Request) {
	discoveryData := map[string]interface{}{
		"issuer":                                h.issuer,
		"authorization_endpoint":                h.issuer + "/oauth/authorize",
		"token_endpoint":                        h.issuer + "/oauth/token",
		"jwks_uri":                              h.issuer + "/jwk",
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

func (h *handlers) serveHTML(w http.ResponseWriter, req *http.Request, filename string) {
	handler := http.FileServer(http.FS(content))
	req.URL.Path = filename
	handler.ServeHTTP(w, req)
}

func (h *handlers) SetIssuer(newIssuer string) {
	h.issuer = newIssuer
}
