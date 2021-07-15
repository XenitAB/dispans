package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cristalhq/aconfig"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/jwk"
)

func main() {
	cfg, err := newConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config generation returned an error: %v\n", err)
		os.Exit(1)
	}

	err = run(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Application returned an error: %v\n", err)
		os.Exit(1)
	}
}

func run(cfg config) error {
	jwksHandler, err := newKeyHandler(cfg.OidcIssuer)
	if err != nil {
		return err
	}

	e := echo.New()
	e.HideBanner = true
	e.Use(middleware.Recover())
	e.Use(middleware.Secure())

	// Unauthenticated route
	e.GET("/", accessible)

	// Restricted group
	r := e.Group("/restricted")
	r.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		KeyFunc: jwksHandler.jwtKeyFunc,
	}))
	r.GET("", restricted)

	addr := net.JoinHostPort(cfg.Address, fmt.Sprintf("%d", cfg.Port))

	return e.Start(addr)
}

type keyHandler struct {
	sync.RWMutex
	jwksURI string
	keySet  jwk.Set
}

func newKeyHandler(issuer string) (*keyHandler, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	discoveryURI := fmt.Sprintf("%s/.well-known/openid-configuration", strings.TrimSuffix(issuer, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURI, nil)
	if err != nil {
		return nil, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	err = res.Body.Close()
	if err != nil {
		return nil, err
	}

	var discoveryData struct {
		JwksURI string `json:"jwks_uri"`
	}

	err = json.Unmarshal(bodyBytes, &discoveryData)
	if err != nil {
		return nil, err
	}

	if discoveryData.JwksURI == "" {
		return nil, fmt.Errorf("JwksURI is empty")
	}

	h := &keyHandler{
		jwksURI: discoveryData.JwksURI,
	}

	err = h.updateKeySet()
	if err != nil {
		return nil, err
	}

	return h, nil
}

func (h *keyHandler) updateKeySet() error {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	keySet, err := jwk.Fetch(ctx, h.jwksURI)
	if err != nil {
		return fmt.Errorf("Unable to fetch keys from %q: %v", h.jwksURI, err)
	}

	h.Lock()
	h.keySet = keySet
	h.Unlock()

	return nil
}

func (h *keyHandler) getKeySet() jwk.Set {
	h.RLock()
	defer h.RUnlock()
	return h.keySet
}

func (h *keyHandler) jwtKeyFunc(token *jwt.Token) (interface{}, error) {
	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have a key ID in the kid field")
	}

	return h.getPublicKeyByKeyID(keyID, false)
}

func (h *keyHandler) getPublicKeyByKeyID(keyID string, retry bool) (interface{}, error) {
	keySet := h.getKeySet()
	key, found := keySet.LookupKeyID(keyID)

	if !found && !retry {
		err := h.updateKeySet()
		if err != nil {
			return nil, fmt.Errorf("unable to find key %q: %v", keyID, err)
		}

		return h.getPublicKeyByKeyID(keyID, true)
	}

	if !found && retry {
		return nil, fmt.Errorf("unable to find key %q", keyID)
	}

	var pubKey interface{}
	if err := key.Raw(&pubKey); err != nil {
		return nil, fmt.Errorf("Unable to get the public key. Error: %s", err.Error())
	}

	return pubKey, nil
}

func accessible(c echo.Context) error {
	return c.String(http.StatusOK, "Accessible")
}

func restricted(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	name := claims["sub"].(string)
	return c.String(http.StatusOK, "Welcome "+name+"!")
}

type config struct {
	Address      string `flag:"address" env:"ADDRESS" default:"127.0.0.1" usage:"address webserver will listen to"`
	Port         int    `flag:"port" env:"PORT" default:"8080" usage:"port webserver will listen to"`
	OidcIssuer   string `flag:"oidc-token-issuer" env:"OIDC_TOKEN_ISSUER" usage:"the oidc issuer url for tokens"`
	OidcAudience string `flag:"oidc-token-audience" env:"OIDC_TOKEN_AUDIENCE" usage:"the oidc audience that tokens need to contain"`
}

func newConfig() (config, error) {
	var cfg config

	loader := aconfig.LoaderFor(&cfg, aconfig.Config{
		SkipDefaults: false,
		SkipFiles:    true,
		SkipEnv:      false,
		SkipFlags:    false,
		EnvPrefix:    "",
		FlagPrefix:   "",
		Files:        []string{},
		FileDecoders: map[string]aconfig.FileDecoder{},
	})

	err := loader.Load()
	if err != nil {
		return config{}, err
	}

	return cfg, nil
}
