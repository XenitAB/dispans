package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"

	"github.com/cristalhq/aconfig"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/xenitab/pkg/echo-v4-middleware/oidc"
	"github.com/xenitab/pkg/service"
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
	errGroup, ctx, cancel := service.NewErrGroupAndContext()
	defer cancel()

	stopChan := service.NewStopChannel()
	defer signal.Stop(stopChan)

	addr := net.JoinHostPort(cfg.Address, fmt.Sprintf("%d", cfg.Port))
	issuer := cfg.OidcIssuer

	web, err := newWebHandler(issuer, addr)
	if err != nil {
		return err
	}

	service.Start(ctx, errGroup, web)

	stoppedBy := service.WaitForStop(stopChan, ctx)
	fmt.Printf("Application stopping. Stopped by: %s\n", stoppedBy)

	cancel()

	timeoutCtx, timeoutCancel := service.NewShutdownTimeoutContext()
	defer timeoutCancel()

	service.Stop(timeoutCtx, errGroup, web)

	return service.WaitForErrGroup(errGroup)
}

type webHandler struct {
	httpServer *echo.Echo
	address    string
}

func newWebHandler(issuer string, addr string) (*webHandler, error) {
	e := echo.New()
	e.HideBanner = true
	e.Use(middleware.Recover())
	e.Use(middleware.Secure())

	// Unauthenticated route
	e.GET("/", accessible)

	// Restricted group
	r := e.Group("/restricted")
	r.Use(oidc.OIDCWithConfig(oidc.OIDCConfig{
		Issuer: issuer,
	}))
	r.GET("", restricted)

	return &webHandler{
		httpServer: e,
		address:    addr,
	}, nil
}

func (h *webHandler) Start(ctx context.Context, wg *sync.WaitGroup) error {
	wg.Done()

	fmt.Printf("web server starting: %s\n", h.address)

	err := h.httpServer.Start(h.address)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

func (h *webHandler) Stop(ctx context.Context) error {
	err := h.httpServer.Shutdown(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "web server failed to stop gracefully: %v\n", err)
		return err
	}

	fmt.Println("web server stopped gracefully")

	return nil
}

func accessible(c echo.Context) error {
	return c.String(http.StatusOK, "Accessible")
}

func restricted(c echo.Context) error {
	token, ok := c.Get("user").(jwt.Token)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid token")
	}

	claims, err := token.AsMap(c.Request().Context())
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid token")
	}

	return c.JSON(http.StatusOK, claims)
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
