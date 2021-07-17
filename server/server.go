package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/gorilla/mux"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/xenitab/dispans/as"
	"github.com/xenitab/dispans/authority"
	"github.com/xenitab/dispans/key"
	"github.com/xenitab/dispans/models"
	"github.com/xenitab/dispans/route"
	"github.com/xenitab/dispans/token"
	"github.com/xenitab/dispans/user"
)

type Options struct {
	Address      string
	Port         int
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

func (opts Options) Validate() error {
	if opts.Address == "" {
		return fmt.Errorf("Address is empty")
	}

	if opts.Port == 0 {
		return fmt.Errorf("Port is empty")
	}

	if opts.Issuer == "" {
		return fmt.Errorf("Issuer is empty")
	}

	if opts.ClientID == "" {
		return fmt.Errorf("ClientID is empty")
	}

	if opts.ClientSecret == "" {
		return fmt.Errorf("Secret is empty")
	}

	if opts.RedirectURI == "" {
		return fmt.Errorf("RedirectURI is empty")
	}

	return nil
}

type handler struct {
	httpServer *http.Server
}

func New(opts Options) (*handler, error) {
	err := opts.Validate()
	if err != nil {
		return nil, err
	}

	router, err := new(opts)
	if err != nil {
		return nil, err
	}

	addr := net.JoinHostPort(opts.Address, fmt.Sprintf("%d", opts.Port))
	httpServer := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	return &handler{
		httpServer: httpServer,
	}, nil
}

func new(opts Options) (http.Handler, error) {
	authorityOpts := authority.Options{
		Issuer: opts.Issuer,
	}

	authorityHandler, err := authority.NewHandler(authorityOpts)
	if err != nil {
		return nil, err
	}

	keyHandler, err := key.NewHandler()
	if err != nil {
		return nil, err
	}

	userHandler := user.NewHandler()

	tokenOpts := token.Options{
		UserHandler:       userHandler,
		IssuerHandler:     authorityHandler,
		PrivateKeyHandler: keyHandler,
		SigningMethod:     jwa.ES384,
	}

	tokenHandler, err := token.NewHandler(tokenOpts)
	if err != nil {
		return nil, err
	}

	asOptions := as.Options{
		UserHandler:   userHandler,
		TokenHandler:  tokenHandler,
		IssuerHandler: authorityHandler,
		ClientID:      opts.ClientID,
		ClientSecret:  opts.ClientSecret,
		RedirectURI:   opts.RedirectURI,
	}

	asHandler, err := as.NewHandler(asOptions)
	if err != nil {
		return nil, err
	}

	as, err := asHandler.NewAuthorizationServer()
	if err != nil {
		return nil, err
	}

	return newRouter(as, authorityHandler, keyHandler)
}

func (h *handler) Start(ctx context.Context, wg *sync.WaitGroup) error {
	wg.Done()

	fmt.Printf("starting authorization webserver: %s\n", h.httpServer.Addr)

	err := h.httpServer.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "web server failed to start or stop gracefully: %v\n", err)
		return err
	}

	return nil
}

func (h *handler) Stop(ctx context.Context) error {
	err := h.httpServer.Shutdown(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "web server failed to stop gracefully: %v\n", err)
		return err
	}

	fmt.Println("web server stopped gracefully")

	return nil
}

func newRouter(as models.AuthorizationServer, issuerHandler models.IssuerGetter, publicKeyHandler models.PublicKeyGetter) (http.Handler, error) {
	routeOpts := route.Options{
		AuthorizationServer: as,
		PublicKeyHandler:    publicKeyHandler,
		IssuerHandler:       issuerHandler,
	}

	routeHandler, err := route.NewHandler(routeOpts)
	if err != nil {
		return nil, err
	}

	router := mux.NewRouter()

	router.HandleFunc("/login", routeHandler.Login)
	router.HandleFunc("/oauth/authorize", routeHandler.Authorize)
	router.HandleFunc("/oauth/token", routeHandler.Token)
	router.HandleFunc("/test", routeHandler.Test)
	router.HandleFunc("/jwks", routeHandler.Jwks)
	router.HandleFunc("/.well-known/openid-configuration", routeHandler.Discovery)

	return router, nil
}
