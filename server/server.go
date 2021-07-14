package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"

	asmanage "github.com/go-oauth2/oauth2/v4/manage"
	asmodels "github.com/go-oauth2/oauth2/v4/models"
	asserver "github.com/go-oauth2/oauth2/v4/server"
	asstore "github.com/go-oauth2/oauth2/v4/store"
	"github.com/gorilla/mux"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/xenitab/dispans/authority"
	"github.com/xenitab/dispans/key"
	"github.com/xenitab/dispans/models"
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

type serverHandler struct {
	http          *http.Server
	keyHandler    models.KeysGetter
	issuerHandler models.IssuerGetSetter
}

func New(opts Options) (*serverHandler, error) {
	err := opts.Validate()
	if err != nil {
		return nil, err
	}

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

	srv := &serverHandler{
		keyHandler: keyHandler,
	}

	as, err := srv.newAS(opts, authorityHandler)
	if err != nil {
		return nil, err
	}

	router, err := srv.newRouter(as, authorityHandler)
	if err != nil {
		return nil, err
	}

	addr := net.JoinHostPort(opts.Address, fmt.Sprintf("%d", opts.Port))

	srv.http = &http.Server{
		Addr:    addr,
		Handler: router,
	}

	return srv, nil
}

func (srv *serverHandler) Start(ctx context.Context, wg *sync.WaitGroup) error {
	wg.Done()

	fmt.Printf("starting authorization webserver: %s\n", srv.http.Addr)

	err := srv.http.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "web server failed to start or stop gracefully: %v\n", err)
		return err
	}

	return nil
}

func (srv *serverHandler) Stop(ctx context.Context) error {
	err := srv.http.Shutdown(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "web server failed to stop gracefully: %v\n", err)
		return err
	}

	fmt.Println("web server stopped gracefully")

	return nil
}

func (srv *serverHandler) newRouter(as *asserver.Server, issuerHandler models.IssuerGetter) (http.Handler, error) {
	handlersOpts := HandlersOptions{
		AuthorizationServer: as,
		PublicKeyHandler:    srv.keyHandler,
		IssuerHandler:       issuerHandler,
	}

	handlers, err := newHandlers(handlersOpts)
	if err != nil {
		return nil, err
	}

	router := mux.NewRouter()

	router.HandleFunc("/login", handlers.login)
	router.HandleFunc("/oauth/authorize", handlers.authorize)
	router.HandleFunc("/oauth/token", handlers.token)
	router.HandleFunc("/test", handlers.test)
	router.HandleFunc("/jwk", handlers.jwk)
	router.HandleFunc("/.well-known/openid-configuration", handlers.discovery)

	return router, nil
}

func (srv *serverHandler) newAS(opts Options, issuerHandler models.IssuerGetter) (*asserver.Server, error) {
	userHandler := user.NewHandler()

	tokenOpts := token.Options{
		UserHandler:       userHandler,
		IssuerHandler:     issuerHandler,
		PrivateKeyHandler: srv.keyHandler,
		SigningMethod:     jwa.ES384,
	}
	tokenHandler, err := token.NewHandler(tokenOpts)
	if err != nil {
		return nil, err
	}

	manager, err := srv.newManager(opts, tokenHandler)
	if err != nil {
		return nil, err
	}

	as := asserver.NewServer(asserver.NewConfig(), manager)

	asHandlers, err := newASHandlers(ASHandlersOptions{})
	if err != nil {
		return nil, err
	}

	as.SetPasswordAuthorizationHandler(asHandlers.passwordAuthorization)
	as.SetUserAuthorizationHandler(asHandlers.userAuthorization)
	as.SetInternalErrorHandler(asHandlers.internalError)
	as.SetResponseErrorHandler(asHandlers.responseError)

	as.SetExtensionFieldsHandler(tokenHandler.ExtensionFieldsHandler)

	return as, nil
}

func (srv *serverHandler) newManager(opts Options, tokenHandler models.AccessTokenGetter) (*asmanage.Manager, error) {
	manager := asmanage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(asmanage.DefaultAuthorizeCodeTokenCfg)
	manager.MustTokenStorage(asstore.NewMemoryTokenStore())
	manager.MapAccessGenerate(tokenHandler)

	clientStore := asstore.NewClientStore()
	clientStore.Set(opts.ClientID, &asmodels.Client{
		ID:     opts.ClientID,
		Secret: opts.ClientSecret,
		Domain: opts.RedirectURI,
	})
	manager.MapClientStorage(clientStore)

	return manager, nil
}
