package authorizationserver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/gorilla/mux"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
)

type AuthorizationServerOptions struct {
	Address      string
	Port         int
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

func (opts AuthorizationServerOptions) Validate() error {
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

type authorizationServer struct {
	http              *http.Server
	privateKey        jwk.Key
	publicKey         jwk.Key
	setIssuerJwt      func(newIssuer string)
	setIssuerHandlers func(newIssuer string)
}

func NewAuthorizationServer(opts AuthorizationServerOptions) (*authorizationServer, error) {
	err := opts.Validate()
	if err != nil {
		return nil, err
	}

	priv, pub, err := getRandomJWK()
	if err != nil {
		return nil, err
	}

	srv := &authorizationServer{
		privateKey: priv,
		publicKey:  pub,
	}

	as, err := srv.newAS(opts, opts.Issuer)
	if err != nil {
		return nil, err
	}

	router, err := srv.newRouter(as, opts.Issuer)
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

func (srv *authorizationServer) Start(ctx context.Context, wg *sync.WaitGroup) error {
	wg.Done()

	fmt.Printf("starting authorization webserver: %s\n", srv.http.Addr)

	err := srv.http.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "web server failed to start or stop gracefully: %v\n", err)
		return err
	}

	return nil
}

func (srv *authorizationServer) Stop(ctx context.Context) error {
	err := srv.http.Shutdown(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "web server failed to stop gracefully: %v\n", err)
		return err
	}

	fmt.Println("web server stopped gracefully")

	return nil
}

func (srv *authorizationServer) newRouter(as *server.Server, issuer string) (http.Handler, error) {
	handlersOpts := HandlersOptions{
		AuthorizationServer: as,
		PublicKey:           srv.publicKey,
		Issuer:              issuer,
	}

	handlers, err := newHandlers(handlersOpts)
	if err != nil {
		return nil, err
	}

	srv.setIssuerHandlers = handlers.SetIssuer

	router := mux.NewRouter()

	router.HandleFunc("/login", handlers.login)
	router.HandleFunc("/oauth/authorize", handlers.authorize)
	router.HandleFunc("/oauth/token", handlers.token)
	router.HandleFunc("/test", handlers.test)
	router.HandleFunc("/jwk", handlers.jwk)
	router.HandleFunc("/.well-known/openid-configuration", handlers.discovery)

	return router, nil
}

func (srv *authorizationServer) newAS(opts AuthorizationServerOptions, issuer string) (*server.Server, error) {
	manager, jwtGenerator, err := srv.newManager(opts, issuer)
	if err != nil {
		return nil, err
	}

	as := server.NewServer(server.NewConfig(), manager)

	asHandlers, err := newASHandlers(ASHandlersOptions{})
	if err != nil {
		return nil, err
	}

	as.SetPasswordAuthorizationHandler(asHandlers.passwordAuthorization)
	as.SetUserAuthorizationHandler(asHandlers.userAuthorization)
	as.SetInternalErrorHandler(asHandlers.internalError)
	as.SetResponseErrorHandler(asHandlers.responseError)

	as.SetExtensionFieldsHandler(jwtGenerator.IDToken)

	return as, nil
}

func (srv *authorizationServer) newManager(opts AuthorizationServerOptions, issuer string) (*manage.Manager, *JWTAccessGenerate, error) {
	jwtGenerator := newJWTAccessGenerate(issuer, srv.privateKey, jwa.ES384)
	srv.setIssuerJwt = jwtGenerator.SetIssuer

	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	manager.MustTokenStorage(store.NewMemoryTokenStore())
	manager.MapAccessGenerate(jwtGenerator)

	clientStore := store.NewClientStore()
	clientStore.Set(opts.ClientID, &models.Client{
		ID:     opts.ClientID,
		Secret: opts.ClientSecret,
		Domain: opts.RedirectURI,
	})
	manager.MapClientStorage(clientStore)

	return manager, jwtGenerator, nil
}

func (srv *authorizationServer) SetIssuer(newIssuer string) {
	srv.setIssuerHandlers(newIssuer)
	srv.setIssuerJwt(newIssuer)
}
