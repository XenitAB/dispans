package as

import (
	"fmt"

	asmanage "github.com/go-oauth2/oauth2/v4/manage"
	asmodels "github.com/go-oauth2/oauth2/v4/models"
	asserver "github.com/go-oauth2/oauth2/v4/server"
	asstore "github.com/go-oauth2/oauth2/v4/store"
	"github.com/xenitab/dispans/models"
)

type Options struct {
	UserHandler   models.UserGetter
	TokenHandler  models.TokenGetter
	IssuerHandler models.IssuerGetter
	ClientID      string
	ClientSecret  string
	RedirectURI   string
}

func (opts Options) Validate() error {
	if opts.UserHandler == nil {
		return fmt.Errorf("UserHandler is nil")
	}

	if opts.TokenHandler == nil {
		return fmt.Errorf("TokenHandler is nil")
	}

	if opts.IssuerHandler == nil {
		return fmt.Errorf("IssuerHandler is nil")
	}

	if opts.ClientID == "" {
		return fmt.Errorf("ClientID is empty")
	}

	if opts.ClientSecret == "" {
		return fmt.Errorf("ClientSecret is empty")
	}

	if opts.RedirectURI == "" {
		return fmt.Errorf("RedirectURI is empty")
	}

	return nil
}

type handler struct {
	userHandler   models.UserGetter
	tokenHandler  models.TokenGetter
	issuerHandler models.IssuerGetter
	clientID      string
	clientSecret  string
	redirectURI   string
}

func NewHandler(opts Options) (*handler, error) {
	return &handler{
		userHandler:   opts.UserHandler,
		tokenHandler:  opts.TokenHandler,
		issuerHandler: opts.IssuerHandler,
		clientID:      opts.ClientID,
		clientSecret:  opts.ClientSecret,
		redirectURI:   opts.RedirectURI,
	}, nil
}

func (h *handler) NewAuthorizationServer() (models.AuthorizationServer, error) {
	asManager, err := h.newASManager()
	if err != nil {
		return nil, err
	}

	asConfig := asserver.NewConfig()

	as := asserver.NewServer(asConfig, asManager)

	asHandlers, err := newASHandlers(ASHandlersOptions{})
	if err != nil {
		return nil, err
	}

	as.SetPasswordAuthorizationHandler(asHandlers.passwordAuthorization)
	as.SetUserAuthorizationHandler(asHandlers.userAuthorization)
	as.SetInternalErrorHandler(asHandlers.internalError)
	as.SetResponseErrorHandler(asHandlers.responseError)
	as.SetExtensionFieldsHandler(h.tokenHandler.ExtensionFieldsHandler)

	return as, nil
}

func (h *handler) newASManager() (*asmanage.Manager, error) {
	manager := asmanage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(asmanage.DefaultAuthorizeCodeTokenCfg)
	manager.MustTokenStorage(asstore.NewMemoryTokenStore())
	manager.MapAccessGenerate(h.tokenHandler)

	clientStore := asstore.NewClientStore()
	clientStore.Set(h.clientID, &asmodels.Client{
		ID:     h.clientID,
		Secret: h.clientSecret,
		Domain: h.redirectURI,
	})
	manager.MapClientStorage(clientStore)

	return manager, nil
}
