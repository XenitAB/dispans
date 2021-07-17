package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/phayes/freeport"
	"github.com/stretchr/testify/require"
	"github.com/xenitab/dispans/server"
	"github.com/xenitab/pkg/service"
)

func TestAccessible(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := accessible(c)
	require.NoError(t, err)

	res := rec.Result()

	require.Equal(t, http.StatusOK, res.StatusCode)
}

func TestRestricted(t *testing.T) {
	op := server.NewTesting(t)
	defer op.Close(t)

	jwksHandler, err := newKeyHandler(op.GetURL(t))
	require.NoError(t, err)

	e := echo.New()
	restrictedHandler := middleware.JWTWithConfig(middleware.JWTConfig{
		KeyFunc: jwksHandler.jwtKeyFunc,
	})(restricted)

	// Test without authentication
	reqNoAuth := httptest.NewRequest(http.MethodGet, "/", nil)
	recNoAuth := httptest.NewRecorder()
	cNoAuth := e.NewContext(reqNoAuth, recNoAuth)

	err = restrictedHandler(cNoAuth)
	require.Error(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	token := op.GetToken(t)

	token.SetAuthHeader(req)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = restrictedHandler(c)
	require.NoError(t, err)

	res := rec.Result()

	require.Equal(t, http.StatusOK, res.StatusCode)
}

func TestE2E(t *testing.T) {
	op := server.NewTesting(t)
	defer op.Close(t)

	addr, close := testWebServer(t, op.GetURL(t))
	defer func() {
		err := close()
		require.NoError(t, err)
	}()

	token := op.GetToken(t)

	reqAccessible, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/", addr), nil)
	require.NoError(t, err)
	resAccessible, err := http.DefaultClient.Do(reqAccessible)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, resAccessible.StatusCode)

	reqRestrictedNoAuth, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/restricted", addr), nil)
	require.NoError(t, err)
	resRestrictedNoAuth, err := http.DefaultClient.Do(reqRestrictedNoAuth)
	require.NoError(t, err)

	require.Equal(t, http.StatusBadRequest, resRestrictedNoAuth.StatusCode)

	reqRestricted, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/restricted", addr), nil)
	require.NoError(t, err)
	token.SetAuthHeader(reqRestricted)
	resRestricted, err := http.DefaultClient.Do(reqRestricted)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, resRestricted.StatusCode)
}

func testWebServer(t *testing.T, issuer string) (string, func() error) {
	errGroup, ctx, cancel := service.NewErrGroupAndContext()

	port, err := freeport.GetFreePort()
	require.NoError(t, err)

	addr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port))

	web, err := newWebHandler(issuer, addr)
	require.NoError(t, err)

	service.Start(ctx, errGroup, web)

	close := func() error {
		cancel()

		timeoutCtx, timeoutCancel := service.NewShutdownTimeoutContext()
		defer timeoutCancel()

		service.Stop(timeoutCtx, errGroup, web)

		return service.WaitForErrGroup(errGroup)
	}

	return addr, close
}
