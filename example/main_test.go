package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/phayes/freeport"
	"github.com/stretchr/testify/require"
	"github.com/xenitab/dispans/server"
	"github.com/xenitab/pkg/echo-v4-middleware/oidc"
	"github.com/xenitab/pkg/service"
	"golang.org/x/oauth2"
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

	e := echo.New()
	restrictedHandler := oidc.OIDCWithConfig(oidc.OIDCConfig{
		Issuer:            op.GetURL(t),
		RequiredTokenType: "JWT+AT",
		RequiredAudience:  "test-client",
	})(restricted)

	// Test without authentication
	reqNoAuth := httptest.NewRequest(http.MethodGet, "/", nil)
	recNoAuth := httptest.NewRecorder()
	cNoAuth := e.NewContext(reqNoAuth, recNoAuth)

	err := restrictedHandler(cNoAuth)
	require.Error(t, err)

	// Test with authentication
	token := op.GetToken(t)
	testRestrictedWithAuthentication(t, token, restrictedHandler, e)
	testRestrictedFailIDToken(t, token, restrictedHandler, e)

	// Test with rotated key
	op.RotateKeys(t)
	tokenWithRotatedKey := op.GetToken(t)
	testRestrictedWithAuthentication(t, tokenWithRotatedKey, restrictedHandler, e)

}

func testRestrictedWithAuthentication(t *testing.T, token *oauth2.Token, restrictedHandler echo.HandlerFunc, e *echo.Echo) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	token.Valid()
	token.SetAuthHeader(req)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := restrictedHandler(c)
	require.NoError(t, err)

	res := rec.Result()

	require.Equal(t, http.StatusOK, res.StatusCode)
}

func testRestrictedFailIDToken(t *testing.T, token *oauth2.Token, restrictedHandler echo.HandlerFunc, e *echo.Echo) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	idToken, ok := token.Extra("id_token").(string)
	require.True(t, ok)

	token.AccessToken = idToken

	token.SetAuthHeader(req)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := restrictedHandler(c)
	require.Error(t, err)
	require.Contains(t, err.Error(), "type \"JWT+AT\" required, but received: JWT")
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
