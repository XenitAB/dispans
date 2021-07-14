package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/require"
	"github.com/xenitab/dispans/pkg/as"
	"github.com/xenitab/dispans/pkg/authority"
	"github.com/xenitab/dispans/pkg/helper"
	"github.com/xenitab/dispans/pkg/key"
	"github.com/xenitab/dispans/pkg/token"
	"github.com/xenitab/dispans/pkg/user"
	"github.com/xenitab/pkg/service"
)

func TestOptionsValidate(t *testing.T) {
	cases := []struct {
		testDescription       string
		opts                  Options
		expectedErrorContains string
	}{
		{
			testDescription: "All values valid",
			opts: Options{
				Address:      "0.0.0.0",
				Port:         8080,
				Issuer:       "http://localhost:8080",
				ClientID:     "foo",
				ClientSecret: "bar",
				RedirectURI:  "http://foo.bar/baz",
			},
			expectedErrorContains: "",
		},
		{
			testDescription:       "empty struct",
			opts:                  Options{},
			expectedErrorContains: "Address is empty",
		},
	}

	for i, c := range cases {
		t.Logf("Test  #%d: %s", i, c.testDescription)

		err := c.opts.Validate()
		if c.expectedErrorContains != "" {
			require.Contains(t, err.Error(), c.expectedErrorContains)
			continue
		}

		require.NoError(t, err)
	}
}

func TestNew(t *testing.T) {
	opts := Options{
		Address:      "0.0.0.0",
		Port:         8080,
		Issuer:       "https://localhost:8080",
		ClientID:     "foo",
		ClientSecret: "bar",
		RedirectURI:  "http://foo.bar/baz",
	}

	as, err := New(opts)
	require.NoError(t, err)

	errGroup, ctx, cancel := service.NewErrGroupAndContext()
	defer cancel()

	service.Start(ctx, errGroup, as)

	cancel()

	timeoutCtx, timeoutCancel := service.NewShutdownTimeoutContext()
	defer timeoutCancel()

	service.Stop(timeoutCtx, errGroup, as)

	err = service.WaitForErrGroup(errGroup)
	require.NoError(t, err)
}

func TestAuthorizationServerE2E(t *testing.T) {
	keyHandler, err := key.NewHandler()
	require.NoError(t, err)

	clientID := "foo"
	clientSecret := "bar"
	redirectURI := "http://foo.bar/baz"

	opts := Options{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
	}

	authorityOpts := authority.Options{
		Issuer: "temporary",
	}

	authorityHandler, err := authority.NewHandler(authorityOpts)
	require.NoError(t, err)

	userHandler := user.NewHandler()

	tokenOpts := token.Options{
		UserHandler:       userHandler,
		IssuerHandler:     authorityHandler,
		PrivateKeyHandler: keyHandler,
		SigningMethod:     jwa.ES384,
	}

	tokenHandler, err := token.NewHandler(tokenOpts)
	require.NoError(t, err)

	asOptions := as.Options{
		UserHandler:   userHandler,
		TokenHandler:  tokenHandler,
		IssuerHandler: authorityHandler,
		ClientID:      opts.ClientID,
		ClientSecret:  opts.ClientSecret,
		RedirectURI:   opts.RedirectURI,
	}

	asHandler, err := as.NewHandler(asOptions)
	require.NoError(t, err)

	as, err := asHandler.NewAuthorizationServer()
	require.NoError(t, err)

	router, err := newRouter(as, authorityHandler, keyHandler)
	require.NoError(t, err)

	testServer := httptest.NewServer(router)

	authorityHandler.SetIssuer(testServer.URL)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	httpClient := testServer.Client()
	httpClient.Jar = jar
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	codeVerifier, codeChallange, err := helper.GenerateCodeChallengeS256()
	require.NoError(t, err)

	state, err := helper.GenerateState()
	require.NoError(t, err)

	// Request #1 - GET /oauth/authorize without cookies
	testGetAuthorizeE2E(t, httpClient, testServer.URL, clientID, codeChallange, redirectURI, state)

	// Request #2 - GET /login
	testGetLoginE2E(t, httpClient, testServer.URL)

	// Request #3 - POST /login
	testPostLoginE2E(t, httpClient, testServer.URL)

	// Request #4 - GET /oauth/authorize
	code, _ := getAuthorizeWithCookiesE2E(t, httpClient, testServer.URL, redirectURI, state)

	// Request #5 - POST /oauth/token
	tokenResponseBytes := testPostTokenE2E(t, httpClient, testServer.URL, clientID, clientSecret, codeVerifier, code, redirectURI)

	// Request #6 - GET /jwk
	keySet := testGetJwkE2E(t, httpClient, testServer.URL)

	// Validate token
	testValidateTokenResponse(t, tokenResponseBytes, keySet, clientID, testServer.URL)

	// Validate discovery
	testDiscoveryE2E(t, httpClient, testServer.URL)

	testServer.Close()
}

func testGetAuthorizeE2E(t *testing.T, httpClient *http.Client, remote, clientID, codeChallange, redirectURI, state string) {
	t.Helper()

	remoteUrl, err := url.Parse(remote)
	require.NoError(t, err)

	remoteUrl.Path = "/oauth/authorize"

	query := url.Values{}
	query.Add("client_id", clientID)
	query.Add("code_challenge", codeChallange)
	query.Add("code_challenge_method", "S256")
	query.Add("redirect_uri", redirectURI)
	query.Add("response_type", "code")
	query.Add("scope", "all")
	query.Add("state", state)

	remoteUrl.RawQuery = query.Encode()

	req, err := http.NewRequest("GET", remoteUrl.String(), nil)
	require.NoError(t, err)

	require.Empty(t, httpClient.Jar.Cookies(remoteUrl))

	res, err := httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusFound, res.StatusCode)

	resLocation := res.Header.Get("location")
	require.Contains(t, resLocation, "/login")
	require.NotEmpty(t, httpClient.Jar.Cookies(remoteUrl))
}

func testGetLoginE2E(t *testing.T, httpClient *http.Client, remote string) {
	t.Helper()

	remoteUrl, err := url.Parse(remote)
	require.NoError(t, err)
	remoteUrl.Path = "/login"

	req, err := http.NewRequest("GET", remoteUrl.String(), nil)
	require.NoError(t, err)

	res, err := httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, res.StatusCode)
}

func testPostLoginE2E(t *testing.T, httpClient *http.Client, remote string) {
	t.Helper()

	remoteUrl, err := url.Parse(remote)
	require.NoError(t, err)
	remoteUrl.Path = "/login"

	form := url.Values{}
	form.Add("username", "test")
	form.Add("password", "test")

	body := strings.NewReader(form.Encode())

	req, err := http.NewRequest("POST", remoteUrl.String(), body)
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusFound, res.StatusCode)
	resLocation := res.Header.Get("location")
	require.Contains(t, resLocation, "/oauth/authorize")
}

func getAuthorizeWithCookiesE2E(t *testing.T, httpClient *http.Client, remote, redirectURI, state string) (string, string) {
	t.Helper()

	remoteUrl, err := url.Parse(remote)
	require.NoError(t, err)
	remoteUrl.Path = "/oauth/authorize"

	req, err := http.NewRequest("GET", remoteUrl.String(), nil)
	require.NoError(t, err)

	res, err := httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusFound, res.StatusCode)
	resLocation := res.Header.Get("location")
	require.Contains(t, resLocation, redirectURI)

	resLocationUrl, err := url.Parse(res.Header.Get("location"))
	require.NoError(t, err)

	code := resLocationUrl.Query().Get("code")
	resState := resLocationUrl.Query().Get("state")
	require.NotEmpty(t, code)
	require.Equal(t, state, resState)

	return code, resState
}

func testPostTokenE2E(t *testing.T, httpClient *http.Client, remote, clientID, clientSecret, codeVerifier, code, redirectURI string) []byte {
	t.Helper()

	remoteUrl, err := url.Parse(remote)
	require.NoError(t, err)
	remoteUrl.Path = "/oauth/token"

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", clientID)
	data.Set("code_verifier", codeVerifier)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)

	body := strings.NewReader(data.Encode())

	req, err := http.NewRequest("POST", remoteUrl.String(), body)
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))

	res, err := httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, res.StatusCode)

	bodyBytes, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	err = res.Body.Close()
	require.NoError(t, err)

	return bodyBytes
}

func testGetJwkE2E(t *testing.T, httpClient *http.Client, remote string) jwk.Set {
	t.Helper()

	remoteUrl, err := url.Parse(remote)
	require.NoError(t, err)
	remoteUrl.Path = "/jwk"

	req, err := http.NewRequest("GET", remoteUrl.String(), nil)
	require.NoError(t, err)

	res, err := httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, res.StatusCode)

	bodyBytes, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	err = res.Body.Close()
	require.NoError(t, err)

	keySet, err := jwk.Parse(bodyBytes)
	require.NoError(t, err)

	return keySet
}

func testDiscoveryE2E(t *testing.T, httpClient *http.Client, remote string) {
	t.Helper()

	remoteUrl, err := url.Parse(remote)
	require.NoError(t, err)
	remoteUrl.Path = "/.well-known/openid-configuration"

	req, err := http.NewRequest("GET", remoteUrl.String(), nil)
	require.NoError(t, err)

	res, err := httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, res.StatusCode)

	bodyBytes, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	var discoveryData struct {
		Issuer  string `json:"issuer"`
		JwksUri string `json:"jwks_uri"`
	}

	err = json.Unmarshal(bodyBytes, &discoveryData)
	require.NoError(t, err)

	require.Equal(t, remote, discoveryData.Issuer)
	require.Equal(t, fmt.Sprintf("%s/jwk", remote), discoveryData.JwksUri)
}

type testTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token"`
}

func testValidateTokenResponse(t *testing.T, tokenResponseBytes []byte, keySet jwk.Set, clientID string, remote string) {
	var tokenResponse testTokenResponse
	err := json.Unmarshal(tokenResponseBytes, &tokenResponse)
	require.NoError(t, err)

	token, err := jwt.Parse([]byte(tokenResponse.AccessToken), jwt.WithKeySet(keySet))
	require.NoError(t, err)

	require.Equal(t, remote, token.Issuer())
	require.Equal(t, clientID, token.Audience()[0])
	require.Equal(t, "test", token.Subject())
	require.WithinDuration(t, time.Now(), token.NotBefore(), 1*time.Second)
	require.WithinDuration(t, time.Now().Add(2*time.Hour), token.Expiration(), 1*time.Second)
}
