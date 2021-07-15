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
	"github.com/xenitab/dispans/as"
	"github.com/xenitab/dispans/authority"
	"github.com/xenitab/dispans/helper"
	"github.com/xenitab/dispans/key"
	"github.com/xenitab/dispans/models"
	"github.com/xenitab/dispans/token"
	"github.com/xenitab/dispans/user"
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
	helper := testPrepareE2E(t)
	defer helper.testServer.Close()

	// Request #1 - GET /oauth/authorize without cookies
	testGetAuthorizeE2E(t, helper)

	// Request #2 - GET /login
	testGetLoginE2E(t, helper)

	// Request #3 - POST /login
	testPostLoginE2E(t, helper)

	// Request #4 - GET /oauth/authorize
	code, _ := getAuthorizeWithCookiesE2E(t, helper)

	// Request #5 - POST /oauth/token
	tokenResponseBytes := testPostTokenE2E(t, helper, code)

	// Request #6 - GET /jwk
	keySet := testGetJwksE2E(t, helper)

	// Validate token
	testValidateTokenResponse(t, helper, tokenResponseBytes, keySet)

	// Validate discovery
	testDiscoveryE2E(t, helper)
}

func TestKeyRotationE2E(t *testing.T) {
	helper := testPrepareE2E(t)
	defer helper.testServer.Close()

	// Get first token response
	testGetAuthorizeE2E(t, helper)
	testGetLoginE2E(t, helper)
	testPostLoginE2E(t, helper)
	firstCode, _ := getAuthorizeWithCookiesE2E(t, helper)
	firstTokenResponseBytes := testPostTokenE2E(t, helper, firstCode)

	// Get Jwks with only one key
	firstKeySet := testGetJwksE2E(t, helper)
	require.Equal(t, 1, firstKeySet.Len())
	testValidateTokenResponse(t, helper, firstTokenResponseBytes, firstKeySet)

	// Clear cookies and add key
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	helper.httpClient.Jar = jar
	err = helper.keyHandler.AddNewKey()
	require.NoError(t, err)

	// Get second token response
	testGetAuthorizeE2E(t, helper)
	testGetLoginE2E(t, helper)
	testPostLoginE2E(t, helper)
	secondCode, _ := getAuthorizeWithCookiesE2E(t, helper)
	secondTokenResponseBytes := testPostTokenE2E(t, helper, secondCode)

	// Get Jwks with only one key
	secondKeySet := testGetJwksE2E(t, helper)
	require.Equal(t, 2, secondKeySet.Len())
	testValidateTokenResponse(t, helper, secondTokenResponseBytes, secondKeySet)

	// Validate that the token is signed with the second key
	firstKey, ok := secondKeySet.Get(0)
	require.True(t, ok)
	invalidKeySet := jwk.NewSet()
	invalidKeySet.Add(firstKey)
	require.Equal(t, firstKeySet, invalidKeySet)
	secondKey, ok := secondKeySet.Get(1)
	require.True(t, ok)
	validKeySet := jwk.NewSet()
	validKeySet.Add(secondKey)

	testValidateTokenResponseFailure(t, helper, secondTokenResponseBytes, invalidKeySet)
	testValidateTokenResponse(t, helper, secondTokenResponseBytes, validKeySet)

	// Remove the oldest key and validate that Jwks only contains the new one
	err = helper.keyHandler.RemoveOldestKey()
	require.NoError(t, err)
	thirdKeySet := testGetJwksE2E(t, helper)
	require.Equal(t, 1, thirdKeySet.Len())
	testValidateTokenResponse(t, helper, secondTokenResponseBytes, thirdKeySet)
}

type testE2EHelper struct {
	testServer    *httptest.Server
	httpClient    *http.Client
	keyHandler    models.KeysUpdater
	remote        string
	clientID      string
	clientSecret  string
	redirectURI   string
	codeVerifier  string
	codeChallange string
	state         string
}

func testPrepareE2E(t *testing.T) testE2EHelper {
	t.Helper()

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

	return testE2EHelper{
		testServer:    testServer,
		httpClient:    httpClient,
		keyHandler:    keyHandler,
		remote:        testServer.URL,
		clientID:      clientID,
		clientSecret:  clientSecret,
		redirectURI:   redirectURI,
		codeVerifier:  codeVerifier,
		codeChallange: codeChallange,
		state:         state,
	}
}

func testGetAuthorizeE2E(t *testing.T, helper testE2EHelper) {
	t.Helper()

	remoteUrl, err := url.Parse(helper.remote)
	require.NoError(t, err)

	remoteUrl.Path = "/oauth/authorize"

	query := url.Values{}
	query.Add("client_id", helper.clientID)
	query.Add("code_challenge", helper.codeChallange)
	query.Add("code_challenge_method", "S256")
	query.Add("redirect_uri", helper.redirectURI)
	query.Add("response_type", "code")
	query.Add("scope", "all")
	query.Add("state", helper.state)

	remoteUrl.RawQuery = query.Encode()

	req, err := http.NewRequest("GET", remoteUrl.String(), nil)
	require.NoError(t, err)

	require.Empty(t, helper.httpClient.Jar.Cookies(remoteUrl))

	res, err := helper.httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusFound, res.StatusCode)

	resLocation := res.Header.Get("location")
	require.Contains(t, resLocation, "/login")
	require.NotEmpty(t, helper.httpClient.Jar.Cookies(remoteUrl))
}

func testGetLoginE2E(t *testing.T, helper testE2EHelper) {
	t.Helper()

	remoteUrl, err := url.Parse(helper.remote)
	require.NoError(t, err)
	remoteUrl.Path = "/login"

	req, err := http.NewRequest("GET", remoteUrl.String(), nil)
	require.NoError(t, err)

	res, err := helper.httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, res.StatusCode)
}

func testPostLoginE2E(t *testing.T, helper testE2EHelper) {
	t.Helper()

	remoteUrl, err := url.Parse(helper.remote)
	require.NoError(t, err)
	remoteUrl.Path = "/login"

	form := url.Values{}
	form.Add("username", "test")
	form.Add("password", "test")

	body := strings.NewReader(form.Encode())

	req, err := http.NewRequest("POST", remoteUrl.String(), body)
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := helper.httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusFound, res.StatusCode)
	resLocation := res.Header.Get("location")
	require.Contains(t, resLocation, "/oauth/authorize")
}

func getAuthorizeWithCookiesE2E(t *testing.T, helper testE2EHelper) (string, string) {
	t.Helper()

	remoteUrl, err := url.Parse(helper.remote)
	require.NoError(t, err)
	remoteUrl.Path = "/oauth/authorize"

	req, err := http.NewRequest("GET", remoteUrl.String(), nil)
	require.NoError(t, err)

	res, err := helper.httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusFound, res.StatusCode)
	resLocation := res.Header.Get("location")
	require.Contains(t, resLocation, helper.redirectURI)

	resLocationUrl, err := url.Parse(res.Header.Get("location"))
	require.NoError(t, err)

	code := resLocationUrl.Query().Get("code")
	resState := resLocationUrl.Query().Get("state")
	require.NotEmpty(t, code)
	require.Equal(t, helper.state, resState)

	return code, resState
}

func testPostTokenE2E(t *testing.T, helper testE2EHelper, code string) []byte {
	t.Helper()

	remoteUrl, err := url.Parse(helper.remote)
	require.NoError(t, err)
	remoteUrl.Path = "/oauth/token"

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", helper.clientID)
	data.Set("code_verifier", helper.codeVerifier)
	data.Set("code", code)
	data.Set("redirect_uri", helper.redirectURI)

	body := strings.NewReader(data.Encode())

	req, err := http.NewRequest("POST", remoteUrl.String(), body)
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(helper.clientID), url.QueryEscape(helper.clientSecret))

	res, err := helper.httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, res.StatusCode)

	bodyBytes, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	err = res.Body.Close()
	require.NoError(t, err)

	return bodyBytes
}

func testGetJwksE2E(t *testing.T, helper testE2EHelper) jwk.Set {
	t.Helper()

	remoteUrl, err := url.Parse(helper.remote)
	require.NoError(t, err)
	remoteUrl.Path = "/jwks"

	req, err := http.NewRequest("GET", remoteUrl.String(), nil)
	require.NoError(t, err)

	res, err := helper.httpClient.Do(req)
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

func testDiscoveryE2E(t *testing.T, helper testE2EHelper) {
	t.Helper()

	remoteUrl, err := url.Parse(helper.remote)
	require.NoError(t, err)
	remoteUrl.Path = "/.well-known/openid-configuration"

	req, err := http.NewRequest("GET", remoteUrl.String(), nil)
	require.NoError(t, err)

	res, err := helper.httpClient.Do(req)
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

	require.Equal(t, helper.remote, discoveryData.Issuer)
	require.Equal(t, fmt.Sprintf("%s/jwk", helper.remote), discoveryData.JwksUri)
}

type testTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token"`
}

func testValidateTokenResponse(t *testing.T, helper testE2EHelper, tokenResponseBytes []byte, keySet jwk.Set) {
	var tokenResponse testTokenResponse
	err := json.Unmarshal(tokenResponseBytes, &tokenResponse)
	require.NoError(t, err)

	token, err := jwt.Parse([]byte(tokenResponse.AccessToken), jwt.WithKeySet(keySet))
	require.NoError(t, err)

	require.Equal(t, helper.remote, token.Issuer())
	require.Equal(t, helper.clientID, token.Audience()[0])
	require.Equal(t, "test", token.Subject())
	require.WithinDuration(t, time.Now(), token.NotBefore(), 1*time.Second)
	require.WithinDuration(t, time.Now().Add(2*time.Hour), token.Expiration(), 1*time.Second)
}

func testValidateTokenResponseFailure(t *testing.T, helper testE2EHelper, tokenResponseBytes []byte, keySet jwk.Set) {
	var tokenResponse testTokenResponse
	err := json.Unmarshal(tokenResponseBytes, &tokenResponse)
	require.NoError(t, err)

	_, err = jwt.Parse([]byte(tokenResponse.AccessToken), jwt.WithKeySet(keySet))
	require.Error(t, err)
}
