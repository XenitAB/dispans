package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/require"
	"github.com/xenitab/dispans/authority"
	"github.com/xenitab/dispans/key"
)

const (
	testClientID        = "foo-client"
	testClientSecret    = "foobar"
	testRedirectURIHost = "localhost:9094"
	testRedirectURIPath = "/oauth2"
	testUsername        = "test"
	testPassword        = "test"
	testDefaultScope    = "all"
)

var (
	testRedirectURI = fmt.Sprintf("http://%s%s", testRedirectURIHost, testRedirectURIPath)
)

func TestAuthorizeWithoutCookie(t *testing.T) {
	handlers := testNewHandlers(t)

	oauthInfo := testGetOAuthInformation(t, testDefaultScope)

	req := httptest.NewRequest("GET", oauthInfo.authzURLString, nil)
	w := httptest.NewRecorder()
	handlers.authorize(w, req)
	res := w.Result()

	require.Equal(t, http.StatusFound, res.StatusCode)
	require.Contains(t, res.Header.Get("Location"), "/login")
}

func TestLoginGet(t *testing.T) {
	handlers := testNewHandlers(t)

	oauthInfo := testGetOAuthInformation(t, testDefaultScope)

	cookies := testGetAuthorizeCookie(t, handlers, oauthInfo)

	req := httptest.NewRequest("GET", "/login", nil)
	testAddCookiesToRequest(t, req, cookies)

	w := httptest.NewRecorder()
	handlers.login(w, req)
	res := w.Result()

	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Contains(t, res.Header.Get("Content-Type"), "text/html")
}

func TestLoginPost(t *testing.T) {
	handlers := testNewHandlers(t)

	oauthInfo := testGetOAuthInformation(t, testDefaultScope)

	_ = testGetAuthorizeCookieAndLogin(t, handlers, oauthInfo)
}

func TestLoginWithWrongUsername(t *testing.T) {
	handlers := testNewHandlers(t)

	oauthInfo := testGetOAuthInformation(t, testDefaultScope)

	cookies := testGetAuthorizeCookie(t, handlers, oauthInfo)

	reqForm := url.Values{}
	reqForm.Add("username", "wrong-username")
	reqForm.Add("password", "wrong-password")

	req := httptest.NewRequest("POST", "/login", strings.NewReader(reqForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	testAddCookiesToRequest(t, req, cookies)

	w := httptest.NewRecorder()
	handlers.login(w, req)
	res := w.Result()

	require.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

func TestAuthorizeWithCookie(t *testing.T) {
	handlers := testNewHandlers(t)

	oauthInfo := testGetOAuthInformation(t, testDefaultScope)

	_ = testGetAuthorizationCode(t, handlers, oauthInfo)
}

func TestToken(t *testing.T) {
	handlers := testNewHandlers(t)

	oauthInfo := testGetOAuthInformation(t, testDefaultScope)

	code := testGetAuthorizationCode(t, handlers, oauthInfo)

	tokenResponse := testGetToken(t, handlers, oauthInfo, code)
	require.Empty(t, tokenResponse.IDToken)
}

func TestIDToken(t *testing.T) {
	handlers := testNewHandlers(t)

	oauthInfo := testGetOAuthInformation(t, "openid")

	code := testGetAuthorizationCode(t, handlers, oauthInfo)

	tokenResponse := testGetToken(t, handlers, oauthInfo, code)
	require.NotEmpty(t, tokenResponse.IDToken)
}

func TestTestEndpoint(t *testing.T) {
	handlers := testNewHandlers(t)

	oauthInfo := testGetOAuthInformation(t, testDefaultScope)

	code := testGetAuthorizationCode(t, handlers, oauthInfo)

	tokenResponse := testGetToken(t, handlers, oauthInfo, code)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Add("Authorization", fmt.Sprintf("%s %s", tokenResponse.TokenType, tokenResponse.AccessToken))

	w := httptest.NewRecorder()
	handlers.test(w, req)
	res := w.Result()

	require.Equal(t, http.StatusOK, res.StatusCode)

	bodyBytes, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	err = res.Body.Close()
	require.NoError(t, err)

	var data struct {
		ExpiresIn int64  `json:"expires_in"`
		ClientID  string `json:"client_id"`
		Username  string `json:"user_id"`
	}

	err = json.Unmarshal(bodyBytes, &data)
	require.NoError(t, err)

	require.Equal(t, testUsername, data.Username)
	require.Equal(t, testClientID, data.ClientID)
}

func TestJwk(t *testing.T) {
	handlers := testNewHandlers(t)

	oauthInfo := testGetOAuthInformation(t, "openid profile email")

	code := testGetAuthorizationCode(t, handlers, oauthInfo)

	tokenResponse := testGetToken(t, handlers, oauthInfo, code)

	req := httptest.NewRequest("GET", "/jwk", nil)

	w := httptest.NewRecorder()
	handlers.jwk(w, req)
	res := w.Result()

	require.Equal(t, http.StatusOK, res.StatusCode)

	bodyBytes, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	err = res.Body.Close()
	require.NoError(t, err)

	keySet, err := jwk.Parse(bodyBytes)
	require.NoError(t, err)

	accessToken, err := jwt.Parse([]byte(tokenResponse.AccessToken), jwt.WithKeySet(keySet))
	require.NoError(t, err)

	require.Equal(t, handlers.issuerHandler.GetIssuer(), accessToken.Issuer())
	require.Equal(t, testClientID, accessToken.Audience()[0])
	require.Equal(t, testUsername, accessToken.Subject())
	require.WithinDuration(t, time.Now(), accessToken.NotBefore(), 1*time.Second)
	require.WithinDuration(t, time.Now().Add(2*time.Hour), accessToken.Expiration(), 1*time.Second)

	idToken, err := jwt.Parse([]byte(tokenResponse.IDToken), jwt.WithKeySet(keySet))
	require.NoError(t, err)

	require.Equal(t, handlers.issuerHandler.GetIssuer(), idToken.Issuer())
	require.Equal(t, testClientID, idToken.Audience()[0])
	require.Equal(t, testUsername, idToken.Subject())
	require.Equal(t, "test testsson", idToken.PrivateClaims()["name"])
	require.Equal(t, "test@test.com", idToken.PrivateClaims()["email"])
	require.WithinDuration(t, time.Now(), idToken.NotBefore(), 1*time.Second)
	require.WithinDuration(t, time.Now().Add(2*time.Hour), idToken.Expiration(), 1*time.Second)
}

func TestDiscovery(t *testing.T) {
	handlers := testNewHandlers(t)

	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)

	w := httptest.NewRecorder()
	handlers.discovery(w, req)
	res := w.Result()

	require.Equal(t, http.StatusOK, res.StatusCode)

	bodyBytes, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	err = res.Body.Close()
	require.NoError(t, err)

	var discoveryData struct {
		Issuer  string `json:"issuer"`
		JwksUri string `json:"jwks_uri"`
	}

	err = json.Unmarshal(bodyBytes, &discoveryData)
	require.NoError(t, err)

	require.Equal(t, handlers.issuerHandler.GetIssuer(), discoveryData.Issuer)
	require.Contains(t, discoveryData.JwksUri, "/jwk")
}

func testAddCookiesToRequest(t *testing.T, req *http.Request, cookies []*http.Cookie) {
	t.Helper()

	require.GreaterOrEqual(t, len(cookies), 1)

	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
}

func testGetAuthorizeCookie(t *testing.T, handlers *handlers, oauthInfo testOAuthInformation) []*http.Cookie {
	t.Helper()

	req := httptest.NewRequest("GET", oauthInfo.authzURLString, nil)
	w := httptest.NewRecorder()
	handlers.authorize(w, req)
	res := w.Result()

	require.Equal(t, http.StatusFound, res.StatusCode)
	require.Contains(t, res.Header["Location"], "/login")

	return res.Cookies()
}

func testGetAuthorizeCookieAndLogin(t *testing.T, handlers *handlers, oauthInfo testOAuthInformation) []*http.Cookie {
	cookies := testGetAuthorizeCookie(t, handlers, oauthInfo)

	reqForm := url.Values{}
	reqForm.Add("username", testUsername)
	reqForm.Add("password", testPassword)

	req := httptest.NewRequest("POST", "/login", strings.NewReader(reqForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	testAddCookiesToRequest(t, req, cookies)

	w := httptest.NewRecorder()
	handlers.login(w, req)
	res := w.Result()

	require.Equal(t, http.StatusFound, res.StatusCode)
	require.Contains(t, res.Header.Get("Location"), "/oauth/authorize")

	return cookies
}

func testGetAuthorizationCode(t *testing.T, handlers *handlers, oauthInfo testOAuthInformation) string {
	cookies := testGetAuthorizeCookieAndLogin(t, handlers, oauthInfo)

	req := httptest.NewRequest("GET", "/oauth/authorize", nil)
	testAddCookiesToRequest(t, req, cookies)

	w := httptest.NewRecorder()
	handlers.authorize(w, req)
	res := w.Result()

	require.Equal(t, http.StatusFound, res.StatusCode)

	resLocationURL, err := url.Parse(res.Header.Get("Location"))
	require.NoError(t, err)

	require.Equal(t, testRedirectURIHost, resLocationURL.Host)
	require.Equal(t, testRedirectURIPath, resLocationURL.Path)

	queryValues := resLocationURL.Query()
	require.NotEmpty(t, queryValues.Get("code"))
	require.Equal(t, oauthInfo.state, queryValues.Get("state"))

	return queryValues.Get("code")
}

func testGetToken(t *testing.T, handlers *handlers, oauthInfo testOAuthInformation, code string) testTokenResponse {
	t.Helper()

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", testClientID)
	data.Set("code_verifier", oauthInfo.codeVerifier)
	data.Set("code", code)
	data.Set("redirect_uri", testRedirectURI)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(testClientID), url.QueryEscape(testClientSecret))

	w := httptest.NewRecorder()
	handlers.token(w, req)
	res := w.Result()

	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Contains(t, res.Header.Get("Content-Type"), "application/json")

	bodyBytes, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	err = res.Body.Close()
	require.NoError(t, err)

	var tokenResponse testTokenResponse

	err = json.Unmarshal(bodyBytes, &tokenResponse)
	require.NoError(t, err)

	return tokenResponse
}

func testNewHandlers(t *testing.T) *handlers {
	t.Helper()

	opts := Options{
		Address:      "0.0.0.0",
		Port:         9096,
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		RedirectURI:  testRedirectURI,
	}

	keyHandler, err := key.NewHandler()
	require.NoError(t, err)

	srv := &serverHandler{
		keyHandler: keyHandler,
	}

	authorityOpts := authority.Options{
		Issuer: "http://test.foo",
	}

	authorityHandler, err := authority.NewHandler(authorityOpts)
	require.NoError(t, err)

	as, err := srv.newAS(opts, authorityHandler)
	require.NoError(t, err)

	handlersOpts := HandlersOptions{
		AuthorizationServer: as,
		PublicKeyHandler:    keyHandler,
		IssuerHandler:       authorityHandler,
	}

	handlers, err := newHandlers(handlersOpts)
	require.NoError(t, err)

	return handlers
}

func testGenerateCodeChallengeS256(t *testing.T) (string, string) {
	t.Helper()

	codeVerifier := testGenerateRandomString(t, 32)

	s256 := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.URLEncoding.EncodeToString(s256[:])

	return codeVerifier, codeChallenge
}

func testGenerateState(t *testing.T) string {
	t.Helper()

	stateString := testGenerateRandomString(t, 32)

	s256 := sha256.Sum256([]byte(stateString))
	state := base64.URLEncoding.EncodeToString(s256[:])
	state = strings.TrimSuffix(state, "=")

	return state
}

func testGenerateRandomString(t *testing.T, length int) string {
	t.Helper()

	result := ""
	for {
		if len(result) >= length {
			return result
		}

		num, err := rand.Int(rand.Reader, big.NewInt(int64(127)))
		require.NoError(t, err)

		n := num.Int64()

		if n > 32 && n < 127 {
			result += fmt.Sprint(n)
		}
	}
}

type testOAuthInformation struct {
	authzURL       *url.URL
	authzURLString string
	codeVerifier   string
	codeChallange  string
	state          string
}

type testTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token"`
}

func testGetOAuthInformation(t *testing.T, scope string) testOAuthInformation {
	t.Helper()

	codeVerifier, codeChallange := testGenerateCodeChallengeS256(t)
	state := testGenerateState(t)

	authzUrl := &url.URL{}
	authzUrl.Path = "/oauth/authorize"

	query := url.Values{}
	query.Add("client_id", testClientID)
	query.Add("code_challenge", codeChallange)
	query.Add("code_challenge_method", "S256")
	query.Add("redirect_uri", testRedirectURI)
	query.Add("response_type", "code")
	query.Add("scope", scope)
	query.Add("state", state)

	authzUrl.RawQuery = query.Encode()

	return testOAuthInformation{
		authzURL:       authzUrl,
		authzURLString: authzUrl.String(),
		codeVerifier:   codeVerifier,
		codeChallange:  codeChallange,
		state:          state,
	}
}
