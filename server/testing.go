package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xenitab/dispans/helper"
	"github.com/xenitab/dispans/key"
	"github.com/xenitab/dispans/models"
	"golang.org/x/oauth2"
)

type handlerTesting struct {
	httpTestServer *httptest.Server
	keyHandler     models.KeysUpdater
	clientID       string
	clientSecret   string
	redirectURI    string
}

func NewTesting(t *testing.T) *handlerTesting {
	t.Helper()

	testServer := httptest.NewServer(nil)

	hostPort := testServer.Listener.Addr().String()
	addr := strings.Split(hostPort, ":")[0]
	portString := strings.Split(hostPort, ":")[1]

	port, err := strconv.Atoi(portString)
	require.NoError(t, err)

	clientID := "test-client"
	clientSecret := "test-secret"
	redirectURI := "http://test.foo.bar/callback"

	keyHandler, err := key.NewHandler()
	require.NoError(t, err)

	opts := Options{
		Address:      addr,
		Port:         port,
		Issuer:       testServer.URL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
		keyHandler:   keyHandler,
	}

	err = opts.Validate()
	require.NoError(t, err)

	router, err := new(opts)
	require.NoError(t, err)

	testServer.Config.Handler = router

	return &handlerTesting{
		httpTestServer: testServer,
		keyHandler:     keyHandler,
		clientID:       clientID,
		clientSecret:   clientSecret,
		redirectURI:    redirectURI,
	}
}

func (h *handlerTesting) Close(t *testing.T) {
	t.Helper()

	h.httpTestServer.Close()
}

func (h *handlerTesting) GetURL(t *testing.T) string {
	t.Helper()

	return h.httpTestServer.URL
}

func (h *handlerTesting) GetClientID(t *testing.T) string {
	t.Helper()

	return h.clientID
}

func (h *handlerTesting) GetClientSecret(t *testing.T) string {
	t.Helper()

	return h.clientSecret
}

func (h *handlerTesting) GetRedirectURI(t *testing.T) string {
	t.Helper()

	return h.redirectURI
}

func (h *handlerTesting) RotateKeys(t *testing.T) {
	t.Helper()

	err := h.keyHandler.AddNewKey()
	require.NoError(t, err)

	err = h.keyHandler.RemoveOldestKey()
	require.NoError(t, err)

}

func (h *handlerTesting) GetToken(t *testing.T) *oauth2.Token {
	t.Helper()

	codeVerifier, codeChallange, err := helper.GenerateCodeChallengeS256()
	require.NoError(t, err)

	state, err := helper.GenerateState()
	require.NoError(t, err)

	httpClient := h.httpTestServer.Client()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	httpClient.Jar = jar
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	h.getAuhtorize(t, httpClient, codeChallange, state)
	h.getLogin(t, httpClient)
	h.postLogin(t, httpClient)
	code := h.getAuthorizeWithCookies(t, httpClient, state)
	tokenResponseBytes := h.postToken(t, httpClient, code, codeVerifier)

	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
		TokenType    string `json:"token_type"`
		IDToken      string `json:"id_token"`
	}

	err = json.Unmarshal(tokenResponseBytes, &tokenResponse)

	token := oauth2.Token{
		TokenType:    tokenResponse.TokenType,
		AccessToken:  tokenResponse.AccessToken,
		RefreshToken: tokenResponse.RefreshToken,
		Expiry:       time.Now().Add(time.Second * time.Duration(tokenResponse.ExpiresIn)),
	}

	tokenExtras := map[string]interface{}{}
	tokenExtras["id_token"] = tokenResponse.IDToken
	tokenExtras["scope"] = tokenResponse.Scope

	return token.WithExtra(tokenExtras)
}

func (h *handlerTesting) getAuhtorize(t *testing.T, httpClient *http.Client, codeChallange, state string) {
	t.Helper()

	remoteUrl, err := url.Parse(h.GetURL(t))
	require.NoError(t, err)

	remoteUrl.Path = "/oauth/authorize"

	query := url.Values{}
	query.Add("client_id", h.clientID)
	query.Add("code_challenge", codeChallange)
	query.Add("code_challenge_method", "S256")
	query.Add("redirect_uri", h.redirectURI)
	query.Add("response_type", "code")
	query.Add("scope", "openid")
	query.Add("state", state)

	remoteUrl.RawQuery = query.Encode()

	req, err := http.NewRequest("GET", remoteUrl.String(), nil)
	require.NoError(t, err)

	res, err := httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusFound, res.StatusCode)
}

func (h *handlerTesting) getLogin(t *testing.T, httpClient *http.Client) {
	t.Helper()

	remoteUrl, err := url.Parse(h.GetURL(t))
	require.NoError(t, err)
	remoteUrl.Path = "/login"

	req, err := http.NewRequest("GET", remoteUrl.String(), nil)
	require.NoError(t, err)

	res, err := httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, res.StatusCode)
}

func (h *handlerTesting) postLogin(t *testing.T, httpClient *http.Client) {
	t.Helper()

	remoteUrl, err := url.Parse(h.GetURL(t))
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
}

func (h *handlerTesting) getAuthorizeWithCookies(t *testing.T, httpClient *http.Client, state string) string {
	t.Helper()

	remoteUrl, err := url.Parse(h.GetURL(t))
	require.NoError(t, err)
	remoteUrl.Path = "/oauth/authorize"

	req, err := http.NewRequest("GET", remoteUrl.String(), nil)
	require.NoError(t, err)

	res, err := httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusFound, res.StatusCode)
	resLocation := res.Header.Get("location")
	require.Contains(t, resLocation, h.redirectURI)

	resLocationUrl, err := url.Parse(res.Header.Get("location"))
	require.NoError(t, err)

	code := resLocationUrl.Query().Get("code")
	resState := resLocationUrl.Query().Get("state")
	require.NotEmpty(t, code)
	require.Equal(t, state, resState)

	return code
}

func (h *handlerTesting) postToken(t *testing.T, httpClient *http.Client, code, codeVerifier string) []byte {
	t.Helper()

	remoteUrl, err := url.Parse(h.GetURL(t))
	require.NoError(t, err)
	remoteUrl.Path = "/oauth/token"

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", h.clientID)
	data.Set("code_verifier", codeVerifier)
	data.Set("code", code)
	data.Set("redirect_uri", h.redirectURI)

	body := strings.NewReader(data.Encode())

	req, err := http.NewRequest("POST", remoteUrl.String(), body)
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(h.clientID), url.QueryEscape(h.clientSecret))

	res, err := httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, res.StatusCode)

	bodyBytes, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	err = res.Body.Close()
	require.NoError(t, err)

	return bodyBytes
}
