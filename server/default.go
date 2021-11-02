package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/xenitab/dispans/helper"
	"github.com/xenitab/dispans/key"
	"github.com/xenitab/dispans/models"
	"golang.org/x/oauth2"
)

type opHandler struct {
	httpTestServer *httptest.Server
	keyHandler     models.KeysUpdater
	clientID       string
	clientSecret   string
	redirectURI    string
}

func NewDefault() (*opHandler, error) {
	testServer := httptest.NewServer(nil)

	hostPort := testServer.Listener.Addr().String()
	addr := strings.Split(hostPort, ":")[0]
	portString := strings.Split(hostPort, ":")[1]

	port, err := strconv.Atoi(portString)
	if err != nil {
		return nil, err
	}

	clientID := "test-client"
	clientSecret := "test-secret"
	redirectURI := "http://test.foo.bar/callback"

	keyHandler, err := key.NewHandler()
	if err != nil {
		return nil, err
	}

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
	if err != nil {
		return nil, err
	}

	router, err := new(opts)
	if err != nil {
		return nil, err
	}

	testServer.Config.Handler = router

	return &opHandler{
		httpTestServer: testServer,
		keyHandler:     keyHandler,
		clientID:       clientID,
		clientSecret:   clientSecret,
		redirectURI:    redirectURI,
	}, nil
}

func (h *opHandler) Close() {
	h.httpTestServer.Close()
}

func (h *opHandler) GetURL() string {
	return h.httpTestServer.URL
}

func (h *opHandler) GetClientID() string {
	return h.clientID
}

func (h *opHandler) GetClientSecret() string {
	return h.clientSecret
}

func (h *opHandler) GetRedirectURI() string {
	return h.redirectURI
}

func (h *opHandler) RotateKeys() error {
	err := h.keyHandler.AddNewKey()
	if err != nil {
		return err
	}

	err = h.keyHandler.RemoveOldestKey()
	if err != nil {
		return err
	}

	return nil
}

func (h *opHandler) GetToken() (*oauth2.Token, error) {
	codeVerifier, codeChallange, err := helper.GenerateCodeChallengeS256()
	if err != nil {
		return nil, err
	}

	state, err := helper.GenerateState()
	if err != nil {
		return nil, err
	}
	httpClient := h.httpTestServer.Client()
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	httpClient.Jar = jar
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	h.getAuhtorize(httpClient, codeChallange, state)
	h.getLogin(httpClient)
	h.postLogin(httpClient)
	code, err := h.getAuthorizeWithCookies(httpClient, state)
	if err != nil {
		return nil, err
	}

	tokenResponseBytes, err := h.postToken(httpClient, code, codeVerifier)
	if err != nil {
		return nil, err
	}

	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
		TokenType    string `json:"token_type"`
		IDToken      string `json:"id_token"`
	}

	err = json.Unmarshal(tokenResponseBytes, &tokenResponse)
	if err != nil {
		return nil, err
	}

	token := oauth2.Token{
		TokenType:    tokenResponse.TokenType,
		AccessToken:  tokenResponse.AccessToken,
		RefreshToken: tokenResponse.RefreshToken,
		Expiry:       time.Now().Add(time.Second * time.Duration(tokenResponse.ExpiresIn)),
	}

	tokenExtras := map[string]interface{}{}
	tokenExtras["id_token"] = tokenResponse.IDToken
	tokenExtras["scope"] = tokenResponse.Scope

	return token.WithExtra(tokenExtras), nil
}

func (h *opHandler) getAuhtorize(httpClient *http.Client, codeChallange, state string) error {
	remoteUrl, err := url.Parse(h.GetURL())
	if err != nil {
		return err
	}

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
	if err != nil {
		return err
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}

	if http.StatusFound != res.StatusCode {
		return fmt.Errorf("received wrong status code for authorize request: %d", res.StatusCode)
	}

	return nil
}

func (h *opHandler) getLogin(httpClient *http.Client) error {

	remoteUrl, err := url.Parse(h.GetURL())
	if err != nil {
		return err
	}

	remoteUrl.Path = "/login"

	req, err := http.NewRequest("GET", remoteUrl.String(), nil)
	if err != nil {
		return err
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}

	if http.StatusFound != res.StatusCode {
		return fmt.Errorf("received wrong status code for login request: %d", res.StatusCode)
	}

	return nil
}

func (h *opHandler) postLogin(httpClient *http.Client) error {
	remoteUrl, err := url.Parse(h.GetURL())
	if err != nil {
		return err
	}

	remoteUrl.Path = "/login"

	form := url.Values{}
	form.Add("username", "test")
	form.Add("password", "test")

	body := strings.NewReader(form.Encode())

	req, err := http.NewRequest("POST", remoteUrl.String(), body)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}

	if http.StatusFound != res.StatusCode {
		return fmt.Errorf("received wrong status code for post login request: %d", res.StatusCode)
	}

	return nil
}

func (h *opHandler) getAuthorizeWithCookies(httpClient *http.Client, state string) (string, error) {
	remoteUrl, err := url.Parse(h.GetURL())
	if err != nil {
		return "", err
	}

	remoteUrl.Path = "/oauth/authorize"

	req, err := http.NewRequest("GET", remoteUrl.String(), nil)
	if err != nil {
		return "", err
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}

	if http.StatusFound != res.StatusCode {
		return "", fmt.Errorf("received wrong status code for post login request: %d", res.StatusCode)
	}

	resLocation := res.Header.Get("location")
	if !strings.Contains(resLocation, h.redirectURI) {
		return "", fmt.Errorf("response location %q does not contain redirect uri %q", resLocation, h.redirectURI)
	}

	resLocationUrl, err := url.Parse(res.Header.Get("location"))
	if err != nil {
		return "", err
	}

	code := resLocationUrl.Query().Get("code")
	if code == "" {
		return "", fmt.Errorf("received code is empty")
	}

	resState := resLocationUrl.Query().Get("state")

	if state != resState {
		return "", fmt.Errorf("expected state %q and response state %q not matching", state, resState)
	}

	return code, nil
}

func (h *opHandler) postToken(httpClient *http.Client, code, codeVerifier string) ([]byte, error) {
	remoteUrl, err := url.Parse(h.GetURL())
	if err != nil {
		return nil, err
	}

	remoteUrl.Path = "/oauth/token"

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", h.clientID)
	data.Set("code_verifier", codeVerifier)
	data.Set("code", code)
	data.Set("redirect_uri", h.redirectURI)

	body := strings.NewReader(data.Encode())

	req, err := http.NewRequest("POST", remoteUrl.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(h.clientID), url.QueryEscape(h.clientSecret))

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if http.StatusOK != res.StatusCode {
		return nil, fmt.Errorf("received wrong status code for post login request: %d", res.StatusCode)
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	err = res.Body.Close()
	if err != nil {
		return nil, err
	}

	return bodyBytes, nil
}
