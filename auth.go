package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/client/rs"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

var (
	relyingParty   rp.RelyingParty
	resourceServer rs.ResourceServer

	redirectURI string
	scopes      = []string{oidc.ScopeOpenID}

	keyPath      = ""
	responseMode = ""

	cookieDomain     string
	cookieAuthKey    []byte
	cookieEncryptKey []byte

	clientID     string
	clientSecret string
	issuerURL    string
	redirectURL  string

	// client = &http.Client{
	// 	Timeout: time.Minute,
	// }
)

func LoginHandler(c echo.Context) error {
	rd := c.QueryParam("rd")

	// set the state cookie if redirect url provided as query param
	if rd != "" {
		stateSession, err := session.Get("state_session", c)
		if err != nil {
			return logAndReturnErr(err)
		}

		stateSession.Options = &sessions.Options{
			Domain:   cookieDomain,
			Path:     "/",
			MaxAge:   60 * 5,
			HttpOnly: true,
			Secure:   true,
		}
		stateSession.Values["redirect_to"] = rd

		if err := stateSession.Save(c.Request(), c.Response()); err != nil {
			return logAndReturnErr(err)
		}
	}

	url := rp.AuthURL("login", relyingParty)
	return c.Redirect(http.StatusFound, url)
}

func CallbackHandler(c echo.Context) error {
	r := c.Request()

	rp.CodeExchange[oidc.IDClaims](context.TODO(), "", relyingParty)

	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](r.Context(), r.FormValue("code"), relyingParty)
	if err != nil {
		fmt.Println("err:", err)
		return logAndReturnErr(err)
	}

	userSession, err := userSession(c)
	if err != nil {
		return logAndReturnErr(err)
	}

	userSession.Values["access_token"] = tokens.AccessToken
	if err := saveSession(userSession, c); err != nil {
		return logAndReturnErr(err)
	}

	stateSession, err := session.Get("state_session", c)
	if err != nil {
		return logAndReturnErr(err)
	}

	redirectTo, ok := stateSession.Values["redirect_to"]
	if !ok {
		fmt.Println("redirectTo not set. no redirect will occur.")
		return c.NoContent(http.StatusOK)
	}

	return c.Redirect(http.StatusFound, redirectTo.(string))
}

func CheckTokenHandler(c echo.Context) error {
	ok, token := checkToken(c)

	if !ok {
		logAndReturnErr(errors.New("no token set"))
		return c.NoContent(http.StatusUnauthorized)
	}

	resp, err := rs.Introspect[*oidc.IntrospectionResponse](c.Request().Context(), resourceServer, token)
	if err != nil {
		fmt.Println(err)
		return c.NoContent(http.StatusUnauthorized)
	}

	userSession, err := userSession(c)
	if err != nil {
		return logAndReturnErr(err)
	}

	userSession.Values["claims"] = resp.Claims
	userSession.Values["email"] = resp.Email
	userSession.Values["username"] = resp.Username
	fmt.Println("\tclaims:", userSession.Values["claims"])
	fmt.Println("\temail:", userSession.Values["email"])
	fmt.Println("\tusername:", userSession.Values["username"])
	return c.NoContent(http.StatusOK)
}

func checkToken(c echo.Context) (bool, string) {
	// check session for token
	ok, token := checkSessionForToken(c)
	if ok {
		fmt.Println("found valid session token: ", token)
		return ok, token
	}

	// if no token found in session check auth header
	return checkAuthHeaderForToken(c.Request().Header.Get("authorization"))
}

func checkAuthHeaderForToken(auth string) (bool, string) {
	if auth == "" {
		logAndReturnErr(errors.New("empty header"))
		return false, ""
	}

	if !strings.HasPrefix(auth, oidc.PrefixBearer) {
		logAndReturnErr(errors.New("invalid header"))
		return false, ""
	}

	token := strings.TrimPrefix(auth, oidc.PrefixBearer)
	fmt.Println("found valid header token: ", token)
	return true, token
}

func checkSessionForToken(c echo.Context) (bool, string) {
	sess, err := session.Get("user_session", c)
	if err != nil {
		fmt.Println(errors.New("error retrieving user_session"))
		return false, ""
	}

	token, ok := sess.Values["access_token"]
	if !ok {
		fmt.Println(errors.New("no access_token set"))
		return false, ""
	}

	return true, token.(string)
}

func loadOidcParams() {
	clientID = os.Getenv("OIDC_SSO_CLIENT_ID")
	clientSecret = os.Getenv("OIDC_SSO_CLIENT_SECRET")

	issuerURL = os.Getenv("OIDC_SSO_ISSUER_URL")
	redirectURL = os.Getenv("OIDC_SSO_REDIRECT_URL")

	if clientID == "" || clientSecret == "" || issuerURL == "" || redirectURL == "" {
		logger.Fatal("missing one or more of required oidc params: client_id, client_secret, issuer_url, redirect_url")
	}

	cookieAuthKey = []byte(os.Getenv("OIDC_SSO_HASH_KEY"))
	cookieEncryptKey = []byte(os.Getenv("OIDC_SSO_ENCRYPT_KEY"))

	cookieDomain = os.Getenv("OIDC_SSO_COOKIE_DOMAIN")
	if cookieDomain == "" {
		cookieDomain = "localhost"
	}
}

func logAndReturnErr(err error) error {
	fmt.Println(err)
	return err
}

func options() []rp.Option {
	options := []rp.Option{
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		rp.WithSigningAlgsFromDiscovery(),
	}

	// NOTE: this flow not currently in use but leaving here for potential future ref
	if keyPath != "" {
		options = append(options, rp.WithJWTProfile(rp.SignerFromKeyPath(keyPath)))
	}

	return options
}

func saveSession(session *sessions.Session, c echo.Context) error {
	if err := session.Save(c.Request(), c.Response()); err != nil {
		fmt.Println("err:", err)
		return err
	}
	return nil
}

func setupAuthClients() {
	var err error

	relyingParty, err = rp.NewRelyingPartyOIDC(context.TODO(), issuerURL, clientID, clientSecret, redirectURL, scopes, options()...)
	if err != nil {
		logger.Fatalf("error creating relying party provider %s", err.Error())
	}

	resourceServer, err = rs.NewResourceServerClientCredentials(context.TODO(), issuerURL, clientID, clientSecret)
	if err != nil {
		logger.Fatalf("error creating resource server provider %s", err.Error())
	}
}

func userSession(c echo.Context) (*sessions.Session, error) {
	userSession, err := session.Get("user_session", c)
	if err != nil {
		return nil, err
	}

	userSession.Options = &sessions.Options{
		Domain:   cookieDomain,
		Path:     "/",
		MaxAge:   60 * 60 * 10, // TODO: make a const (kc SSO session max [10hrs])
		HttpOnly: true,
		Secure:   true,
	}

	return userSession, nil
}
