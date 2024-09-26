package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	// "github.com/zitadel/oidc/v3/pkg/client/rp"

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

	client = &http.Client{
		Timeout: time.Minute,
	}
)

func init() {
	var err error

	// use log.Fatalf instead of logger here since logger doesn't get declared until after init() calls run
	relyingParty, err = rp.NewRelyingPartyOIDC(context.TODO(), issuerURL, clientID, clientSecret, redirectURL, scopes, options()...)
	if err != nil {
		log.Fatalf("error creating relying party provider %s", err.Error())
	}

	resourceServer, err = rs.NewResourceServerClientCredentials(context.TODO(), issuerURL, clientID, clientSecret)
	if err != nil {
		log.Fatalf("error creating resource server provider %s", err.Error())
	}
}

func LoginHandler(c echo.Context) error {
	rd := c.QueryParam("rd")

	// set the state cookie if redirect url provided as query param
	if rd != "" {
		sess, err := session.Get("state", c)
		if err != nil {
			return err
		}

		sess.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   60 * 5,
			HttpOnly: true,
			Secure:   true,
		}
		sess.Values["redirect_to"] = rd

		if err := sess.Save(c.Request(), c.Response()); err != nil {
			return err
		}
	}

	url := rp.AuthURL("login", relyingParty)
	fmt.Println("url: ", url)
	return c.Redirect(http.StatusFound, url)
}

func CallbackHandler(c echo.Context) error {
	r := c.Request()

	rp.CodeExchange[oidc.IDClaims](context.TODO(), "", relyingParty)

	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](r.Context(), r.FormValue("code"), relyingParty)
	if err != nil {
		return logAndReturnErr(err)
	}

	userSession, err := session.Get("user_session", c)
	if err != nil {
		return logAndReturnErr(err)
	}

	userSession.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   60 * 60 * 10, // TODO: make a const (kc SSO session max [10hrs])
		HttpOnly: true,
		Secure:   true,
	}
	userSession.Values["access_token"] = tokens.AccessToken

	if err := userSession.Save(c.Request(), c.Response()); err != nil {
		return err
	}

	stateSession, err := session.Get("state", c)
	if err != nil {
		return err
	}

	redirectTo, ok := stateSession.Values["redirect_to"]
	if !ok {
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
		logAndReturnErr(err)
		return c.NoContent(http.StatusUnauthorized)
	}

	data, err := json.Marshal(resp)
	if err != nil {
		log.Fatal(err)
	}

	return c.JSONPretty(200, data, "  ")
}

func checkToken(c echo.Context) (bool, string) {
	// check session for token
	ok, token := checkSessionForToken(c)
	if ok {
		fmt.Println("token: ", token)
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

	return true, strings.TrimPrefix(auth, oidc.PrefixBearer)
}

func checkSessionForToken(c echo.Context) (bool, string) {
	sess, err := session.Get("user_session", c)
	if err != nil {
		logAndReturnErr(errors.New("error retrieving user_session"))
		return false, ""
	}

	token, ok := sess.Values["access_token"]
	if !ok {
		logAndReturnErr(errors.New("no access_token set"))
		return false, ""
	}

	return true, token.(string)
}

func options() []rp.Option {
	options := []rp.Option{
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		rp.WithHTTPClient(client),
		rp.WithSigningAlgsFromDiscovery(),
	}

	// NOTE: this flow not currently in use but leaving here for potential future ref
	if keyPath != "" {
		options = append(options, rp.WithJWTProfile(rp.SignerFromKeyPath(keyPath)))
	}

	return options
}

func logAndReturnErr(err error) error {
	return err
}
