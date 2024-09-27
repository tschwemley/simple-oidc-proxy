package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
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
)

// AuthHandler returns 200 if the user is authorized and 401 if the user is not authorized. It is accessible at "/auth"
func AuthHandler(c echo.Context) error {
	sess, err := userSession(c)
	if err != nil {
		return logUnauthorized(c, err)
	}

	if sess.IsNew {
		logger.Info("no user session set. returning 401.")
		return c.NoContent(http.StatusUnauthorized)
	}

	info, ok := sess.Values["info"].([]byte)
	if !ok {
		return logUnauthorized(c, errors.New("unable to get user info from session"))
	}

	var userInfo oidc.UserInfo
	if err := json.Unmarshal(info, &userInfo); err != nil {
		return logUnauthorized(c, err)
	}

	// TODO: it's probably going to be better long-term to just custom type the claims
	logger.Info("user groups: ", userInfo.Claims["groups"])
	logger.Info("realm access: ", userInfo.Claims["realm_access"])
	logger.Info("resource access: ", userInfo.Claims["resource_access"])

	return c.NoContent(http.StatusOK)
}

func LoginHandler(c echo.Context) error {
	// create the sso session (this is short lived for the oidc/oauth flow and holds pkce, etc.)
	oidcSession, err := oidcSession(c)
	if err != nil {
		return logUnauthorized(c, err)
	}

	// store url to redirect back to in the oidc session
	oidcSession.Values["redirect"] = c.QueryParam("rd")

	// generate code verifier and store in sso session
	oidcSession.Values["pkce"] = base64.RawURLEncoding.EncodeToString([]byte(uuid.New().String()))

	// generate the code challenge from the code verifier
	codeChallenge := oidc.NewSHACodeChallenge(oidcSession.Values["pkce"].(string))

	if err := saveSession(oidcSession, c); err != nil {
		return logUnauthorized(c, err)
	}

	url := rp.AuthURL("", relyingParty, rp.WithCodeChallenge(codeChallenge))
	return c.Redirect(http.StatusFound, url)
}

func CallbackHandler(c echo.Context) error {
	oidcSession, err := oidcSession(c)
	if err != nil {
		return logUnauthorized(c, err)
	}

	codeVerifier, ok := oidcSession.Values["pkce"]
	if !ok {
		return logUnauthorized(c, errors.New("no code verifier set"))
	}

	redirect, ok := oidcSession.Values["redirect"].(string)
	if !ok {
		redirect = "" // TODO: fill out
	}

	ctx := c.Request().Context()
	code := c.QueryParam("code")

	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](ctx, code, relyingParty, rp.WithCodeVerifier(codeVerifier.(string)))
	if err != nil {
		return logUnauthorized(c, err)
	}

	info, err := rp.Userinfo[*oidc.UserInfo](ctx, tokens.AccessToken, tokens.TokenType, tokens.IDTokenClaims.GetSubject(), relyingParty)
	if err != nil {
		return logUnauthorized(c, err)
	}

	userSession, err := userSession(c)
	if err != nil {
		return logUnauthorized(c, err)
	}

	infoJson, err := json.Marshal(info)
	userSession.Values["info"] = infoJson

	logger.Info("user info profile: ", info.Profile)
	if err = saveSession(userSession, c); err != nil {
		return logUnauthorized(c, err)
	}

	return c.Redirect(http.StatusFound, redirect)
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

func logUnauthorized(c echo.Context, err error) error {
	logger.Error(err)
	return c.NoContent(http.StatusUnauthorized)
}

func options() []rp.Option {
	options := []rp.Option{
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		rp.WithSigningAlgsFromDiscovery(),
	}

	return options
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
