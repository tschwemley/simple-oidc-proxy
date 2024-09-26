package main

import (
	"flag"
	"log"
	"os"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

var (
	listenPort string

	cookieAuthKey    []byte
	cookieEncryptKey []byte

	clientID     string
	clientSecret string
	issuerURL    string
	redirectURL  string

	cookieStore *sessions.CookieStore
	logger      echo.Logger
)

// TODO: see also: https://github.com/zitadel/oidc/blob/main/example/client/api/api.go
// for an api implementation that checks against header and calls introspection endopint

func init() {
	// if .env file exists load it
	if _, err := os.Stat(".env"); err == nil {
		godotenv.Load()
	}

	listenPort = os.Getenv("OIDC_SSO_LISTEN_PORT")
	clientID = os.Getenv("OIDC_SSO_CLIENT_ID")
	clientSecret = os.Getenv("OIDC_SSO_CLIENT_SECRET")
	issuerURL = os.Getenv("OIDC_SSO_ISSUER_URL")
	redirectURL = os.Getenv("OIDC_SSO_REDIRECT_URL")

	cookieAuthKey = []byte(os.Getenv("OIDC_SSO_HASH_KEY"))
	cookieEncryptKey = []byte(os.Getenv("OIDC_SSO_ENCRYPT_KEY"))

	debugPtr := flag.Bool("debug", false, "output debug info to logs")
	logDebugInfo(*debugPtr)
}

func main() {
	e := echo.New()
	logger = e.Logger

	cookieStore = sessions.NewCookieStore(cookieAuthKey, cookieEncryptKey)
	e.Use(session.Middleware(cookieStore))

	// e.GET("/auth", AuthHandler)
	e.GET("/auth/callback", CallbackHandler)
	e.GET("/check-token", CheckTokenHandler)
	e.GET("/login", LoginHandler)

	logger.Fatal(e.Start(":" + listenPort))
}

func logDebugInfo(d bool) {
	if d {
		log.Println("-----------------------------")
		log.Println("--- Environment Variables ---")
		log.Println("-----------------------------")
		for _, e := range os.Environ() {
			log.Println("\t", e)
		}

		log.Println("\n-----------------------------\n")
	}
}
