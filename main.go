package main

import (
	"flag"
	"os"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

var (
	cookieStore *sessions.CookieStore
	listenPort  string

	logger Logger

	// flag variables
	envFile string
	debug   bool
)

// init handles parsing flags and initializing logger
func init() {
	flag.BoolVar(&debug, "d", false, "enable debug output")
	flag.StringVar(&envFile, "e", ".env", "the environment file to load from")

	flag.Parse()

	logger = NewLogger(LoggerOptions{Debug: debug})

	loadEnv()
}

// Simple OIDC/OAuth2 proxy. Performs the following flow (for my setup the routing is handled via nginx and the auth_reqest directive):
//
//  1. Calls auth endpoint. Checks if a valid user session exists.
//     a. Exists       : return HTTP 200 -- proxy should pass to protected page
//     b. Doesn't Exist: return HTTP 401 -- continue to step 2
//
//  2. On 401 have proxy redirect to /login to begin the oidc/oauth flow
//
//  3. On succesful credentials the provider will redirect back to /auth/callback
//
//  4. Ensure valid data returned back and set user session.
func main() {
	e := echo.New()
	// logger = e.Logger
	// _, w, _ := os.Pipe()
	// logger.SetOutput(w)

	// loadEnv()
	setupAuthClients()

	cookieStore = sessions.NewCookieStore(cookieAuthKey, cookieEncryptKey)
	e.Use(session.Middleware(cookieStore))

	e.GET("/auth", AuthHandler)
	e.GET("/auth/callback", CallbackHandler)
	// e.GET("/check-token", CheckTokenHandler)
	e.GET("/login", LoginHandler)

	logger.Fatal(e.Start(":" + listenPort))
}

func loadEnv() {
	if err := godotenv.Load(envFile); err != nil {
		logger.Fatal(err)
	}

	listenPort = os.Getenv("OIDC_SSO_LISTEN_PORT")
	if listenPort == "" {
		logger.Fatal("missing listen port")
	}

	loadOidcParams()
}
