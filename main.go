package main

import (
	"bytes"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	o "github.com/Quiq/webauthn_proxy/oauth2"
	u "github.com/Quiq/webauthn_proxy/user"
	util "github.com/Quiq/webauthn_proxy/util"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	yaml "gopkg.in/yaml.v3"
)

type Configuration struct {
	RPDisplayName string   // Relying party display name
	RPID          string   // Relying party ID
	RPOrigins     []string // Relying party origin

	// Note: enabling this can be risky as it allows anyone to add themselves to the proxy.
	// Only enable test mode during testing!
	TestMode bool

	ServerAddress             string
	ServerPort                string
	SessionSoftTimeoutSeconds int
	SessionHardTimeoutSeconds int
	SessionCookieName         string
	UserCookieName            string
	UsernameRegex             string
	CookieSecure              bool
	CookieDomain              string
	AllowedRedirects          []string // List of allowed redirect URLs

	// OAuth2 Configuration
	OAuth2Enabled      bool
	OAuth2RedirectURL  string
	OAuth2Providers    map[string]OAuth2ProviderConfig
}

type CredentialsConfiguration struct {
	CookieSecrets []string          `yaml:"cookie_session_secrets"`
	Credentials   map[string]string `yaml:"user_credentials"`
	AllowedUsers  []string          `yaml:"allowed_users"`
	OAuth2Secrets map[string]string `yaml:"oauth2_secrets"`
}

// OAuth2ProviderConfig holds configuration for an OAuth2 provider
type OAuth2ProviderConfig struct {
	ClientID     string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	Scopes       []string
	DisplayName  string
	Icon    string
}

type WebAuthnMessage struct {
	Message string
}

type RegistrationSuccess struct {
	Message string
	Data    string
}

type LoginVerification struct {
	IPAddr    string
	LoginTime time.Time
}

// HandlerContext contains common objects needed by handlers
type HandlerContext struct {
	webAuthn     *webauthn.WebAuthn
	sessionStore *sessions.CookieStore
	session      *sessions.Session
	username     string
	user         u.User
}

const (
	AuthenticatedUsernameHeader = "X-Authenticated-User"
	loginVerificationInterval   = 5 * time.Minute
	staticPath                  = "static/"
)

var (
	configuration      Configuration
	loginError         WebAuthnMessage
	registrationError  WebAuthnMessage
	authError          WebAuthnMessage
	notAllowedError    WebAuthnMessage
	users              map[string]u.User
	registrations      map[string]u.User
	cookieSecrets      []string
	dynamicOrigins     bool
	webAuthns          map[string]*webauthn.WebAuthn
	sessionStores      map[string]*sessions.CookieStore
	loginVerifications map[string]*LoginVerification
	logger             *logrus.Entry
	oauth2Providers    map[string]*o.Provider
	oauth2States       map[string]*o.State
	allowedUsers       []string
)

// Constants for OAuth2
const (
	oauth2StateKey = "oauth2_state"
)

func main() {
	var (
		genSecretFlag, versionFlag bool
		loggingLevel               string
	)
	flag.StringVar(&loggingLevel, "log-level", "info", "logging level")
	flag.BoolVar(&genSecretFlag, "generate-secret", false, "generate a random string suitable as a cookie secret")
	flag.BoolVar(&versionFlag, "version", false, "show version")
	flag.Parse()
	logger = util.SetupLogging("webauthn_proxy", loggingLevel)

	if genSecretFlag {
		fmt.Println(util.GenChallenge())
		return
	} else if versionFlag {
		fmt.Println(version)
		return
	}

	var err error
	var credfile []byte
	var credentialsConfig CredentialsConfiguration
	// Standard error messages
	loginError = WebAuthnMessage{Message: "Unable to login"}
	registrationError = WebAuthnMessage{Message: "Error during registration"}
	authError = WebAuthnMessage{Message: "Unauthenticated"}
	notAllowedError = WebAuthnMessage{Message: "User not in allowed list"}

	users = make(map[string]u.User)
	registrations = make(map[string]u.User)
	webAuthns = make(map[string]*webauthn.WebAuthn)
	sessionStores = make(map[string]*sessions.CookieStore)
	loginVerifications = make(map[string]*LoginVerification)

	// Set configuration defaults
	viper.SetDefault("configpath", "./config")
	viper.SetEnvPrefix("webauthn_proxy")
	viper.BindEnv("configpath")
	viper.SetConfigName("config")
	viper.SetConfigType("yml")

	viper.SetDefault("rpdisplayname", "MyCompany")
	viper.SetDefault("rpid", "localhost")
	viper.SetDefault("rporigins", []string{})
	viper.SetDefault("testmode", false)
	viper.SetDefault("serveraddress", "0.0.0.0")
	viper.SetDefault("serverport", "8080")
	viper.SetDefault("sessionsofttimeoutseconds", 28800)
	viper.SetDefault("sessionhardtimeoutseconds", 86400)
	viper.SetDefault("sessioncookiename", "webauthn-proxy-session")
	viper.SetDefault("usercookiename", "webauthn-proxy-username")
	viper.SetDefault("usernameregex", "^.+$")
	viper.SetDefault("cookiesecure", false)
	viper.SetDefault("cookiedomain", "")
	
	// OAuth2 defaults
	viper.SetDefault("oauth2enabled", false)
	viper.SetDefault("oauth2redirecturl", "")
	viper.SetDefault("oauth2providers", map[string]interface{}{})
	viper.SetDefault("allowedredirects", []string{})

	// Read in configuration file
	configpath := viper.GetString("configpath")
	viper.AddConfigPath(configpath)
	logger.Infof("Reading config file %s/config.yml", configpath)
	if err := viper.ReadInConfig(); err != nil {
		logger.Fatalf("Error reading config file %s/config.yml: %s", configpath, err)
	}
	if err = viper.Unmarshal(&configuration); err != nil {
		logger.Fatalf("Unable to decode config file into struct: %s", err)
	}
	// Read in credentials file
	credentialspath := filepath.Join(configpath, "credentials.yml")
	logger.Infof("Reading credentials file %s", credentialspath)

	if credfile, err = os.ReadFile(credentialspath); err != nil {
		logger.Fatalf("Unable to read credential file %s %v", credentialspath, err)
	}
	if err = yaml.Unmarshal(credfile, &credentialsConfig); err != nil {
		logger.Fatalf("Unable to parse YAML credential file %s %v", credentialspath, err)
	}
	
	// Store allowed users list
	allowedUsers = credentialsConfig.AllowedUsers
	logger.Debugf("Allowed users: %v", allowedUsers)

	logger.Debugf("Configuration: %+v\n", configuration)
	logger.Debugf("Viper AllSettings: %+v\n", viper.AllSettings())

	// Ensure that session soft timeout <= hard timeout
	if configuration.SessionSoftTimeoutSeconds < 1 {
		logger.Fatalf("Invalid session soft timeout of %d, must be > 0", configuration.SessionSoftTimeoutSeconds)
	} else if configuration.SessionHardTimeoutSeconds < 1 {
		logger.Fatalf("Invalid session hard timeout of %d, must be > 0", configuration.SessionHardTimeoutSeconds)
	} else if configuration.SessionHardTimeoutSeconds < configuration.SessionSoftTimeoutSeconds {
		logger.Fatal("Invalid session hard timeout, must be > session soft timeout")
	}

	cookieSecrets = credentialsConfig.CookieSecrets
	if len(cookieSecrets) == 0 {
		logger.Warnf("You did not set any cookie_session_secrets in credentials.yml.")
		logger.Warnf("So it will be dynamic and your cookie sessions will not persist proxy restart.")
		logger.Warnf("Generate one using `-generate-secret` flag and add to credentials.yml.")
	}
	if len(cookieSecrets) > 0 && cookieSecrets[0] == "your-own-cookie-secret" {
		logger.Warnf("You did not set any valid cookie_session_secrets in credentials.yml.")
		logger.Fatalf("Generate one using `-generate-secret` flag and add to credentials.yml.")
	}
	for username, credential := range credentialsConfig.Credentials {
		unmarshaledUser, err := u.UnmarshalUser(credential)
		if err != nil {
			logger.Fatalf("Error unmarshalling user credential %s: %s", username, err)
		}
		if username != unmarshaledUser.Name {
			logger.Fatalf("Credentials for user %s are designated for another one %s", username, unmarshaledUser.Name)
		}
		users[username] = *unmarshaledUser
		if logrus.GetLevel() == logrus.DebugLevel {
			util.PrettyPrint(unmarshaledUser)
		}
	}
	
	// Initialize OAuth2 providers if enabled
	oauth2Providers = make(map[string]*o.Provider)
	oauth2States = make(map[string]*o.State)
	
	if configuration.OAuth2Enabled {
		if configuration.OAuth2RedirectURL == "" {
			logger.Fatalf("OAuth2 is enabled but no redirect URL is configured")
		}
		
		// Initialize OAuth2 providers from configuration
		for providerName, providerConfig := range configuration.OAuth2Providers {
			clientSecret, exists := credentialsConfig.OAuth2Secrets[providerName]
			if !exists {
				logger.Warnf("OAuth2 provider %s is configured but no client secret is provided", providerName)
				continue
			}
			
			provider := o.NewProvider(
				providerName,
				providerConfig.ClientID,
				clientSecret,
				providerConfig.AuthURL,
				providerConfig.TokenURL,
				providerConfig.UserInfoURL,
				configuration.OAuth2RedirectURL + "?provider=" + providerName,
				providerConfig.Scopes,
				providerConfig.DisplayName,
				providerConfig.Icon,
			)
			
			oauth2Providers[providerName] = provider
			logger.Infof("Initialized OAuth2 provider: %s", providerName)
		}
		
		if len(oauth2Providers) == 0 {
			logger.Warnf("OAuth2 is enabled but no providers are configured")
		}
	}

	// Print the effective config.
	fmt.Println()
	fmt.Printf("Relying Party Display Name: %s\n", configuration.RPDisplayName)
	fmt.Printf("Relying Party ID: %s\n", configuration.RPID)
	fmt.Printf("Relying Party Origins: %v\n", configuration.RPOrigins)
	fmt.Printf("Test Mode: %v\n", configuration.TestMode)
	fmt.Printf("Server Address: %s\n", configuration.ServerAddress)
	fmt.Printf("Server Port: %s\n", configuration.ServerPort)
	fmt.Printf("Session Soft Timeout: %d\n", configuration.SessionSoftTimeoutSeconds)
	fmt.Printf("Session Hard Timeout: %d\n", configuration.SessionHardTimeoutSeconds)
	fmt.Printf("Session Cookie Name: %s\n", configuration.SessionCookieName)
	fmt.Printf("User Cookie Name: %s\n", configuration.UserCookieName)
	fmt.Printf("Username Regex: %s\n", configuration.UsernameRegex)
	fmt.Printf("Cookie secure: %v\n", configuration.CookieSecure)
	fmt.Printf("Cookie domain: %s\n", configuration.CookieDomain)
	fmt.Printf("Cookie secrets: %d\n", len(cookieSecrets))
	fmt.Printf("User credentials: %d\n", len(users))
	fmt.Printf("Allowed users: %d\n", len(allowedUsers))
	fmt.Printf("Allowed redirects: %v\n", configuration.AllowedRedirects)
	fmt.Printf("OAuth2 enabled: %v\n", configuration.OAuth2Enabled)
	if configuration.OAuth2Enabled {
		fmt.Printf("OAuth2 providers: %d\n", len(oauth2Providers))
	}
	fmt.Println()
	if configuration.TestMode {
		fmt.Printf("Warning!!! Test Mode enabled! This is not safe for production!\n\n")
	}

	// If list of relying party origins has been specified in configuration,
	// create one Webauthn config / Session store per origin, else origins will be dynamic.
	if len(configuration.RPOrigins) > 0 {
		for _, origin := range configuration.RPOrigins {
			if _, _, err := createWebAuthnClient(origin); err != nil {
				logger.Fatalf("Failed to create WebAuthn from config: %s", err)
			}
		}
	} else {
		dynamicOrigins = true
	}

	util.CookieSecure = configuration.CookieSecure
	util.CookieDomain = configuration.CookieDomain
	r := http.NewServeMux()
	fileServer := http.FileServer(http.Dir("./static"))
	r.Handle("/auth_proxy/static/", http.StripPrefix("/auth_proxy/static/", fileServer))
	r.HandleFunc("/", HandleIndex)
	r.HandleFunc("/auth_proxy/login", HandleLogin)
	r.HandleFunc("/auth_proxy/webauthn/login/get_credential_request_options", GetCredentialRequestOptions)
	r.HandleFunc("/auth_proxy/webauthn/login/process_login_assertion", ProcessLoginAssertion)
	r.HandleFunc("/auth_proxy/webauthn/register", HandleRegister)
	r.HandleFunc("/auth_proxy/webauthn/register/get_credential_creation_options", GetCredentialCreationOptions)
	r.HandleFunc("/auth_proxy/webauthn/register/process_registration_attestation", ProcessRegistrationAttestation)
	r.HandleFunc("/auth_proxy/auth", HandleAuth)
	r.HandleFunc("/auth_proxy/verify", HandleVerify)
	r.HandleFunc("/auth_proxy/logout", HandleLogout)
	
	// OAuth2 routes
	if configuration.OAuth2Enabled {
		r.HandleFunc("/auth_proxy/oauth2/login", HandleOAuth2Login)
		r.HandleFunc("/auth_proxy/oauth2/callback", HandleOAuth2Callback)
		r.HandleFunc("/auth_proxy/oauth2/providers", HandleOAuth2Providers)
	}

	listenAddress := fmt.Sprintf("%s:%s", configuration.ServerAddress, configuration.ServerPort)
	logger.Infof("Starting server at %s", listenAddress)
	logger.Fatal(http.ListenAndServe(listenAddress, r))
}

// initHandlerContext initializes the common handler context
func initHandlerContext(r *http.Request) (*HandlerContext, error) {
	webAuthn, sessionStore, err := checkOrigin(r)
	if err != nil {
		return nil, fmt.Errorf("error validating origin: %s", err)
	}

	ctx := &HandlerContext{
		webAuthn:     webAuthn,
		sessionStore: sessionStore,
	}

	// Get session if available
	session, err := sessionStore.Get(r, configuration.SessionCookieName)
	if err != nil {
		logger.Debugf("Error getting session from session store: %s", err)
		// Continue with a new session
	}
	ctx.session = session

	// Try to get username if available
	username, err := util.GetUsername(r, configuration.UsernameRegex)
	if err == nil {
		ctx.username = username
		
		// Try to get user if available
		if user, exists := users[username]; exists {
			ctx.user = user
		}
	}

	return ctx, nil
}

// setUserCookie sets the user cookie
func setUserCookie(w http.ResponseWriter, username string) {
	ck := http.Cookie{
		Name:    configuration.UserCookieName,
		Domain:  configuration.CookieDomain,
		Path:    "/",
		Value:   username,
		Expires: time.Now().AddDate(1, 0, 0), // 1 year
		Secure:  configuration.CookieSecure,
	}
	http.SetCookie(w, &ck)
}

// isUserAllowed checks if a user is in the allowed_users list
func isUserAllowed(username string, user u.User) bool {
	// If allowed_users list is empty, allow all users
	if len(allowedUsers) == 0 {
		return true
	}
	
	// Check if username is in allowed_users list
	for _, allowedUser := range allowedUsers {
		if username == allowedUser {
			return true
		}
		
		// For OAuth2 users, also check if their email is in allowed_users list
		if user.OAuth2Provider != "" && user.OAuth2Data["email"] != "" {
			if user.OAuth2Data["email"] == allowedUser {
				return true
			}
		}
	}
	
	return false
}

// authenticateUser sets the user as authenticated in the session
func authenticateUser(ctx *HandlerContext, r *http.Request, w http.ResponseWriter) {
	userIP := util.GetUserIP(r)
	loginVerifications[ctx.username] = &LoginVerification{IPAddr: userIP, LoginTime: time.Now()}
	
	// session cookie
	ctx.session.Values["authenticated"] = true
	ctx.session.Values["authenticated_user"] = ctx.username
	ctx.session.Values["authenticated_time"] = time.Now().Unix()
	ctx.session.Values["authenticated_ip"] = userIP
	ctx.session.Save(r, w)
	
	// username cookie
	setUserCookie(w, ctx.username)
	
	logger.Infof("User %s authenticated successfully from %s", ctx.username, userIP)
}

// isAuthenticated checks if the user is authenticated
func isAuthenticated(ctx *HandlerContext, r *http.Request, w http.ResponseWriter) (bool, string) {
	if auth, ok := ctx.session.Values["authenticated"].(bool); !ok || !auth {
		return false, ""
	}
	
	username := ctx.session.Values["authenticated_user"].(string)
	
	// Check hard timeout
	if time.Now().Unix()-ctx.session.Values["authenticated_time"].(int64) >= int64(configuration.SessionHardTimeoutSeconds) {
		// Session has exceeded the hard limit
		logger.Debugf("Expiring user %s session expired by hard limit", username)
		util.ExpireWebauthnSession(ctx.session, r, w)
		return false, ""
	}
	
	// Check IP match
	userIP := ctx.session.Values["authenticated_ip"].(string)
	if userIP != util.GetUserIP(r) {
		// User IP mismatches, let use to re-login
		logger.Debugf("Invalidating user %s session coming from %s while session was created from %s",
			username, util.GetUserIP(r), userIP)
		util.ExpireWebauthnSession(ctx.session, r, w)
		return false, ""
	}
	
	return true, username
}

// validateRedirectURL checks if a redirect URL is allowed
// Returns true if:
// 1. The URL starts with "/" (same domain)
// 2. The URL matches one of the allowed redirect URLs by prefix
func validateRedirectURL(redirectURL string) bool {
	// If redirect URL starts with "/", it's a same-domain redirect, so it's allowed
	if strings.HasPrefix(redirectURL, "/") {
		logger.Infof("skip validate url %s", redirectURL)
		return true
	}

	// Check if the redirect URL matches any of the allowed redirect URLs by prefix
	for _, allowedURL := range configuration.AllowedRedirects {
		logger.Infof("validate url %s vs %s", redirectURL, allowedURL)
		if strings.HasPrefix(redirectURL, allowedURL) {
			logger.Infof("OK validate url %s vs %s", redirectURL, allowedURL)
			return true
		}
	}

	// If we get here, the redirect URL is not allowed
	logger.Warnf("Redirect URL %s is not allowed", redirectURL)
	return false
}

// Root page
func HandleIndex(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/auth_proxy/login", http.StatusTemporaryRedirect)
}

// /auth_proxy/auth - Check if user has an authenticated session
// This endpoint can be used for internal nginx checks.
// Also this endpoint prolongs the user session by soft limit interval.
func HandleAuth(w http.ResponseWriter, r *http.Request) {
	ctx, err := initHandlerContext(r)
	if err != nil {
		logger.Errorf("%s", err)
		util.JSONResponse(w, authError, http.StatusBadRequest)
		return
	}

	authenticated, username := isAuthenticated(ctx, r, w)
	if !authenticated {
		util.JSONResponse(w, authError, http.StatusUnauthorized)
		return
	}

	// Update the session to reset the soft timeout
	ctx.session.Save(r, w)
	w.Header().Set(AuthenticatedUsernameHeader, username)
	util.JSONResponse(w, WebAuthnMessage{Message: "OK"}, http.StatusOK)
}

// /auth_proxy/webauthn/login - Show authenticated page or serve up login page
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	ctx, err := initHandlerContext(r)
	if err != nil {
		logger.Errorf("%s", err)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	// Prevents html caching because this page serves two different pages.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0")
	
	authenticated, _ := isAuthenticated(ctx, r, w)
	if !authenticated {
		content, err := os.ReadFile(filepath.Join(staticPath, "login.html"))
		if err != nil {
			util.JSONResponse(w, loginError, http.StatusNotFound)
			return
		}
		content = []byte(strings.Replace(string(content), configuration.UserCookieName, configuration.UserCookieName, 1))
		
		// Check if redirect_url exists in query parameters
		if redirectURL := r.URL.Query().Get("redirect_url"); redirectURL != "" && validateRedirectURL(redirectURL) {
			// Replace the REDIRECT_URL constant with the URL-encoded redirect_url
			encodedRedirectURL := url.QueryEscape(redirectURL)
			logger.Infof("Redirecting to %s", encodedRedirectURL)

			content = []byte(strings.Replace(string(content),
				"<div id=\"redirect-url\"></div>",
				fmt.Sprintf("<div id=\"redirect-url\">%s</div>", encodedRedirectURL),
				1))
		}
		
		reader := bytes.NewReader(content)
		http.ServeContent(w, r, "", time.Time{}, reader)
		return
	}

	if redirectUrl := r.URL.Query().Get("redirect_url"); redirectUrl != "" && validateRedirectURL(redirectUrl) {
		http.Redirect(w, r, redirectUrl, http.StatusTemporaryRedirect)
	} else {
		http.ServeFile(w, r, filepath.Join(staticPath, "authenticated.html"))
	}
}

// /auth_proxy/logout - Logout page
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	ctx, err := initHandlerContext(r)
	if err != nil {
		logger.Errorf("%s", err)
		util.JSONResponse(w, authError, http.StatusBadRequest)
		return
	}

	util.ExpireWebauthnSession(ctx.session, r, w)
	http.Redirect(w, r, "/auth_proxy/login", http.StatusTemporaryRedirect)
}

// /auth_proxy/verify - one-time verification if user has recently authenticated, useful as 2FA check.
func HandleVerify(w http.ResponseWriter, r *http.Request) {
	// We only need to check origin here, don't need the full context
	_, _, err := checkOrigin(r)
	if err != nil {
		logger.Errorf("Error validating origin: %s", err)
		util.JSONResponse(w, authError, http.StatusBadRequest)
		return
	}

	username := r.URL.Query().Get("username")
	userIP := r.URL.Query().Get("ip")
	if data, exists := loginVerifications[username]; exists {
		// Check whether this is within last 5 min.
		if data.LoginTime.Add(loginVerificationInterval).Before(time.Now()) {
			delete(loginVerifications, username)
			util.JSONResponse(w, authError, http.StatusUnauthorized)
			return
		}
		if data.IPAddr == userIP {
			// Check once and delete
			delete(loginVerifications, username)
			logger.Infof("User %s verified successfully from %s", username, userIP)
			util.JSONResponse(w, WebAuthnMessage{Message: "OK"}, http.StatusOK)
			return
		} else {
			logger.Warnf("User %s failed verification: auth IP %s, validating IP %s", username, data.IPAddr, userIP)
		}
	}
	util.JSONResponse(w, authError, http.StatusUnauthorized)
}

// /auth_proxy/webauthn/register - Serve up registration page
func HandleRegister(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join(staticPath, "register.html"))
}

/*
/auth_proxy/webauthn/login/get_credential_request_options -
Step 1 of the login process, get credential request options for the user
*/
func GetCredentialRequestOptions(w http.ResponseWriter, r *http.Request) {
	ctx, err := initHandlerContext(r)
	if err != nil {
		logger.Errorf("%s", err)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	var options interface{}
	var sessionData interface{}

	// Handle discoverable login if no username provided
	if ctx.username == "" {
		// Begin the discoverable login process
		options, sessionData, err = ctx.webAuthn.BeginDiscoverableLogin()
		if err != nil {
			logger.Errorf("Error beginning the discoverable login process: %s", err)
			util.JSONResponse(w, loginError, http.StatusInternalServerError)
			return
		}
	} else {
		// Check if user exists
		user, exists := users[ctx.username]
		if !exists {
			logger.Warnf("User %s does not exist", ctx.username)
			util.JSONResponse(w, loginError, http.StatusBadRequest)
			return
		}
		ctx.user = user
		
		// Check if user is allowed
		if !isUserAllowed(ctx.username, ctx.user) {
			logger.Warnf("User %s not in allowed_users list, login request denied", ctx.username)
			util.JSONResponse(w, notAllowedError, http.StatusForbidden)
			return
		}

		// Begin the login process
		options, sessionData, err = ctx.webAuthn.BeginLogin(ctx.user)
		if err != nil {
			logger.Errorf("Error beginning the login process: %s", err)
			util.JSONResponse(w, loginError, http.StatusInternalServerError)
			return
		}
	}

	// Store Webauthn session data
	sessionDataPtr, ok := sessionData.(*webauthn.SessionData)
	if !ok {
		logger.Errorf("Error: sessionData is not of type *webauthn.SessionData")
		util.JSONResponse(w, loginError, http.StatusInternalServerError)
		return
	}
	err = util.SaveWebauthnSession(ctx.session, "authentication", sessionDataPtr, r, w)
	if err != nil {
		logger.Errorf("Error saving Webauthn session: %s", err)
		util.JSONResponse(w, loginError, http.StatusInternalServerError)
		return
	}

	util.JSONResponse(w, options, http.StatusOK)
}

/*
/auth_proxy/webauthn/login/process_login_assertion -
Step 2 of the login process, process the assertion from the client authenticator
*/
// findUserByCredential finds a user by their credential ID or user handle
func findUserByCredential(rawID, userHandle []byte) (webauthn.User, string, error) {
	// Option 1: If you stored user ID in the userHandle during registration
	if len(userHandle) > 0 {
		userID := string(userHandle)
		for username, user := range users {
			if bytes.Equal(user.WebAuthnID(), []byte(userID)) {
				return user, username, nil
			}
		}
	}
	
	// Option 2: Look up by credential ID (rawID)
	for username, user := range users {
		for _, cred := range user.WebAuthnCredentials() {
			if bytes.Equal(cred.ID, rawID) {
				return user, username, nil
			}
		}
	}
	
	return nil, "", fmt.Errorf("user not found for credential")
}

// processCredential processes the credential after successful authentication
func processCredential(user u.User, cred *webauthn.Credential, username string) error {
	// Check for cloned authenticators
	if cred.Authenticator.CloneWarning {
		return fmt.Errorf("authenticator for %s appears to be cloned", username)
	}

	// Increment sign counter on user to help avoid clones
	userCredential, err := user.CredentialById(cred.ID)
	if err != nil {
		return fmt.Errorf("error incrementing sign counter: %s", err)
	}
	
	userCredential.Authenticator.UpdateCounter(cred.Authenticator.SignCount)
	return nil
}

func ProcessLoginAssertion(w http.ResponseWriter, r *http.Request) {
	ctx, err := initHandlerContext(r)
	if err != nil {
		logger.Errorf("%s", err)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}
	
	// Get redirect URL from query parameters if present
	redirectURL := r.URL.Query().Get("redirect_url")

	// Handle discoverable login if no username provided
	if ctx.username == "" {
		logger.Infof("No username provided, attempting discoverable login")

		// Load the session data
		sessionData, err := util.FetchWebauthnSession(ctx.session, "authentication", r)
		if err != nil {
			logger.Errorf("Error getting Webauthn session during discoverable login: %s", err)
			util.JSONResponse(w, loginError, http.StatusInternalServerError)
			return
		}

		userHandler := func(rawID, userHandle []byte) (webauthn.User, error) {
			user, _, err := findUserByCredential(rawID, userHandle)
			return user, err
		}

		// Finish the discoverable login using the proper method
		cred, err := ctx.webAuthn.FinishDiscoverableLogin(userHandler, sessionData, r)
		if err != nil {
			logger.Errorf("Error finishing discoverable login: %s", err)
			util.JSONResponse(w, loginError, http.StatusInternalServerError)
			return
		}

		// Get the user that was matched
		matchedUser, matchedUsername, err := findUserByCredential(cred.ID, nil)
		if err != nil {
			logger.Errorf("Error getting matched user: %s", err)
			util.JSONResponse(w, loginError, http.StatusInternalServerError)
			return
		}

		logger.Infof("Found matching user %s for discoverable login", matchedUsername)

		// Process the credential
		if err := processCredential(matchedUser.(u.User), cred, matchedUsername); err != nil {
			logger.Errorf("Error: %s", err)
			util.JSONResponse(w, loginError, http.StatusBadRequest)
			return
		}

		// Create a new context with the matched user
		ctx.username = matchedUsername
		ctx.user = matchedUser.(u.User)

		// Check if user is allowed
		if !isUserAllowed(ctx.username, ctx.user) {
			logger.Warnf("WebAuthn user %s not in allowed_users list, authentication denied", ctx.username)
			util.JSONResponse(w, notAllowedError, http.StatusForbidden)
			return
		}

		// Set user as authenticated
		authenticateUser(ctx, r, w)
		// Create response message
		responseMsg := WebAuthnMessage{Message: "Authentication Successful"}
		
		// If redirect URL is provided and valid, include it in the response
		if redirectURL != "" && validateRedirectURL(redirectURL) {
			// Create a custom response with redirect URL
			type AuthSuccessResponse struct {
				Message     string `json:"Message"`
				RedirectURL string `json:"redirect_url,omitempty"`
			}
			
			response := AuthSuccessResponse{
				Message:     "Authentication Successful",
				RedirectURL: redirectURL,
			}
			
			util.JSONResponse(w, response, http.StatusOK)
		} else {
			util.JSONResponse(w, responseMsg, http.StatusOK)
		}
		return
	}

	// Regular login with username
	user, exists := users[ctx.username]
	if !exists {
		logger.Errorf("User %s does not exist", ctx.username)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}
	ctx.user = user

	// Load the session data
	sessionData, err := util.FetchWebauthnSession(ctx.session, "authentication", r)
	if err != nil {
		logger.Errorf("Error getting Webauthn session during login: %s", err)
		util.JSONResponse(w, loginError, http.StatusInternalServerError)
		return
	}

	cred, err := ctx.webAuthn.FinishLogin(user, sessionData, r)
	if err != nil {
		logger.Errorf("Error finishing Webauthn login: %s", err)
		util.JSONResponse(w, loginError, http.StatusInternalServerError)
		return
	}

	// Process the credential
	if err := processCredential(user, cred, ctx.username); err != nil {
		logger.Errorf("Error: %s", err)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	// Check if user is allowed
	if !isUserAllowed(ctx.username, ctx.user) {
		logger.Warnf("WebAuthn user %s not in allowed_users list, authentication denied", ctx.username)
		util.JSONResponse(w, notAllowedError, http.StatusForbidden)
		return
	}

	// Set user as authenticated
	authenticateUser(ctx, r, w)
	
	// Create response message
	responseMsg := WebAuthnMessage{Message: "Authentication Successful"}
	
	// If redirect URL is provided and valid, include it in the response
	if redirectURL != "" && validateRedirectURL(redirectURL) {
		// Create a custom response with redirect URL
		type AuthSuccessResponse struct {
			Message     string `json:"Message"`
			RedirectURL string `json:"redirect_url,omitempty"`
		}
		
		response := AuthSuccessResponse{
			Message:     "Authentication Successful",
			RedirectURL: redirectURL,
		}
		
		util.JSONResponse(w, response, http.StatusOK)
	} else {
		util.JSONResponse(w, responseMsg, http.StatusOK)
	}
}

/*
/webauthn/register/get_credential_creation_options -
Step 1 of the registration process, get credential creation options
*/
func GetCredentialCreationOptions(w http.ResponseWriter, r *http.Request) {
	ctx, err := initHandlerContext(r)
	if err != nil {
		logger.Errorf("%s", err)
		util.JSONResponse(w, registrationError, http.StatusBadRequest)
		return
	}

	if ctx.username == "" {
		logger.Errorf("Username is required for registration")
		util.JSONResponse(w, registrationError, http.StatusBadRequest)
		return
	}

	// We allow a user to register multiple time with different authenticators.
	// First check if they are an existing user
	var user u.User
	var exists bool
	
	if user, exists = users[ctx.username]; !exists {
		// Not found, see if they have registered previously
		if user, exists = registrations[ctx.username]; !exists {
			// Create a new user
			user = *u.NewUser(ctx.username)
			registrations[ctx.username] = user
		}
	}
	
	ctx.user = user

	// Generate PublicKeyCredentialCreationOptions, session data
	options, sessionData, err := ctx.webAuthn.BeginRegistration(user, user.UserRegistrationOptions)
	if err != nil {
		logger.Errorf("Error beginning Webauthn registration: %s", err)
		util.JSONResponse(w, registrationError, http.StatusInternalServerError)
		return
	}

	// Store session data as marshaled JSON
	if err = util.SaveWebauthnSession(ctx.session, "registration", sessionData, r, w); err != nil {
		logger.Errorf("Error saving Webauthn session during registration: %s", err)
		util.JSONResponse(w, registrationError, http.StatusInternalServerError)
		return
	}

	util.JSONResponse(w, options, http.StatusOK)
}

/*
/webauthn/register/process_registration_attestation -
Step 2 of the registration process, process the attestation (new credential) from the client authenticator
*/
// checkCredentialUniqueness checks if a credential is already registered to another user
func checkCredentialUniqueness(credentialID []byte, username string) error {
	for uname, u := range users {
		if uname == username {
			continue // Skip the current user
		}
		for _, c := range u.Credentials {
			if bytes.Equal(c.ID, credentialID) {
				return fmt.Errorf("credential already registered to user %s", u.Name)
			}
		}
	}
	
	for rname, r := range registrations {
		if rname == username {
			continue // Skip the current registrant
		}
		for _, c := range r.Credentials {
			if bytes.Equal(c.ID, credentialID) {
				return fmt.Errorf("credential already registered to registrant %s", r.Name)
			}
		}
	}
	
	return nil
}

func ProcessRegistrationAttestation(w http.ResponseWriter, r *http.Request) {
	ctx, err := initHandlerContext(r)
	if err != nil {
		logger.Errorf("%s", err)
		util.JSONResponse(w, registrationError, http.StatusBadRequest)
		return
	}

	if ctx.username == "" {
		logger.Errorf("Username is required for registration")
		util.JSONResponse(w, registrationError, http.StatusBadRequest)
		return
	}

	// First check if they are an existing user
	var user u.User
	var exists bool
	
	if user, exists = users[ctx.username]; !exists {
		// Not found, check the registrants pool
		if user, exists = registrations[ctx.username]; !exists {
			// Something's wrong here. We made it here without the registrant going
			// through GetCredentialCreationOptions. Fail this request.
			logger.Errorf("Registrant %s skipped GetCredentialCreationOptions step, failing registration", ctx.username)
			util.JSONResponse(w, registrationError, http.StatusBadRequest)
			return
		}
	}
	
	ctx.user = user

	// Load the session data
	sessionData, err := util.FetchWebauthnSession(ctx.session, "registration", r)
	if err != nil {
		logger.Errorf("Error getting Webauthn session during registration: %s", err)
		util.JSONResponse(w, registrationError, http.StatusInternalServerError)
		return
	}

	credential, err := ctx.webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		logger.Errorf("Error finishing Webauthn registration: %s", err)
		util.JSONResponse(w, registrationError, http.StatusInternalServerError)
		return
	}

	// Check that the credential doesn't belong to another user or registrant
	if err := checkCredentialUniqueness(credential.ID, ctx.username); err != nil {
		logger.Errorf("Error registering credential for user %s: %s", ctx.username, err)
		util.JSONResponse(w, registrationError, http.StatusBadRequest)
		return
	}

	// Add the credential to the user
	user.AddCredential(*credential)

	// Note: enabling this can be risky as it allows anyone to add themselves to the proxy.
	// Only enable test mode during testing!
	if configuration.TestMode {
		users[ctx.username] = user
		delete(registrations, ctx.username)
	}

	// Marshal the user so it can be added to the credentials file
	marshaledUser, err := user.Marshal()
	if err != nil {
		logger.Errorf("Error marshalling user object: %s", err)
		util.JSONResponse(w, registrationError, http.StatusInternalServerError)
		return
	}

	userCredText := fmt.Sprintf("%s: %s", ctx.username, marshaledUser)
	successMessage := RegistrationSuccess{
		Message: "Registration Successful. Please share the values below with your system administrator so they can add you!",
		Data:    userCredText,
	}
	logger.Infof("New user registration: %s", userCredText)
	util.JSONResponse(w, successMessage, http.StatusOK)
}

// Check that the origin is in our configuration or we're allowing dynamic origins
func checkOrigin(r *http.Request) (*webauthn.WebAuthn, *sessions.CookieStore, error) {
	u, err := url.Parse(r.URL.RequestURI())
	if err != nil {
		return nil, nil, fmt.Errorf("RPOrigin not valid URL: %+v", err)
	}

	// Try to determine the scheme, falling back to https
	var scheme string
	if u.Scheme != "" {
		scheme = u.Scheme
	} else if r.Header.Get("X-Forwarded-Proto") != "" {
		scheme = r.Header.Get("X-Forwarded-Proto")
	} else if r.TLS != nil {
		scheme = "https"
	} else {
		scheme = "http"
	}
	origin := fmt.Sprintf("%s://%s", scheme, r.Host)

	if webAuthn, exists := webAuthns[origin]; exists {
		sessionStore := sessionStores[origin]
		return webAuthn, sessionStore, nil
	}

	if !dynamicOrigins {
		return nil, nil, fmt.Errorf("request origin not valid: %s", origin)
	} else {
		logger.Infof("Adding new dynamic origin: %s", origin)
		webAuthn, sessionStore, err := createWebAuthnClient(origin)
		return webAuthn, sessionStore, err
	}
}

// createWebAuthnClient add webauthn client and session store per origin
func createWebAuthnClient(origin string) (*webauthn.WebAuthn, *sessions.CookieStore, error) {
	webAuthn, err := webauthn.New(&webauthn.Config{
		RPDisplayName: configuration.RPDisplayName, // Relying party display name
		RPID:          configuration.RPID,          // Relying party ID
		RPOrigins:     []string{origin},            // Relying party origin
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create WebAuthn for origin: %s", origin)
	}
	webAuthns[origin] = webAuthn

	var stringKeys []string
	var byteKeyPairs [][]byte
	if len(cookieSecrets) == 0 {
		stringKeys = []string{util.GenChallenge()}
	} else {
		stringKeys = cookieSecrets
	}
	// Each keypair consists of auth key and enc key.
	// If auth or enc key is changed all users will have to re-login.
	// enc key is optional and should be up to 32 bytes!
	// Otherwise it will whether fail with unclear error on login/register
	// or if you are lucky complain about the length. Not using enc key (nil).
	for _, s := range stringKeys {
		byteKeyPairs = append(byteKeyPairs, []byte(s), nil)
	}
	var sessionStore = sessions.NewCookieStore(byteKeyPairs...)
	sessionStore.Options = &sessions.Options{
		Domain:   configuration.CookieDomain,
		Path:     "/",
		MaxAge:   configuration.SessionSoftTimeoutSeconds,
		HttpOnly: true,
		Secure:   configuration.CookieSecure,
	}
	sessionStores[origin] = sessionStore
	return webAuthn, sessionStore, nil
}

// HandleOAuth2Login initiates the OAuth2 login flow
func HandleOAuth2Login(w http.ResponseWriter, r *http.Request) {
	// Get the provider name from the query parameters
	providerName := r.URL.Query().Get("provider")
	if providerName == "" {
		logger.Errorf("No OAuth2 provider specified")
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	// Get the provider
	provider, err := o.GetProviderByName(oauth2Providers, providerName)
	if err != nil {
		logger.Errorf("OAuth2 provider not found: %s", providerName)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	// Get redirect_url from query parameters if provided
	redirectURL := r.URL.Query().Get("redirect_url")
	
	// Validate the redirect URL if provided
	if redirectURL != "" && !validateRedirectURL(redirectURL) {
		// If redirect URL is not valid, set it to empty to use the default
		logger.Warnf("Invalid redirect URL provided: %s", redirectURL)
		redirectURL = ""
	}
	
	// Generate a state parameter for CSRF protection with redirect URL
	state, err := o.GenerateState(redirectURL)
	if err != nil {
		logger.Errorf("Failed to generate OAuth2 state: %s", err)
		util.JSONResponse(w, loginError, http.StatusInternalServerError)
		return
	}

	// Store the state in memory
	oauth2States[state.Value] = state

	// Get the authorization URL
	authURL := provider.GetAuthURL(state.Value)

	// Redirect to the authorization URL
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// HandleOAuth2Callback handles the OAuth2 callback
func HandleOAuth2Callback(w http.ResponseWriter, r *http.Request) {
	// Get the state and code from the query parameters
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	providerName := r.URL.Query().Get("provider")

	// Validate state
	storedState, exists := oauth2States[state]
	if !exists {
		logger.Errorf("Invalid OAuth2 state")
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	// Check if state has expired
	if storedState.ExpiresAt.Before(time.Now()) {
		logger.Errorf("OAuth2 state has expired")
		delete(oauth2States, state)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	// Delete the state from memory
	delete(oauth2States, state)

	// Get the provider
	provider, err := o.GetProviderByName(oauth2Providers, providerName)
	if err != nil {
		logger.Errorf("OAuth2 provider not found: %s", providerName)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	// Exchange the code for a token
	tokenResp, err := provider.ExchangeCodeForToken(code)
	if err != nil {
		logger.Errorf("Failed to exchange code for token: %s", err)
		util.JSONResponse(w, loginError, http.StatusInternalServerError)
		return
	}

	// Get the user info
	userInfo, err := provider.GetUserInfo(tokenResp.AccessToken)
	if err != nil {
		logger.Errorf("Failed to get user info: %s", err)
		util.JSONResponse(w, loginError, http.StatusInternalServerError)
		return
	}

	// Create or update the user
	user, err := provider.CreateOrUpdateUser(userInfo, users)
	if err != nil {
		logger.Errorf("Failed to create or update user: %s", err)
		util.JSONResponse(w, loginError, http.StatusInternalServerError)
		return
	}

	// Add or update the user in the users map
	users[user.Name] = *user

	// Initialize handler context
	ctx, err := initHandlerContext(r)
	if err != nil {
		logger.Errorf("%s", err)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	// Set the username
	ctx.username = user.Name
	ctx.user = *user

	// Check if user is allowed
	if !isUserAllowed(ctx.username, ctx.user) {
		logger.Warnf("OAuth2 user %s with email %s not in allowed_users list, authentication denied",
			ctx.username, user.OAuth2Data["email"])
		
		// Redirect to the stored redirect URL or the login page
		if storedState.RedirectURL != "" && validateRedirectURL(storedState.RedirectURL) {
			http.Redirect(w, r, storedState.RedirectURL, http.StatusTemporaryRedirect)
		} else {
			// Fallback to query parameter for backward compatibility
			redirectURL := r.URL.Query().Get("redirect_url")
			if redirectURL != "" && validateRedirectURL(redirectURL) {
				http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
			} else {
				http.Redirect(w, r, "/auth_proxy/login", http.StatusTemporaryRedirect)
			}
		}
		return
	}

	// Authenticate the user
	authenticateUser(ctx, r, w)

	// Redirect to the stored redirect URL or the login page
	if storedState.RedirectURL != "" && validateRedirectURL(storedState.RedirectURL) {
		logger.Warnf("Authentication ok -> redirect to (state) %s", storedState.RedirectURL)
		http.Redirect(w, r, storedState.RedirectURL, http.StatusTemporaryRedirect)
	} else {
		// Fallback to query parameter for backward compatibility
		redirectURL := r.URL.Query().Get("redirect_url")
		if redirectURL != "" && validateRedirectURL(redirectURL) {
			logger.Warnf("Authentication ok -> redirect to (param) %s", redirectURL)
			http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		} else {
			logger.Warnf("Authentication ok -> redirect to start page")
			http.Redirect(w, r, "/auth_proxy/login", http.StatusTemporaryRedirect)
		}
	}
}

// HandleOAuth2Providers returns a list of available OAuth2 providers
func HandleOAuth2Providers(w http.ResponseWriter, r *http.Request) {
	type ProviderInfo struct {
		Name        string   `json:"name"`
		DisplayName string   `json:"displayName"`
		Icon   string   `json:"icon"`
		Scopes      []string `json:"scopes,omitempty"`
	}

	type ProvidersResponse struct {
		Providers []ProviderInfo `json:"providers"`
	}

	var providers []ProviderInfo
	for _, provider := range oauth2Providers {
		providers = append(providers, ProviderInfo{
			Name:        provider.Name,
			DisplayName: provider.DisplayName,
			Icon:   provider.Icon,
			Scopes:      provider.Scopes,
		})
	}

	response := ProvidersResponse{
		Providers: providers,
	}

	util.JSONResponse(w, response, http.StatusOK)
}
