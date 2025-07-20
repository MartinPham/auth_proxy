package oauth2

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	u "github.com/martinpham/auth_proxy/user"
)

// Provider represents an OAuth2 provider
type Provider struct {
	Name         string
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	RedirectURL  string
	Scopes       []string
	DisplayName  string
	Icon    string
}

// TokenResponse represents the OAuth2 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// UserInfo represents the user information from the OAuth2 provider
type UserInfo struct {
	ID            string `json:"id,omitempty"`
	Sub           string `json:"sub,omitempty"`
	Email         string `json:"email,omitempty"`
	VerifiedEmail bool   `json:"verified_email,omitempty"`
	Name          string `json:"name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	Picture       string `json:"picture,omitempty"`
	Locale        string `json:"locale,omitempty"`
}

// State represents the OAuth2 state
type State struct {
	Value       string
	ExpiresAt   time.Time
	RedirectURL string
}

// NewProvider creates a new OAuth2 provider
func NewProvider(name, clientID, clientSecret, authURL, tokenURL, userInfoURL, redirectURL string, scopes []string, displayName, icon string) *Provider {
	return &Provider{
		Name:         name,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      authURL,
		TokenURL:     tokenURL,
		UserInfoURL:  userInfoURL,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		DisplayName:  displayName,
		Icon:    icon,
	}
}

// GenerateState generates a random state string for CSRF protection
// If redirectURL is provided, it will be stored in the state for later use
func GenerateState(redirectURL string) (*State, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	state := &State{
		Value:       base64.URLEncoding.EncodeToString(b),
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		RedirectURL: redirectURL,
	}
	return state, nil
}

// GetAuthURL returns the authorization URL for the provider
func (p *Provider) GetAuthURL(state string) string {
	u, _ := url.Parse(p.AuthURL)
	q := u.Query()
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", p.RedirectURL)
	q.Set("response_type", "code")
	q.Set("state", state)
	q.Set("scope", strings.Join(p.Scopes, " "))
	u.RawQuery = q.Encode()
	return u.String()
}

// ExchangeCodeForToken exchanges the authorization code for an access token
func (p *Provider) ExchangeCodeForToken(code string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", p.ClientID)
	data.Set("client_secret", p.ClientSecret)
	data.Set("redirect_uri", p.RedirectURL)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequest("POST", p.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to exchange code for token: %s - %s", resp.Status, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// GetUserInfo fetches the user information from the provider
func (p *Provider) GetUserInfo(accessToken string) (*UserInfo, error) {
	req, err := http.NewRequest("GET", p.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: %s - %s", resp.Status, string(body))
	}

	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

// CreateOrUpdateUser creates or updates a user from OAuth2 user info
func (p *Provider) CreateOrUpdateUser(userInfo *UserInfo, users map[string]u.User) (*u.User, error) {
	// Get user ID from provider-specific field
	userID := userInfo.ID
	if userID == "" {
		userID = userInfo.Sub // Some providers use 'sub' instead of 'id'
	}
	
	if userID == "" {
		return nil, errors.New("could not determine user ID from OAuth2 provider")
	}

	// Use email as username if available, otherwise use provider name + ID
	username := userInfo.Email
	if username == "" {
		username = fmt.Sprintf("%s_%s", p.Name, userID)
	}

	// Check if user already exists
	for _, existingUser := range users {
		if existingUser.OAuth2Provider == p.Name && existingUser.OAuth2ID == userID {
			// User exists, update OAuth2 data
			existingUser.OAuth2Data["email"] = userInfo.Email
			existingUser.OAuth2Data["name"] = userInfo.Name
			existingUser.OAuth2Data["picture"] = userInfo.Picture
			return &existingUser, nil
		}
	}

	// Create new user
	userData := make(map[string]string)
	userData["email"] = userInfo.Email
	userData["name"] = userInfo.Name
	userData["picture"] = userInfo.Picture

	newUser := u.NewOAuth2User(username, p.Name, userID, userData)
	return newUser, nil
}

// GetProviderByName returns a provider by name
func GetProviderByName(providers map[string]*Provider, name string) (*Provider, error) {
	provider, exists := providers[name]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", name)
	}
	return provider, nil
}