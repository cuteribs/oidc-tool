package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// DiscoveryDocument represents an OIDC discovery document
type DiscoveryDocument struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
	Issuer                string `json:"issuer"`
}

// OidcService handles OIDC operations
type OidcService struct {
	tokenCache  *TokenCache
	redirectURI string
}

// NewOidcService creates a new OIDC service instance
func NewOidcService(tokenCache *TokenCache) *OidcService {
	return &OidcService{
		tokenCache:  tokenCache,
		redirectURI: "http://localhost:5000/signin-oidc",
	}
}

// AcquireToken acquires an access token using OIDC implicit flow
func (s *OidcService) AcquireToken(authority, clientID, scope string) error {
	fmt.Println("Starting OIDC token acquisition...")
	fmt.Printf("Authority: %s\n", authority)
	fmt.Printf("Client ID: %s\n", clientID)
	fmt.Printf("Scope: %s\n", scope)
	fmt.Println()

	// Check cache first
	cachedToken := s.tokenCache.GetToken(authority, clientID, scope)
	if cachedToken != nil {
		fmt.Println("✅ Found valid cached token!")
		if cachedToken.OID != nil && *cachedToken.OID != "" {
			fmt.Printf("OID: %s\n", *cachedToken.OID)
		}
		fmt.Printf("Access Token: %s\n", cachedToken.AccessToken)
		fmt.Printf("Expires at: %s UTC\n", cachedToken.ExpiresAt.Format("2006-01-02 15:04:05"))
		tokenType := "Bearer"
		if cachedToken.TokenType != nil {
			tokenType = *cachedToken.TokenType
		}
		fmt.Printf("Token Type: %s\n", tokenType)
		fmt.Println()
		return nil
	}

	fmt.Println("No valid cached token found. Starting interactive authentication...")
	fmt.Println()

	// Discover OIDC configuration
	discoveryDocument, err := s.getDiscoveryDocument(authority)
	if err != nil {
		return fmt.Errorf("error fetching discovery document: %w", err)
	}

	if discoveryDocument.AuthorizationEndpoint == "" {
		return fmt.Errorf("no authorization endpoint found in discovery document")
	}

	fmt.Printf("Authorization Endpoint: %s\n", discoveryDocument.AuthorizationEndpoint)
	fmt.Println()

	// Generate state parameter for security
	state, err := generateRandomString(32)
	if err != nil {
		return fmt.Errorf("error generating state: %w", err)
	}

	// Build authorization URL
	authURL := s.buildAuthorizationURL(discoveryDocument.AuthorizationEndpoint, clientID, scope, state)

	fmt.Println("Opening browser for authentication...")
	fmt.Printf("Authorization URL: %s\n", authURL)
	fmt.Println()

	// Start local HTTP server for callback
	callbackData := make(chan map[string]string, 1)
	server := s.startCallbackServer(callbackData)
	defer server.Shutdown(context.Background())

	// Open browser
	if err := openBrowser(authURL); err != nil {
		fmt.Printf("Could not open browser automatically. Please navigate to: %s\n", authURL)
	}

	fmt.Println("Waiting for callback...")
	fmt.Println("Please complete the authentication in your browser.")
	fmt.Println()

	// Wait for callback with timeout
	var params map[string]string
	select {
	case params = <-callbackData:
		// Callback received
	case <-time.After(5 * time.Minute):
		return fmt.Errorf("timeout waiting for authentication callback")
	}

	// Process callback data
	if errorParam, exists := params["error"]; exists {
		errorDesc := params["error_description"]
		if errorDesc != "" {
			return fmt.Errorf("authentication error: %s - %s", errorParam, errorDesc)
		}
		return fmt.Errorf("authentication error: %s", errorParam)
	}

	returnedState := params["state"]
	if returnedState != state {
		return fmt.Errorf("state parameter mismatch")
	}

	accessToken := params["access_token"]
	if accessToken == "" {
		return fmt.Errorf("no access token received")
	}

	fmt.Println("✅ Access token acquired successfully!")
	fmt.Printf("Access Token: %s\n", accessToken)
	fmt.Println()

	// Cache the token
	expiresIn := params["expires_in"]
	expiresInSeconds := 3600 // Default 1 hour
	if expiresIn != "" {
		if parsed, err := strconv.Atoi(expiresIn); err == nil {
			expiresInSeconds = parsed
		}
	}

	tokenType := params["token_type"]
	if tokenType == "" {
		tokenType = "Bearer"
	}

	tokenCacheEntry := &TokenCacheEntry{
		AccessToken: accessToken,
		Authority:   authority,
		ClientID:    clientID,
		Scope:       scope,
		TokenType:   &tokenType,
		ExpiresAt:   time.Now().UTC().Add(time.Duration(expiresInSeconds) * time.Second),
	}

	s.tokenCache.SaveToken(tokenCacheEntry)
	fmt.Printf("🔄 Token cached successfully. Expires at: %s UTC\n", tokenCacheEntry.ExpiresAt.Format("2006-01-02 15:04:05"))
	fmt.Println()

	// Optionally decode and display token info
	s.displayTokenInfo(accessToken, discoveryDocument)

	return nil
}

// getDiscoveryDocument fetches the OIDC discovery document
func (s *OidcService) getDiscoveryDocument(authority string) (*DiscoveryDocument, error) {
	discoveryURL := strings.TrimSuffix(authority, "/") + "/.well-known/openid-configuration"
	fmt.Printf("Fetching discovery document from: %s\n", discoveryURL)

	resp, err := http.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery document request failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read discovery document response: %w", err)
	}

	var discoveryDoc DiscoveryDocument
	if err := json.Unmarshal(body, &discoveryDoc); err != nil {
		return nil, fmt.Errorf("failed to parse discovery document: %w", err)
	}

	return &discoveryDoc, nil
}

// buildAuthorizationURL builds the authorization URL for implicit flow
func (s *OidcService) buildAuthorizationURL(authorizationEndpoint, clientID, scope, state string) string {
	nonce, _ := generateRandomString(32)

	params := url.Values{
		"response_type": {"token"},
		"response_mode": {"form_post"},
		"client_id":     {clientID},
		"redirect_uri":  {s.redirectURI},
		"scope":         {scope},
		"state":         {state},
		"nonce":         {nonce},
	}

	return authorizationEndpoint + "?" + params.Encode()
}

// startCallbackServer starts the local HTTP server for callback
func (s *OidcService) startCallbackServer(callbackData chan<- map[string]string) *http.Server {
	server := &http.Server{
		Addr: ":5000",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.handleCallback(w, r, callbackData)
		}),
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Callback server error: %v", err)
		}
	}()

	return server
}

// handleCallback handles the OIDC callback request
func (s *OidcService) handleCallback(w http.ResponseWriter, r *http.Request, callbackData chan<- map[string]string) {
	var params map[string]string

	if r.Method == "POST" {
		// Parse form data from POST body
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form data", http.StatusBadRequest)
			return
		}
		params = make(map[string]string)
		for key, values := range r.PostForm {
			if len(values) > 0 {
				params[key] = values[0]
			}
		}
	} else {
		// Fallback to query parameters for GET requests
		params = make(map[string]string)
		for key, values := range r.URL.Query() {
			if len(values) > 0 {
				params[key] = values[0]
			}
		}
	}

	// Send the data to the callback channel
	select {
	case callbackData <- params:
		// Data sent successfully
	default:
		// Channel is full or closed
	}

	// Send response to browser
	error := params["error"]
	errorDescription := params["error_description"]
	accessToken := params["access_token"]

	var responseHTML string
	var statusCode int

	if error != "" {
		responseHTML = fmt.Sprintf(`
		<html>
			<body>
				<h1>Error</h1>
				<p>%s: %s</p>
			</body>
		</html>`, error, errorDescription)
		statusCode = http.StatusBadRequest
	} else if accessToken == "" {
		responseHTML = `
		<html>
			<body>
				<h1>Error</h1>
				<p>No access token received</p>
			</body>
		</html>`
		statusCode = http.StatusBadRequest
	} else {
		responseHTML = fmt.Sprintf(`
		<html>
			<body>
				<h1>Success</h1>
				<p>Access token received. You can close this window.</p>
				<div style='word-break: break-all; margin-top: 20px;'>
					<code>%s</code>
				</div>
			</body>
		</html>`, accessToken)
		statusCode = http.StatusOK
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(statusCode)
	w.Write([]byte(responseHTML))
}

// displayTokenInfo displays additional token information
func (s *OidcService) displayTokenInfo(accessToken string, discoveryDocument *DiscoveryDocument) {
	fmt.Println("Token Information:")
	fmt.Printf("Length: %d characters\n", len(accessToken))

	// If there's a userinfo endpoint, try to get user information
	if discoveryDocument.UserinfoEndpoint != "" {
		fmt.Println("Fetching user information...")

		req, err := http.NewRequest("GET", discoveryDocument.UserinfoEndpoint, nil)
		if err != nil {
			fmt.Printf("Could not create userinfo request: %v\n", err)
			return
		}

		req.Header.Set("Authorization", "Bearer "+accessToken)

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("Could not fetch user info: %v\n", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Could not read userinfo response: %v\n", err)
				return
			}

			var userInfo map[string]interface{}
			if err := json.Unmarshal(body, &userInfo); err != nil {
				fmt.Printf("Could not parse userinfo response: %v\n", err)
				return
			}

			fmt.Println("User Information:")
			userInfoJSON, _ := json.MarshalIndent(userInfo, "", "  ")
			fmt.Println(string(userInfoJSON))
		} else {
			fmt.Printf("Could not fetch user info: HTTP %d\n", resp.StatusCode)
		}
	}
}

// generateRandomString generates a random string of specified length
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// openBrowser opens the default browser with the given URL
func openBrowser(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
		args = []string{url}
	}

	return exec.Command(cmd, args...).Start()
}
