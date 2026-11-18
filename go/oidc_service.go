package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type discoveryDoc struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
}

type tokenInfo struct {
	IDToken     string
	AccessToken string
	ExpiresIn   string
	ExpiresAt   *time.Time
}

func acquireToken(authority, clientID, scope, redirectURI, responseType string, listenPort int) error {
	for {
		fmt.Printf("Getting token from: %s\n", authority)

		// Get authorization endpoint
		authEndpoint, err := getAuthEndpoint(authority)
		if err != nil {
			return err
		}

		// Generate security parameters
		state := randomString(16)
		nonce := randomString(16)

		// Build auth URL
		authURL := buildAuthURL(authEndpoint, clientID, scope, redirectURI, responseType, state, nonce)

		// Start callback server and open browser
		callbackChan := make(chan map[string]string, 1)
		server := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handleCallback(w, r, callbackChan)
			}),
		}
		cleanup, err := listenAndOpen(server, redirectURI, listenPort, authURL)
		if err != nil {
			return err
		}

		// Wait for callback
		var tokenResult *tokenInfo
		select {
		case params := <-callbackChan:
			tokenResult, err = processCallback(params, state, nonce)
		case <-time.After(5 * time.Minute):
			err = fmt.Errorf("timeout waiting for callback")
		}
		cleanup()
		if err != nil {
			return err
		}

		// Display token information
		displayTokenInfo(tokenResult)

		// Interactive prompt
		if !promptForAction() {
			break // Exit the loop
		}
		// Continue the loop to refresh the token
	}

	return nil
}

func getAuthEndpoint(authority string) (string, error) {
	url := strings.TrimSuffix(authority, "/") + "/.well-known/openid-configuration"
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var doc discoveryDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", err
	}

	if doc.AuthorizationEndpoint == "" {
		return "", fmt.Errorf("no authorization endpoint found")
	}

	return doc.AuthorizationEndpoint, nil
}

func buildAuthURL(endpoint, clientID, scope, redirectURI, responseType, state, nonce string) string {
	params := url.Values{
		"response_type": {responseType},
		"response_mode": {"form_post"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"scope":         {scope},
		"state":         {state},
		"nonce":         {nonce},
		"prompt":        {"login"},
	}
	return endpoint + "?" + params.Encode()
}

func processCallback(params map[string]string, expectedState, expectedNonce string) (*tokenInfo, error) {
	if err := params["error"]; err != "" {
		desc := params["error_description"]
		if desc != "" {
			return nil, fmt.Errorf("auth error: %s - %s", err, desc)
		}
		return nil, fmt.Errorf("auth error: %s", err)
	}

	if params["state"] != expectedState {
		return nil, fmt.Errorf("state mismatch")
	}

	result := &tokenInfo{
		IDToken:     params["id_token"],
		AccessToken: params["access_token"],
		ExpiresIn:   params["expires_in"],
	}
	if result.IDToken == "" && result.AccessToken == "" {
		return nil, fmt.Errorf("no token received")
	}

	if result.IDToken != "" {
		claims, err := decodeJWT(result.IDToken)
		if err != nil {
			return nil, fmt.Errorf("invalid id_token: %w", err)
		}
		if claims["nonce"] != expectedNonce {
			return nil, fmt.Errorf("nonce mismatch")
		}
	}

	// Calculate expiration time if available
	if expiresIn := params["expires_in"]; expiresIn != "" {
		if seconds, err := strconv.Atoi(expiresIn); err == nil {
			expires := time.Now().Add(time.Duration(seconds) * time.Second)
			result.ExpiresAt = &expires
		}
	}

	return result, nil
}

func listenAddr(redirectURI string, listenPort int) string {
	// Extract port from redirect URI
	addr := ":5000" // default
	if u, err := url.Parse(redirectURI); err == nil && u.Host != "" {
		addr = u.Host
		if !strings.Contains(addr, ":") {
			addr += ":5000"
		}
	}

	// Override port with --listen-port if provided
	if listenPort > 0 {
		host := "localhost"
		if u, err := url.Parse(redirectURI); err == nil && u.Host != "" {
			if h, _, err := net.SplitHostPort(u.Host); err == nil {
				host = h
			} else if u.Hostname() != "" {
				host = u.Hostname()
			}
		}
		addr = fmt.Sprintf("%s:%d", host, listenPort)
	}

	return addr
}

func handleCallback(w http.ResponseWriter, r *http.Request, callbackChan chan<- map[string]string) {
	params := make(map[string]string)

	// Parse POST form or GET query params
	if r.Method == "POST" {
		r.ParseForm()
		for k, v := range r.PostForm {
			if len(v) > 0 {
				params[k] = v[0]
			}
		}
	} else {
		for k, v := range r.URL.Query() {
			if len(v) > 0 {
				params[k] = v[0]
			}
		}
	}

	// Send to channel
	select {
	case callbackChan <- params:
	default:
	}

	// Response to browser
	errMsg := params["error"]

	if errMsg != "" {
		fmt.Fprintf(w, "<h1>Error</h1><p>%s</p>", errMsg)
	} else if params["access_token"] == "" && params["id_token"] == "" {
		fmt.Fprint(w, "<h1>Error</h1><p>No token received</p>")
	} else {
		fmt.Fprint(w, "<h1>Success!</h1><p>Token received. You can close this window.</p>")
	}
}

func randomString(length int) string {
	bytes := make([]byte, length/2)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func openBrowser(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		cmd, args = "open", []string{url}
	default:
		cmd, args = "xdg-open", []string{url}
	}

	return exec.Command(cmd, args...).Start()
}

func displayTokenInfo(token *tokenInfo) {
	fmt.Println("\n✅ Success!")
	printToken("ID Token", token.IDToken)
	printToken("Access Token", token.AccessToken)

	if token.ExpiresAt != nil {
		fmt.Printf("\nExpires: %s\n", token.ExpiresAt.Format("2006-01-02 15:04:05"))
	}
}

func printToken(label, token string) {
	if token == "" {
		return
	}
	fmt.Printf("\n%s: %s\n", label, token)
	// Opaque (non-JWT) access tokens are printed as-is.
	if claims, err := decodeJWT(token); err == nil {
		b, _ := json.MarshalIndent(claims, "", "  ")
		fmt.Printf("%s claims:\n%s\n", label, b)
	}
}

// ponytail: payload decode only, no signature check; claims are displayed, never trusted.
// Add JWKS validation if this ever gates access to something.
func decodeJWT(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	return claims, json.Unmarshal(payload, &claims)
}

func promptForAction() bool {
	fmt.Print("\nPress 'R' to refresh token, or 'Enter' to exit: ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	input = strings.TrimSpace(strings.ToUpper(input))
	return input == "R"
}
