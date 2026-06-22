package main

import (
	"bufio"
	"context"
	"crypto/rand"
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
	AccessToken string
	ExpiresIn   string
	ExpiresAt   *time.Time
}

func acquireToken(authority, clientID, scope, redirectURI string, listenPort int) error {
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
		authURL := buildAuthURL(authEndpoint, clientID, scope, redirectURI, state, nonce)

		// Start callback server
		callbackChan := make(chan map[string]string, 1)
		server := startServer(redirectURI, listenPort, callbackChan)

		// Open browser
		fmt.Println("Opening browser...")
		if err := openBrowser(authURL); err != nil {
			fmt.Printf("Open manually: %s\n", authURL)
		}

		// Wait for callback
		var tokenResult *tokenInfo
		select {
		case params := <-callbackChan:
			tokenResult, err = processCallback(params, state)
			if err != nil {
				server.Shutdown(context.Background())
				return err
			}
		case <-time.After(5 * time.Minute):
			server.Shutdown(context.Background())
			return fmt.Errorf("timeout waiting for callback")
		}

		server.Shutdown(context.Background())

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

func buildAuthURL(endpoint, clientID, scope, redirectURI, state, nonce string) string {
	params := url.Values{
		"response_type": {"token"},
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

func processCallback(params map[string]string, expectedState string) (*tokenInfo, error) {
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

	token := params["access_token"]
	if token == "" {
		return nil, fmt.Errorf("no access token received")
	}

	result := &tokenInfo{
		AccessToken: token,
		ExpiresIn:   params["expires_in"],
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

func startServer(redirectURI string, listenPort int, callbackChan chan<- map[string]string) *http.Server {
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

	server := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleCallback(w, r, callbackChan)
		}),
	}

	go server.ListenAndServe()
	return server
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
	token := params["access_token"]
	errMsg := params["error"]

	if errMsg != "" {
		fmt.Fprintf(w, "<h1>Error</h1><p>%s</p>", errMsg)
	} else if token == "" {
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
	fmt.Printf("\n✅ Success! Access Token: %s\n", token.AccessToken)

	if token.ExpiresAt != nil {
		fmt.Printf("Expires: %s\n", token.ExpiresAt.Format("2006-01-02 15:04:05"))
	}
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
