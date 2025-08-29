package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type discoveryDoc struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
}

func acquireToken(authority, clientID, scope, redirectURI string) error {
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
	server := startServer(redirectURI, callbackChan)
	defer server.Shutdown(context.Background())

	// Open browser
	fmt.Println("Opening browser...")
	if err := openBrowser(authURL); err != nil {
		fmt.Printf("Open manually: %s\n", authURL)
	}

	// Wait for callback
	select {
	case params := <-callbackChan:
		return processCallback(params, state)
	case <-time.After(5 * time.Minute):
		return fmt.Errorf("timeout waiting for callback")
	}
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

func processCallback(params map[string]string, expectedState string) error {
	if err := params["error"]; err != "" {
		desc := params["error_description"]
		if desc != "" {
			return fmt.Errorf("auth error: %s - %s", err, desc)
		}
		return fmt.Errorf("auth error: %s", err)
	}

	if params["state"] != expectedState {
		return fmt.Errorf("state mismatch")
	}

	token := params["access_token"]
	if token == "" {
		return fmt.Errorf("no access token received")
	}

	fmt.Printf("✅ Success! Access Token: %s\n", token)

	// Show expiration if available
	if expiresIn := params["expires_in"]; expiresIn != "" {
		if seconds, err := strconv.Atoi(expiresIn); err == nil {
			expires := time.Now().Add(time.Duration(seconds) * time.Second)
			fmt.Printf("Expires: %s\n", expires.Format("2006-01-02 15:04:05"))
		}
	}

	return nil
}

func startServer(redirectURI string, callbackChan chan<- map[string]string) *http.Server {
	// Extract port from redirect URI
	addr := ":5000" // default
	if u, err := url.Parse(redirectURI); err == nil && u.Host != "" {
		addr = u.Host
		if !strings.Contains(addr, ":") {
			addr += ":5000"
		}
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
