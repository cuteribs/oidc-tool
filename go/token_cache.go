package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TokenCacheEntry represents a cached token entry
type TokenCacheEntry struct {
	AccessToken  string    `json:"access_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	Authority    string    `json:"authority"`
	ClientID     string    `json:"client_id"`
	Scope        string    `json:"scope"`
	RefreshToken *string   `json:"refresh_token,omitempty"`
	TokenType    *string   `json:"token_type,omitempty"`
	OID          *string   `json:"oid,omitempty"`
}

// Custom JSON marshaling to handle time format compatibility
func (e *TokenCacheEntry) MarshalJSON() ([]byte, error) {
	type Alias TokenCacheEntry
	return json.Marshal(&struct {
		ExpiresAt string `json:"expires_at"`
		*Alias
	}{
		ExpiresAt: e.ExpiresAt.Format(time.RFC3339),
		Alias:     (*Alias)(e),
	})
}

// Custom JSON unmarshaling to handle different time formats
func (e *TokenCacheEntry) UnmarshalJSON(data []byte) error {
	type Alias TokenCacheEntry
	aux := &struct {
		ExpiresAt string `json:"expires_at"`
		*Alias
	}{
		Alias: (*Alias)(e),
	}
	
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	
	// Try multiple time formats for compatibility
	timeFormats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05",
	}
	
	var parseErr error
	for _, format := range timeFormats {
		if t, err := time.Parse(format, aux.ExpiresAt); err == nil {
			e.ExpiresAt = t.UTC()
			return nil
		} else {
			parseErr = err
		}
	}
	
	return fmt.Errorf("could not parse time %s: %v", aux.ExpiresAt, parseErr)
}

// IsExpired checks if the token is expired (with 5-minute buffer)
func (e *TokenCacheEntry) IsExpired() bool {
	return time.Now().UTC().After(e.ExpiresAt.Add(-5 * time.Minute))
}

// GetCacheKey returns the cache key for this entry
func (e *TokenCacheEntry) GetCacheKey() string {
	if e.OID != nil && *e.OID != "" {
		return *e.OID
	}
	return strings.ToLower(fmt.Sprintf("%s:%s:%s", e.Authority, e.ClientID, e.Scope))
}

// TokenCache manages token caching with OID-based keys
type TokenCache struct {
	cacheFilePath string
	cache         map[string]*TokenCacheEntry
}

// NewTokenCache creates a new token cache instance
func NewTokenCache() *TokenCache {
	// Get user home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Printf("Warning: Could not get user home directory: %v", err)
		homeDir = "."
	}

	// Create cache directory
	cacheDir := filepath.Join(homeDir, ".oidc-tool")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		log.Printf("Warning: Could not create cache directory: %v", err)
	}

	cacheFilePath := filepath.Join(cacheDir, "token_cache.json")
	tc := &TokenCache{
		cacheFilePath: cacheFilePath,
		cache:         make(map[string]*TokenCacheEntry),
	}

	tc.loadCache()
	return tc
}

// GetToken retrieves a valid token for the given parameters
func (tc *TokenCache) GetToken(authority, clientID, scope string) *TokenCacheEntry {
	// Search through all cached entries for matching parameters
	for _, entry := range tc.cache {
		if !entry.IsExpired() &&
			strings.EqualFold(entry.Authority, authority) &&
			strings.EqualFold(entry.ClientID, clientID) &&
			strings.EqualFold(entry.Scope, scope) {
			return entry
		}
	}

	// Clean up expired tokens
	tc.cleanupExpiredTokens()
	return nil
}

// GetTokenByOID retrieves a token by OID
func (tc *TokenCache) GetTokenByOID(oid string) *TokenCacheEntry {
	entry, exists := tc.cache[oid]
	if exists {
		if !entry.IsExpired() {
			return entry
		} else {
			// Remove expired token
			delete(tc.cache, oid)
			tc.saveCache()
		}
	}
	return nil
}

// SaveToken saves a token to the cache
func (tc *TokenCache) SaveToken(entry *TokenCacheEntry) {
	// Extract OID from the access token
	oid := extractOIDFromToken(entry.AccessToken)
	if oid != "" {
		entry.OID = &oid
		tc.cache[oid] = entry
		fmt.Printf("Token cached with OID: %s\n", oid)
	} else {
		// Fallback to old key format if OID is not available
		fallbackKey := entry.GetCacheKey()
		tc.cache[fallbackKey] = entry
		fmt.Printf("Token cached with fallback key (no OID found): %s\n", fallbackKey)
	}

	tc.saveCache()
}

// RemoveToken removes a specific token from cache
func (tc *TokenCache) RemoveToken(authority, clientID, scope string) {
	// Find and remove the token
	var keyToRemove string
	for key, entry := range tc.cache {
		if strings.EqualFold(entry.Authority, authority) &&
			strings.EqualFold(entry.ClientID, clientID) &&
			strings.EqualFold(entry.Scope, scope) {
			keyToRemove = key
			break
		}
	}

	if keyToRemove != "" {
		delete(tc.cache, keyToRemove)
		tc.saveCache()
	}
}

// ClearCache clears all cached tokens
func (tc *TokenCache) ClearCache() {
	tc.cache = make(map[string]*TokenCacheEntry)
	tc.saveCache()
}

// DisplayCacheInfo displays information about the cache
func (tc *TokenCache) DisplayCacheInfo() {
	fmt.Printf("Cache location: %s\n", tc.cacheFilePath)
	fmt.Printf("Cached tokens: %d\n", len(tc.cache))

	if len(tc.cache) > 0 {
		fmt.Println("\nCached entries:")
		for _, entry := range tc.cache {
			status := "EXPIRED"
			if !entry.IsExpired() {
				status = fmt.Sprintf("Valid until %s UTC", entry.ExpiresAt.Format("2006-01-02 15:04:05"))
			}
			oidInfo := ""
			if entry.OID != nil && *entry.OID != "" {
				oidInfo = fmt.Sprintf(" | OID: %s", *entry.OID)
			}
			fmt.Printf("  %s | %s | %s%s - %s\n", entry.Authority, entry.ClientID, entry.Scope, oidInfo, status)
		}
	}
}

// loadCache loads cache from file
func (tc *TokenCache) loadCache() {
	data, err := os.ReadFile(tc.cacheFilePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("Warning: Could not load token cache: %v", err)
		}
		tc.cache = make(map[string]*TokenCacheEntry)
		return
	}

	var entries []*TokenCacheEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		log.Printf("Warning: Could not parse token cache: %v", err)
		tc.cache = make(map[string]*TokenCacheEntry)
		return
	}

	// Load entries and filter out expired ones
	tc.cache = make(map[string]*TokenCacheEntry)
	for _, entry := range entries {
		if !entry.IsExpired() {
			key := entry.GetCacheKey()
			tc.cache[key] = entry
		}
	}
}

// saveCache saves cache to file
func (tc *TokenCache) saveCache() {
	entries := make([]*TokenCacheEntry, 0, len(tc.cache))
	for _, entry := range tc.cache {
		entries = append(entries, entry)
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		log.Printf("Warning: Could not marshal token cache: %v", err)
		return
	}

	if err := os.WriteFile(tc.cacheFilePath, data, 0600); err != nil {
		log.Printf("Warning: Could not save token cache: %v", err)
	}
}

// cleanupExpiredTokens removes expired tokens from cache
func (tc *TokenCache) cleanupExpiredTokens() {
	var expiredKeys []string
	for key, entry := range tc.cache {
		if entry.IsExpired() {
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		delete(tc.cache, key)
	}

	if len(expiredKeys) > 0 {
		tc.saveCache()
	}
}

// extractOIDFromToken extracts OID claim from JWT token
func extractOIDFromToken(accessToken string) string {
	return extractClaimFromJWT(accessToken, "oid")
}

// extractClaimFromJWT extracts a claim from a JWT token
func extractClaimFromJWT(jwtToken, claimName string) string {
	// JWT tokens have three parts separated by dots: header.payload.signature
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return ""
	}

	// Decode the payload (second part)
	payload := parts[1]

	// Add padding if necessary for base64 decoding
	for len(payload)%4 != 0 {
		payload += "="
	}

	// Decode from base64url to bytes
	payload = strings.ReplaceAll(payload, "-", "+")
	payload = strings.ReplaceAll(payload, "_", "/")

	payloadBytes, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		log.Printf("Warning: Could not decode JWT payload: %v", err)
		return ""
	}

	// Parse JSON and extract the claim
	var payloadData map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payloadData); err != nil {
		log.Printf("Warning: Could not parse JWT payload: %v", err)
		return ""
	}

	if claim, exists := payloadData[claimName]; exists {
		if claimStr, ok := claim.(string); ok {
			return claimStr
		}
	}

	return ""
}
