package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

// Build-time variables injected via ldflags
var (
	Version    = "dev"
	CommitHash = "unknown"
	BuildTime  = "unknown"
)

func main() {
	// Check if no arguments provided
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	// Get command first
	command := os.Args[1]

	// Handle special commands that don't need flags
	switch command {
	case "help", "--help", "-help":
		printUsage()
		return
	case "version", "--version", "-version":
		fmt.Printf("OIDC Tool Go Implementation %s\n", Version)
		fmt.Printf("Commit: %s\n", CommitHash)
		fmt.Printf("Built: %s\n", BuildTime)
		return
	case "cache-info":
		tokenCache := NewTokenCache()
		tokenCache.DisplayCacheInfo()
		return
	case "clear-cache":
		tokenCache := NewTokenCache()
		tokenCache.ClearCache()
		fmt.Println("Token cache cleared successfully.")
		return
	}

	// For commands that need flags, create a new FlagSet and parse remaining args
	var authority, clientID, scope string
	var help, version bool

	fs := flag.NewFlagSet(command, flag.ExitOnError)
	fs.StringVar(&authority, "authority", "", "The OIDC authority URL")
	fs.StringVar(&clientID, "client-id", "", "The OIDC client ID")
	fs.StringVar(&scope, "scope", "", "The requested scope")
	fs.BoolVar(&help, "help", false, "Show help")
	fs.BoolVar(&version, "version", false, "Show version")

	// Custom usage for the flagset
	fs.Usage = func() {
		printUsage()
	}

	// Parse flags from position 2 onwards
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(1)
	}

	// Handle help for specific commands
	if help {
		printUsage()
		return
	}

	if version {
		fmt.Printf("OIDC Tool Go Implementation %s\n", Version)
		fmt.Printf("Commit: %s\n", CommitHash)
		fmt.Printf("Built: %s\n", BuildTime)
		return
	}

	// Initialize services
	tokenCache := NewTokenCache()
	oidcService := NewOidcService(tokenCache)

	// Handle commands that require parameters
	switch command {
	case "token":
		if authority == "" || clientID == "" || scope == "" {
			fmt.Println("Error: authority, client-id, and scope are required for token command")
			printUsage()
			os.Exit(1)
		}
		if err := oidcService.AcquireToken(authority, clientID, scope); err != nil {
			log.Fatalf("Error acquiring token: %v", err)
		}

	case "remove-token":
		if authority == "" || clientID == "" || scope == "" {
			fmt.Println("Error: authority, client-id, and scope are required for remove-token command")
			printUsage()
			os.Exit(1)
		}
		tokenCache.RemoveToken(authority, clientID, scope)
		fmt.Println("Token removed from cache.")

	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "OIDC Tool - Acquire access tokens using implicit flow with caching\n\n")
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  %s [command] [flags]\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Available Commands:\n")
	fmt.Fprintf(os.Stderr, "  token        Acquire an access token\n")
	fmt.Fprintf(os.Stderr, "  cache-info   Display information about the token cache\n")
	fmt.Fprintf(os.Stderr, "  clear-cache  Clear all cached tokens\n")
	fmt.Fprintf(os.Stderr, "  remove-token Remove a specific token from cache\n")
	fmt.Fprintf(os.Stderr, "  help         Show this help message\n")
	fmt.Fprintf(os.Stderr, "  version      Show version information\n\n")
	fmt.Fprintf(os.Stderr, "Flags for token and remove-token commands:\n")
	fmt.Fprintf(os.Stderr, "  --authority string    The OIDC authority URL\n")
	fmt.Fprintf(os.Stderr, "  --client-id string    The OIDC client ID\n")
	fmt.Fprintf(os.Stderr, "  --scope string        The requested scope\n\n")
	fmt.Fprintf(os.Stderr, "Examples:\n")
	fmt.Fprintf(os.Stderr, "  %s token --authority \"https://demo.duendesoftware.com\" --client-id \"interactive.public\" --scope \"openid profile\"\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s cache-info\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s clear-cache\n", os.Args[0])
}
