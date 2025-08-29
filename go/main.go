package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "help", "--help", "-h":
		printUsage()
	case "token":
		handleTokenCommand()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func handleTokenCommand() {
	var authority, clientID, scope, redirectURI string

	fs := flag.NewFlagSet("token", flag.ExitOnError)
	fs.StringVar(&authority, "authority", "", "OIDC authority URL")
	fs.StringVar(&clientID, "client-id", "", "OIDC client ID")
	fs.StringVar(&scope, "scope", "", "Requested scope")
	fs.StringVar(&redirectURI, "redirect-uri", "http://localhost:5000/signin-oidc", "Redirect URI")

	fs.Parse(os.Args[2:])

	if authority == "" || clientID == "" || scope == "" {
		fmt.Println("Error: authority, client-id, and scope are required")
		printUsage()
		os.Exit(1)
	}

	if err := acquireToken(authority, clientID, scope, redirectURI); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func printUsage() {
	fmt.Printf(`OIDC Tool - Acquire access tokens using implicit flow

Usage:
  %s <command> [flags]

Commands:
  token      Acquire an access token
  help       Show this help

Token Flags:
  --authority string     OIDC authority URL
  --client-id string     OIDC client ID  
  --scope string         Requested scope
  --redirect-uri string  Redirect URI (default: http://localhost:5000/signin-oidc)

Example:
  %s token --authority "https://demo.duendesoftware.com" --client-id "interactive.public" --scope "openid profile"
`, os.Args[0], os.Args[0])
}
