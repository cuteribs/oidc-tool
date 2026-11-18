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
	var authority, clientID, scope, redirectURI, responseType string
	var listenPort int

	fs := flag.NewFlagSet("token", flag.ExitOnError)
	fs.StringVar(&authority, "authority", "", "OIDC authority URL")
	fs.StringVar(&clientID, "client-id", "", "OIDC client ID")
	fs.StringVar(&scope, "scope", "", "Requested scope")
	fs.StringVar(&redirectURI, "redirect-uri", "http://localhost:5000/signin-oidc", "Redirect URI")
	fs.StringVar(&responseType, "response-type", "id_token token", "OIDC response_type")
	fs.IntVar(&listenPort, "listen-port", 0, "Port to listen on (overrides port derived from redirect-uri)")

	fs.Parse(os.Args[2:])

	if authority == "" || clientID == "" || scope == "" {
		fmt.Println("Error: authority, client-id, and scope are required")
		printUsage()
		os.Exit(1)
	}

	if err := acquireToken(authority, clientID, scope, redirectURI, responseType, listenPort); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func printUsage() {
	fmt.Printf(`OIDC Tool - Acquire id/access tokens using implicit flow

Usage:
  %s <command> [flags]

Commands:
  token      Acquire tokens
  help       Show this help

Token Flags:
  --authority string      OIDC authority URL
  --client-id string      OIDC client ID  
  --scope string          Requested scope
  --redirect-uri string   Redirect URI (default: http://localhost:5000/signin-oidc)
                          Non-localhost or https URIs are intercepted in a private Edge/Chrome window
  --response-type string  OIDC response_type (default: "id_token token")
  --listen-port int       Port to listen on (overrides port derived from redirect-uri;
                          random when intercepting)

Example:
  %s token --authority "https://demo.duendesoftware.com" --client-id "interactive.public" --scope "openid profile"
  %s token --authority "https://login.microsoftonline.com/<tenant>/v2.0" --client-id "<id>" --scope "openid profile" --redirect-uri "https://myapp.example.com/signin-oidc"
`, os.Args[0], os.Args[0], os.Args[0])
}
