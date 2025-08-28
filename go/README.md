# OIDC Tool - Go Implementation

A Go application that can acquire access tokens using OIDC implicit flow with automatic token caching.

## Features

- Supports OIDC implicit flow for token acquisition
- **Smart OID-based token caching** - tokens are cached using the user's OID (Object Identifier) from the JWT token
- **Automatic token caching** - tokens are cached locally and reused until expiration
- **Smart expiration handling** - automatically acquires new tokens when cached ones expire
- Automatically discovers OIDC configuration from authority
- Opens browser for user authentication
- Handles callback with local HTTP listener
- Displays token information and user details (if available)
- Command-line interface with cache management commands
- Secure local storage in user's home directory
- **Cross-platform** - works on Windows, macOS, and Linux

## Token Caching Behavior

The application uses the `oid` (Object Identifier) claim from JWT tokens as the cache key. This means:

- **User-specific caching**: Each user's tokens are cached separately based on their unique OID
- **Cross-application sharing**: Tokens can be shared between different client applications for the same user
- **Automatic fallback**: If no OID is found in the token, falls back to authority:clientId:scope as the cache key
- **Secure isolation**: Different users' tokens are automatically isolated

## Prerequisites

- Go 1.21 or higher
- A web browser
- Network access to the OIDC authority

## Installation

### Option 1: Build from source

```bash
# Clone or download the source code
# cd to the go-oidc-tool directory

# Build the application (no external dependencies needed)
go build -o oidc-tool

# Run the application
./oidc-tool --help
```

### Option 2: Run directly

```bash
# Run directly without building (no external dependencies needed)
go run . --help
```

## Usage

### Acquire Token (with automatic caching)
```bash
./oidc-tool token --authority <OIDC_AUTHORITY_URL> --client-id <CLIENT_ID> --scope <SCOPE>
```

### Cache Management Commands

#### View cache information
```bash
./oidc-tool cache-info
```

#### Clear all cached tokens
```bash
./oidc-tool clear-cache
```

#### Remove specific token from cache
```bash
./oidc-tool remove-token --authority <AUTHORITY> --client-id <CLIENT_ID> --scope <SCOPE>
```

### Backward Compatibility
The tool still supports the old syntax for direct token acquisition:
```bash
./oidc-tool --authority <AUTHORITY> --client-id <CLIENT_ID> --scope <SCOPE>
```

### Parameters

- `--authority`: The OIDC authority URL (e.g., `https://login.microsoftonline.com/common/v2.0`)
- `--client-id`: The OIDC client ID registered with the authority
- `--scope`: The requested scope (e.g., `openid profile email`)

### Example

```bash
./oidc-tool token --authority "https://demo.duendesoftware.com" --client-id "interactive.public" --scope "openid profile email api"
```

## How it works

1. **Discovery**: Fetches the OIDC configuration from the authority's `.well-known/openid_configuration` endpoint
2. **Authorization**: Builds an authorization URL with the implicit flow parameters
3. **Authentication**: Opens the user's default browser to the authorization URL
4. **Callback**: Starts a local HTTP listener on `http://localhost:5000/signin-oidc` to receive the token
5. **Token Extraction**: Parses the access token from the callback form data (POST) or URL parameters (GET)
6. **User Info**: Optionally fetches user information using the acquired token

## Security Features

- State parameter validation to prevent CSRF attacks
- Nonce parameter for additional security
- Local callback handling to keep tokens secure
- OID-based caching for user isolation
- Secure file permissions for cache storage (0600)

## Cache Location

Tokens are cached in:
- **Windows**: `%USERPROFILE%\.oidc-tool\token_cache.json`
- **macOS/Linux**: `~/.oidc-tool/token_cache.json`

## Cross-Platform Support

The application automatically detects the operating system and uses the appropriate method to open the browser:
- **Windows**: `rundll32 url.dll,FileProtocolHandler`
- **macOS**: `open`
- **Linux/Unix**: `xdg-open`

## Build Options

### Build for current platform
```bash
go build -o oidc-tool
```

### Build for specific platforms
```bash
# Windows
GOOS=windows GOARCH=amd64 go build -o oidc-tool.exe

# macOS
GOOS=darwin GOARCH=amd64 go build -o oidc-tool-macos

# Linux
GOOS=linux GOARCH=amd64 go build -o oidc-tool-linux
```

### Build optimized binary
```bash
go build -ldflags="-s -w" -o oidc-tool
```

## Dependencies

The application uses **no external dependencies** - only Go's standard library:
- `flag` - Command-line flag parsing
- `net/http` - HTTP client and server
- `encoding/json` - JSON parsing
- `crypto/rand` - Secure random generation
- `os/exec` - Browser launching
- `time` - Time handling

## Notes

- This tool is designed for development and testing purposes
- The implicit flow is being deprecated in favor of Authorization Code flow with PKCE
- Make sure your OIDC client is configured to allow `http://localhost:5000/signin-oidc` as a redirect URI
- The tool requires firewall permissions to start the local HTTP listener

## Error Handling

The application includes comprehensive error handling for:
- Network connectivity issues
- Invalid OIDC configurations
- Authentication failures
- Token parsing errors
- Cache corruption
- Browser launching failures

## Performance

Go's compiled nature provides excellent performance characteristics:
- **Fast startup**: Sub-second startup times
- **Low memory usage**: Minimal runtime overhead
- **Efficient HTTP handling**: Built-in HTTP client and server
- **Small binary size**: Single executable with all dependencies

## Development

### Running tests
```bash
go test ./...
```

### Code formatting
```bash
go fmt ./...
```

### Static analysis
```bash
go vet ./...
```
