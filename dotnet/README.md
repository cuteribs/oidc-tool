# OIDC Tool

A .NET 8 console application that can acquire access tokens using OIDC implicit flow with automatic token caching.

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
- Secure local storage in user's AppData folder

## Token Caching Behavior

The application now uses the `oid` (Object Identifier) claim from JWT tokens as the cache key. This means:

- **User-specific caching**: Each user's tokens are cached separately based on their unique OID
- **Cross-application sharing**: Tokens can be shared between different client applications for the same user
- **Automatic fallback**: If no OID is found in the token, falls back to authority:clientId:scope as the cache key
- **Secure isolation**: Different users' tokens are automatically isolated

## Prerequisites

- .NET 8 SDK
- A web browser
- Network access to the OIDC authority

## Usage

### Acquire Token (with automatic caching)
```bash
dotnet run -- token --authority <OIDC_AUTHORITY_URL> --client-id <CLIENT_ID> --scope <SCOPE>
```

### Cache Management Commands

#### View cache information
```bash
dotnet run -- cache-info
```

#### Clear all cached tokens
```bash
dotnet run -- clear-cache
```

#### Remove specific token from cache
```bash
dotnet run -- remove-token --authority <AUTHORITY> --client-id <CLIENT_ID> --scope <SCOPE>
```

### Backward Compatibility
The tool still supports the old syntax for direct token acquisition:
```bash
dotnet run -- --authority <AUTHORITY> --client-id <CLIENT_ID> --scope <SCOPE>
```

### Parameters

- `--authority`: The OIDC authority URL (e.g., `https://login.microsoftonline.com/common/v2.0`)
- `--client-id`: The OIDC client ID registered with the authority
- `--scope`: The requested scope (e.g., `openid profile email`)

### Example

```bash
dotnet run -- --authority "https://demo.duendesoftware.com" --client-id "interactive.public" --scope "openid profile email api"
```

## How it works

1. **Discovery**: Fetches the OIDC configuration from the authority's `.well-known/openid_configuration` endpoint
2. **Authorization**: Builds an authorization URL with the implicit flow parameters
3. **Authentication**: Opens the user's default browser to the authorization URL
4. **Callback**: Starts a local HTTP listener on `http://localhost:8080/callback` to receive the token
5. **Token Extraction**: Parses the access token from the callback URL fragment
6. **User Info**: Optionally fetches user information using the acquired token

## Security Features

- State parameter validation to prevent CSRF attacks
- Nonce parameter for additional security
- Local callback handling to keep tokens secure

## Build

```bash
dotnet build
```

## Publish

```bash
dotnet publish -c Release -o ./publish
```

## Notes

- This tool is designed for development and testing purposes
- The implicit flow is being deprecated in favor of Authorization Code flow with PKCE
- Make sure your OIDC client is configured to allow `http://localhost:8080/callback` as a redirect URI
- The tool requires firewall permissions to start the local HTTP listener
