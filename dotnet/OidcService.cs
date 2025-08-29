using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Web;

namespace OidcTool;

public class OidcService
{
    private readonly HttpClient _httpClient;
    private readonly TokenCache _tokenCache;

    public OidcService(HttpClient httpClient)
    {
        _httpClient = httpClient;
        _tokenCache = new TokenCache();
    }

    public async Task AcquireTokenAsync(string authority, string clientId, string scope, string redirectUri)
    {
        try
        {
            Console.WriteLine($"Starting OIDC token acquisition...");
            Console.WriteLine($"Authority: {authority}");
            Console.WriteLine($"Client ID: {clientId}");
            Console.WriteLine($"Scope: {scope}");
            Console.WriteLine($"Redirect URI: {redirectUri}");
            Console.WriteLine();

            // Check cache first
            var cachedToken = _tokenCache.GetToken(authority, clientId, scope);
            if (cachedToken != null)
            {
                Console.WriteLine("✅ Found valid cached token!");
                if (!string.IsNullOrEmpty(cachedToken.Oid))
                {
                    Console.WriteLine($"OID: {cachedToken.Oid}");
                }
                Console.WriteLine($"Access Token: {cachedToken.AccessToken}");
                Console.WriteLine($"Expires at: {cachedToken.ExpiresAt:yyyy-MM-dd HH:mm:ss} UTC");
                Console.WriteLine($"Token Type: {cachedToken.TokenType ?? "Bearer"}");
                Console.WriteLine();
                return;
            }

            Console.WriteLine("No valid cached token found. Starting interactive authentication...");
            Console.WriteLine();

            // Discover OIDC configuration
            var discoveryDocument = await GetDiscoveryDocumentAsync(authority);
            
            if (discoveryDocument?.AuthorizationEndpoint == null)
            {
                Console.WriteLine("Error: Could not retrieve authorization endpoint from discovery document");
                return;
            }

            Console.WriteLine($"Authorization Endpoint: {discoveryDocument.AuthorizationEndpoint}");
            Console.WriteLine();

            // Generate state parameter for security
            var state = Guid.NewGuid().ToString("N");
            
            // Build authorization URL
            var authUrl = BuildAuthorizationUrl(discoveryDocument.AuthorizationEndpoint, clientId, scope, state, redirectUri);
            
            Console.WriteLine("Opening browser for authentication...");
            Console.WriteLine($"Authorization URL: {authUrl}");
            Console.WriteLine();

            // Start local HTTP listener for callback
            var callbackListener = new HttpListener();
            
            // Parse redirect URI to get the correct prefix
            try
            {
                var uri = new Uri(redirectUri);
                var prefix = $"{uri.Scheme}://{uri.Host}:{uri.Port}/";
                callbackListener.Prefixes.Add(prefix);
            }
            catch
            {
                // Fallback to default
                callbackListener.Prefixes.Add("http://localhost:5000/");
            }
            
            callbackListener.Start();

            // Open browser
            Process.Start(new ProcessStartInfo
            {
                FileName = authUrl,
                UseShellExecute = true
            });

            Console.WriteLine("Waiting for callback...");
            Console.WriteLine("Please complete the authentication in your browser.");
            Console.WriteLine();

            // Wait for callback
            var context = await callbackListener.GetContextAsync();
            var request = context.Request;
            var response = context.Response;

            // Parse callback parameters
            System.Collections.Specialized.NameValueCollection? formParams = null;
            string? returnedState = null;
            string? accessToken = null;
            string? error = null;
            string? errorDescription = null;
            string? tokenType = null;
            string? expiresIn = null;

            if (request.HttpMethod == "POST" && request.HasEntityBody)
            {
                // Read form data from POST body
                using var reader = new StreamReader(request.InputStream, request.ContentEncoding);
                var formData = await reader.ReadToEndAsync();
                formParams = HttpUtility.ParseQueryString(formData);
                
                returnedState = formParams["state"];
                accessToken = formParams["access_token"];
                error = formParams["error"];
                errorDescription = formParams["error_description"];
                tokenType = formParams["token_type"];
                expiresIn = formParams["expires_in"];
            }
            else
            {
                // Fallback to query parameters for GET requests
                var queryParams = HttpUtility.ParseQueryString(request.Url?.Query ?? string.Empty);
                returnedState = queryParams["state"];
                accessToken = queryParams["access_token"];
                error = queryParams["error"];
                errorDescription = queryParams["error_description"];
                tokenType = queryParams["token_type"];
                expiresIn = queryParams["expires_in"];
            }

            // Send response to browser
            string responseString;
            if (!string.IsNullOrEmpty(error))
            {
                responseString = $"<html><body><h1>Error</h1><p>{error}: {errorDescription}</p></body></html>";
                response.StatusCode = 400;
            }
            else if (string.IsNullOrEmpty(accessToken))
            {
                responseString = "<html><body><h1>Error</h1><p>No access token received</p></body></html>";
                response.StatusCode = 400;
            }
            else if (returnedState != state)
            {
                responseString = "<html><body><h1>Error</h1><p>Invalid state parameter</p></body></html>";
                response.StatusCode = 400;
            }
            else
            {
                responseString = $"<html><body><h1>Success</h1><p>Access token received. You can close this window.</p><div style='width:100%'><code>{accessToken}</code></div></body></html>";
                response.StatusCode = 200;
            }

            byte[] buffer = Encoding.UTF8.GetBytes(responseString);
            response.ContentLength64 = buffer.Length;
            response.OutputStream.Write(buffer, 0, buffer.Length);
            response.OutputStream.Close();
            callbackListener.Stop();

            // Handle result
            if (!string.IsNullOrEmpty(error))
            {
                Console.WriteLine($"Error: {error}");
                if (!string.IsNullOrEmpty(errorDescription))
                {
                    Console.WriteLine($"Description: {errorDescription}");
                }
                return;
            }

            if (returnedState != state)
            {
                Console.WriteLine("Error: State parameter mismatch");
                return;
            }

            if (string.IsNullOrEmpty(accessToken))
            {
                Console.WriteLine("Error: No access token received");
                return;
            }

            Console.WriteLine("✅ Access token acquired successfully!");
            Console.WriteLine($"Access Token: {accessToken}");
            Console.WriteLine();

            // Cache the token
            var expiresInSeconds = int.TryParse(expiresIn, out var expiry) ? expiry : 3600; // Default 1 hour
            var tokenCacheEntry = new TokenCacheEntry
            {
                AccessToken = accessToken,
                Authority = authority,
                ClientId = clientId,
                Scope = scope,
                TokenType = tokenType ?? "Bearer",
                ExpiresAt = DateTime.UtcNow.AddSeconds(expiresInSeconds)
            };

            _tokenCache.SaveToken(tokenCacheEntry);
            Console.WriteLine($"🔄 Token cached successfully. Expires at: {tokenCacheEntry.ExpiresAt:yyyy-MM-dd HH:mm:ss} UTC");
            Console.WriteLine();

            // Optionally decode and display token info
            await DisplayTokenInfoAsync(accessToken, discoveryDocument);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    private async Task<DiscoveryDocument?> GetDiscoveryDocumentAsync(string authority)
    {
        try
        {
            var discoveryUrl = $"{authority.TrimEnd('/')}/.well-known/openid-configuration";
            Console.WriteLine($"Fetching discovery document from: {discoveryUrl}");
            
            var response = await _httpClient.GetAsync(discoveryUrl);
            response.EnsureSuccessStatusCode();
            
            var json = await response.Content.ReadAsStringAsync();
            var options = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
            };
            
            return JsonSerializer.Deserialize<DiscoveryDocument>(json, options);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error fetching discovery document: {ex.Message}");
            return null;
        }
    }

    private string BuildAuthorizationUrl(string authorizationEndpoint, string clientId, string scope, string state, string redirectUri)
    {
        var queryParams = new Dictionary<string, string>
        {
            ["response_type"] = "token",
            ["response_mode"] = "form_post",
            ["client_id"] = clientId,
            ["redirect_uri"] = redirectUri,
            ["scope"] = scope,
            ["state"] = state,
            ["nonce"] = Guid.NewGuid().ToString("N")
        };

        var query = string.Join("&", queryParams.Select(kvp => 
            $"{HttpUtility.UrlEncode(kvp.Key)}={HttpUtility.UrlEncode(kvp.Value)}"));

        return $"{authorizationEndpoint}?{query}";
    }

    private async Task DisplayTokenInfoAsync(string accessToken, DiscoveryDocument discoveryDocument)
    {
        try
        {
            Console.WriteLine("Token Information:");
            Console.WriteLine($"Length: {accessToken.Length} characters");
            
            // If there's a userinfo endpoint, try to get user information
            if (!string.IsNullOrEmpty(discoveryDocument.UserinfoEndpoint))
            {
                Console.WriteLine("Fetching user information...");
                
                var request = new HttpRequestMessage(HttpMethod.Get, discoveryDocument.UserinfoEndpoint);
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                
                var response = await _httpClient.SendAsync(request);
                if (response.IsSuccessStatusCode)
                {
                    var userInfoJson = await response.Content.ReadAsStringAsync();
                    var userInfo = JsonSerializer.Deserialize<JsonElement>(userInfoJson);
                    
                    Console.WriteLine("User Information:");
                    Console.WriteLine(JsonSerializer.Serialize(userInfo, new JsonSerializerOptions { WriteIndented = true }));
                }
                else
                {
                    Console.WriteLine($"Could not fetch user info: {response.StatusCode}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error displaying token info: {ex.Message}");
        }
    }

    public void DisplayCacheInfo()
    {
        _tokenCache.DisplayCacheInfo();
    }

    public void ClearCache()
    {
        _tokenCache.ClearCache();
        Console.WriteLine("Token cache cleared successfully.");
    }

    public void RemoveTokenFromCache(string authority, string clientId, string scope)
    {
        _tokenCache.RemoveToken(authority, clientId, scope);
        Console.WriteLine("Token removed from cache.");
    }
}

public class DiscoveryDocument
{
    public string? AuthorizationEndpoint { get; set; }
    public string? TokenEndpoint { get; set; }
    public string? UserinfoEndpoint { get; set; }
    public string? JwksUri { get; set; }
    public string? Issuer { get; set; }
}
