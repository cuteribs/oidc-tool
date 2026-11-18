using System.Collections.Specialized;
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

    public async Task AcquireTokenAsync(string authority, string clientId, string scope, string redirectUri, int listenPort = 0, string responseType = "id_token token")
    {
        try
        {
            Console.WriteLine($"Starting OIDC token acquisition...");
            Console.WriteLine($"Authority: {authority}");
            Console.WriteLine($"Client ID: {clientId}");
            Console.WriteLine($"Scope: {scope}");
            Console.WriteLine($"Redirect URI: {redirectUri}");
            if (listenPort > 0)
            {
                Console.WriteLine($"Listen Port: {listenPort}");
            }
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

            // Generate state and nonce parameters for security
            var state = Guid.NewGuid().ToString("N");
            var nonce = Guid.NewGuid().ToString("N");

            // Build authorization URL
            var authUrl = BuildAuthorizationUrl(discoveryDocument.AuthorizationEndpoint, clientId, scope, responseType, state, nonce, redirectUri);

            Console.WriteLine($"Authorization URL: {authUrl}");
            Console.WriteLine();

            (int, string) Respond(NameValueCollection p) => ValidateCallback(p, state, nonce) is { } err
                ? (400, $"<html><body><h1>Error</h1><p>{WebUtility.HtmlEncode(err)}</p></body></html>")
                : (200, $"<html><body><h1>Success</h1><p>Token received. You can close this window.</p><div style='width:100%'><code>{WebUtility.HtmlEncode(p["access_token"] ?? p["id_token"])}</code></div></body></html>");

            // http://localhost uses the default browser; anything else is intercepted in a private Edge/Chrome instance
            var uri = new Uri(redirectUri);
            var callback = uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback
                ? await ListenLocalAsync(uri, listenPort, authUrl, Respond)
                : await CallbackInterceptor.RunAsync(uri, listenPort, authUrl, Respond);

            if (ValidateCallback(callback, state, nonce) is { } error)
            {
                Console.WriteLine($"Error: {error}");
                return;
            }

            var idToken = callback["id_token"];
            var accessToken = callback["access_token"];

            Console.WriteLine("✅ Token(s) acquired successfully!");
            PrintToken("ID Token", idToken);
            PrintToken("Access Token", accessToken);
            Console.WriteLine();

            if (string.IsNullOrEmpty(accessToken))
            {
                return;
            }

            // Cache the token
            var expiresInSeconds = int.TryParse(callback["expires_in"], out var expiry) ? expiry : 3600; // Default 1 hour
            var tokenCacheEntry = new TokenCacheEntry
            {
                AccessToken = accessToken,
                Authority = authority,
                ClientId = clientId,
                Scope = scope,
                TokenType = callback["token_type"] ?? "Bearer",
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

    private string BuildAuthorizationUrl(string authorizationEndpoint, string clientId, string scope, string responseType, string state, string nonce, string redirectUri)
    {
        var queryParams = new Dictionary<string, string>
        {
            ["response_type"] = responseType,
            ["response_mode"] = "form_post",
            ["client_id"] = clientId,
            ["redirect_uri"] = redirectUri,
            ["scope"] = scope,
            ["state"] = state,
            ["nonce"] = nonce
        };

        var query = string.Join("&", queryParams.Select(kvp => 
            $"{HttpUtility.UrlEncode(kvp.Key)}={HttpUtility.UrlEncode(kvp.Value)}"));

        return $"{authorizationEndpoint}?{query}";
    }

    private static string? ValidateCallback(NameValueCollection p, string state, string nonce)
    {
        if (!string.IsNullOrEmpty(p["error"]))
            return string.IsNullOrEmpty(p["error_description"]) ? p["error"] : $"{p["error"]}: {p["error_description"]}";
        if (p["state"] != state)
            return "State parameter mismatch";
        if (string.IsNullOrEmpty(p["id_token"]) && string.IsNullOrEmpty(p["access_token"]))
            return "No token received";
        if (!string.IsNullOrEmpty(p["id_token"]) && JwtTokenHelper.ExtractClaim(p["id_token"]!, "nonce") != nonce)
            return "Nonce mismatch";
        return null;
    }

    private static void PrintToken(string label, string? token)
    {
        if (string.IsNullOrEmpty(token))
            return;
        Console.WriteLine();
        Console.WriteLine($"{label}: {token}");
        // Opaque (non-JWT) access tokens are printed as-is.
        if (JwtTokenHelper.DecodePayload(token) is { } claims)
            Console.WriteLine($"{label} claims:\n{JsonSerializer.Serialize(claims, new JsonSerializerOptions { WriteIndented = true })}");
    }

    private static async Task<NameValueCollection> ListenLocalAsync(Uri uri, int listenPort, string authUrl, Func<NameValueCollection, (int Status, string Html)> respond)
    {
        using var listener = new HttpListener();
        listener.Prefixes.Add($"{uri.Scheme}://{uri.Host}:{(listenPort > 0 ? listenPort : uri.Port)}/");
        listener.Start();

        Console.WriteLine("Opening browser for authentication...");
        Process.Start(new ProcessStartInfo { FileName = authUrl, UseShellExecute = true });
        Console.WriteLine("Waiting for callback...");
        Console.WriteLine("Please complete the authentication in your browser.");
        Console.WriteLine();

        var context = await listener.GetContextAsync();
        var request = context.Request;
        NameValueCollection p;
        if (request.HttpMethod == "POST" && request.HasEntityBody)
        {
            using var reader = new StreamReader(request.InputStream, request.ContentEncoding);
            p = HttpUtility.ParseQueryString(await reader.ReadToEndAsync());
        }
        else
        {
            p = HttpUtility.ParseQueryString(request.Url?.Query ?? string.Empty);
        }

        var (status, html) = respond(p);
        var buffer = Encoding.UTF8.GetBytes(html);
        context.Response.StatusCode = status;
        context.Response.ContentLength64 = buffer.Length;
        context.Response.OutputStream.Write(buffer, 0, buffer.Length);
        context.Response.OutputStream.Close();
        return p;
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
