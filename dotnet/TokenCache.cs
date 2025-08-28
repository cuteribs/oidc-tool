using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text;

namespace OidcTool;

public class TokenCacheEntry
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;
    
    [JsonPropertyName("expires_at")]
    public DateTime ExpiresAt { get; set; }
    
    [JsonPropertyName("authority")]
    public string Authority { get; set; } = string.Empty;
    
    [JsonPropertyName("client_id")]
    public string ClientId { get; set; } = string.Empty;
    
    [JsonPropertyName("scope")]
    public string Scope { get; set; } = string.Empty;
    
    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }
    
    [JsonPropertyName("token_type")]
    public string? TokenType { get; set; }
    
    [JsonPropertyName("oid")]
    public string? Oid { get; set; }

    public bool IsExpired => DateTime.UtcNow >= ExpiresAt.AddMinutes(-5); // 5 minute buffer

    public string GetCacheKey() => !string.IsNullOrEmpty(Oid) ? Oid : $"{Authority}:{ClientId}:{Scope}".ToLowerInvariant();
}

public class TokenCache
{
    private readonly string _cacheFilePath;
    private Dictionary<string, TokenCacheEntry> _cache = new();

    public TokenCache()
    {
        // Use same cache directory as Go/Python versions for compatibility
        var homeDir = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var cacheDir = Path.Combine(homeDir, ".oidc-tool");
        Directory.CreateDirectory(cacheDir);
        _cacheFilePath = Path.Combine(cacheDir, "token_cache.json");
        LoadCache();
    }

    public TokenCacheEntry? GetToken(string authority, string clientId, string scope)
    {
        // First, try to find by oid if we have any cached tokens
        foreach (var entry in _cache.Values)
        {
            if (!entry.IsExpired && 
                entry.Authority.Equals(authority, StringComparison.OrdinalIgnoreCase) &&
                entry.ClientId.Equals(clientId, StringComparison.OrdinalIgnoreCase) &&
                entry.Scope.Equals(scope, StringComparison.OrdinalIgnoreCase))
            {
                return entry;
            }
        }

        // Clean up expired tokens
        var expiredKeys = _cache.Where(kvp => kvp.Value.IsExpired).Select(kvp => kvp.Key).ToList();
        foreach (var expiredKey in expiredKeys)
        {
            _cache.Remove(expiredKey);
        }
        
        if (expiredKeys.Any())
        {
            SaveCache();
        }
        
        return null;
    }

    public TokenCacheEntry? GetTokenByOid(string oid)
    {
        if (_cache.TryGetValue(oid, out var entry))
        {
            if (!entry.IsExpired)
            {
                return entry;
            }
            else
            {
                // Remove expired token
                _cache.Remove(oid);
                SaveCache();
            }
        }
        
        return null;
    }

    public void SaveToken(TokenCacheEntry entry)
    {
        // Extract OID from the access token
        var oid = ExtractOidFromToken(entry.AccessToken);
        if (!string.IsNullOrEmpty(oid))
        {
            entry.Oid = oid;
            _cache[oid] = entry;
            Console.WriteLine($"Token cached with OID: {oid}");
        }
        else
        {
            // Fallback to old key format if OID is not available
            var fallbackKey = entry.GetCacheKey();
            _cache[fallbackKey] = entry;
            Console.WriteLine($"Token cached with fallback key (no OID found): {fallbackKey}");
        }
        
        SaveCache();
    }

    public void RemoveToken(string authority, string clientId, string scope)
    {
        var key = new TokenCacheEntry { Authority = authority, ClientId = clientId, Scope = scope }.GetCacheKey();
        if (_cache.Remove(key))
        {
            SaveCache();
        }
    }

    public void ClearCache()
    {
        _cache.Clear();
        SaveCache();
    }

    private void LoadCache()
    {
        try
        {
            if (File.Exists(_cacheFilePath))
            {
                var json = File.ReadAllText(_cacheFilePath);
                var entries = JsonSerializer.Deserialize<List<TokenCacheEntry>>(json) ?? new List<TokenCacheEntry>();
                
                _cache = entries
                    .Where(e => !e.IsExpired)
                    .ToDictionary(e => e.GetCacheKey(), e => e);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Warning: Could not load token cache: {ex.Message}");
            _cache = new Dictionary<string, TokenCacheEntry>();
        }
    }

    private void SaveCache()
    {
        try
        {
            var entries = _cache.Values.ToList();
            var json = JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_cacheFilePath, json);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Warning: Could not save token cache: {ex.Message}");
        }
    }

    public void DisplayCacheInfo()
    {
        Console.WriteLine($"Cache location: {_cacheFilePath}");
        Console.WriteLine($"Cached tokens: {_cache.Count}");
        
        if (_cache.Any())
        {
            Console.WriteLine("\nCached entries:");
            foreach (var entry in _cache.Values)
            {
                var status = entry.IsExpired ? "EXPIRED" : $"Valid until {entry.ExpiresAt:yyyy-MM-dd HH:mm:ss} UTC";
                var oidInfo = !string.IsNullOrEmpty(entry.Oid) ? $" | OID: {entry.Oid}" : "";
                Console.WriteLine($"  {entry.Authority} | {entry.ClientId} | {entry.Scope}{oidInfo} - {status}");
            }
        }
    }

    public static string? ExtractOidFromToken(string accessToken)
    {
        return JwtTokenHelper.ExtractClaim(accessToken, "oid");
    }
}

public static class JwtTokenHelper
{
    public static string? ExtractClaim(string jwtToken, string claimName)
    {
        try
        {
            // JWT tokens have three parts separated by dots: header.payload.signature
            var parts = jwtToken.Split('.');
            if (parts.Length != 3)
                return null;

            // Decode the payload (second part)
            var payload = parts[1];
            
            // Add padding if necessary for base64 decoding
            while (payload.Length % 4 != 0)
            {
                payload += "=";
            }

            // Decode from base64url to bytes
            var payloadBytes = Convert.FromBase64String(payload.Replace('-', '+').Replace('_', '/'));
            var payloadJson = Encoding.UTF8.GetString(payloadBytes);

            // Parse JSON and extract the claim
            var jsonDocument = JsonDocument.Parse(payloadJson);
            if (jsonDocument.RootElement.TryGetProperty(claimName, out var claimElement))
            {
                return claimElement.GetString();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Warning: Could not extract '{claimName}' from token: {ex.Message}");
        }

        return null;
    }
}
