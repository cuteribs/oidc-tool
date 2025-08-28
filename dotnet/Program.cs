using System.CommandLine;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace OidcTool;

class Program
{
    static async Task<int> Main(string[] args)
    {
        var authorityOption = new Option<string>(
            name: "--authority",
            description: "The OIDC authority URL")
        {
            IsRequired = true
        };

        var clientIdOption = new Option<string>(
            name: "--client-id",
            description: "The OIDC client ID")
        {
            IsRequired = true
        };

        var scopeOption = new Option<string>(
            name: "--scope",
            description: "The requested scope")
        {
            IsRequired = true
        };

        // Main token command
        var tokenCommand = new Command("token", "Acquire an access token")
        {
            authorityOption,
            clientIdOption,
            scopeOption
        };

        tokenCommand.SetHandler(async (authority, clientId, scope) =>
        {
            var host = CreateHost();
            var oidcService = host.Services.GetRequiredService<OidcService>();
            await oidcService.AcquireTokenAsync(authority, clientId, scope);
        }, authorityOption, clientIdOption, scopeOption);

        // Cache info command
        var cacheInfoCommand = new Command("cache-info", "Display information about the token cache");
        cacheInfoCommand.SetHandler(() =>
        {
            var host = CreateHost();
            var oidcService = host.Services.GetRequiredService<OidcService>();
            oidcService.DisplayCacheInfo();
        });

        // Clear cache command
        var clearCacheCommand = new Command("clear-cache", "Clear all cached tokens");
        clearCacheCommand.SetHandler(() =>
        {
            var host = CreateHost();
            var oidcService = host.Services.GetRequiredService<OidcService>();
            oidcService.ClearCache();
        });

        // Remove specific token command
        var removeTokenCommand = new Command("remove-token", "Remove a specific token from cache")
        {
            authorityOption,
            clientIdOption,
            scopeOption
        };

        removeTokenCommand.SetHandler((authority, clientId, scope) =>
        {
            var host = CreateHost();
            var oidcService = host.Services.GetRequiredService<OidcService>();
            oidcService.RemoveTokenFromCache(authority, clientId, scope);
        }, authorityOption, clientIdOption, scopeOption);

        var rootCommand = new RootCommand("OIDC Tool - Acquire access tokens using implicit flow with caching")
        {
            tokenCommand,
            cacheInfoCommand,
            clearCacheCommand,
            removeTokenCommand
        };

        // For backward compatibility, if no subcommand is provided, default to token acquisition
        rootCommand.SetHandler(async (authority, clientId, scope) =>
        {
            if (!string.IsNullOrEmpty(authority) && !string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(scope))
            {
                var host = CreateHost();
                var oidcService = host.Services.GetRequiredService<OidcService>();
                await oidcService.AcquireTokenAsync(authority, clientId, scope);
            }
            else
            {
                Console.WriteLine("Use 'oidc-tool --help' to see available commands.");
            }
        }, authorityOption, clientIdOption, scopeOption);

        return await rootCommand.InvokeAsync(args);
    }

    private static IHost CreateHost()
    {
        return Host.CreateDefaultBuilder()
            .ConfigureServices(services =>
            {
                services.AddHttpClient();
                services.AddSingleton<OidcService>();
            })
            .Build();
    }
}
