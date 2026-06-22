using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.CommandLine;

namespace OidcTool;

class Program
{
	static async Task<int> Main(string[] args)
	{
		var authorityOption = new Option<string>("--authority")
		{
			Description = "The OIDC authority URL",
			Required = true
		};

		var clientIdOption = new Option<string>("--client-id")
		{
			Description = "The OIDC client ID",
			Required = true
		};

		var scopeOption = new Option<string>("--scope")
		{
			Description = "The requested scope",
			Required = true
		};

		var redirectUriOption = new Option<string>("--redirect-uri")
		{
			Description = "The OIDC redirect URI",
			DefaultValueFactory = _ => "http://localhost:5000/signin-oidc",
		};

		var listenPortOption = new Option<int>("--listen-port")
		{
			Description = "Port to listen on (overrides port derived from redirect-uri)",
			DefaultValueFactory = _ => 0
		};

		// Main token command
		var tokenCommand = new Command("token", "Acquire an access token")
		{
			authorityOption,
			clientIdOption,
			scopeOption,
			redirectUriOption,
			listenPortOption
		};

		tokenCommand.SetAction(x =>
		//async (authority, clientId, scope, redirectUri, listenPort) =>
		{
			var authority = x.GetValue(authorityOption)!;
			var clientId = x.GetValue(clientIdOption)!;
			var scope = x.GetValue(scopeOption)!;
			var redirectUri = x.GetValue(redirectUriOption)!;
			var listenPort = x.GetValue(listenPortOption);
			var host = CreateHost();
			var oidcService = host.Services.GetRequiredService<OidcService>();
			return oidcService.AcquireTokenAsync(authority, clientId, scope, redirectUri, listenPort);
		});

		// Cache info command
		var cacheInfoCommand = new Command("cache-info", "Display information about the token cache");
		cacheInfoCommand.SetAction(_ =>
		{
			var host = CreateHost();
			var oidcService = host.Services.GetRequiredService<OidcService>();
			oidcService.DisplayCacheInfo();
		});

		// Clear cache command
		var clearCacheCommand = new Command("clear-cache", "Clear all cached tokens");
		clearCacheCommand.SetAction(_ =>
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
			scopeOption,
			redirectUriOption
		};
		removeTokenCommand.SetAction(x =>
		{
			var authority = x.GetValue(authorityOption)!;
			var clientId = x.GetValue(clientIdOption)!;
			var scope = x.GetValue(scopeOption)!;
			var host = CreateHost();
			var oidcService = host.Services.GetRequiredService<OidcService>();
			oidcService.RemoveTokenFromCache(authority, clientId, scope);
		});

		var rootCommand = new RootCommand("OIDC Tool - Acquire access tokens using implicit flow with caching")
		{
			tokenCommand,
			cacheInfoCommand,
			clearCacheCommand,
			removeTokenCommand,
			authorityOption,
			clientIdOption,
			scopeOption,
			redirectUriOption,
			listenPortOption
		};
		rootCommand.SetAction(async x =>
		{
			var authority = x.GetValue(authorityOption);
			var clientId = x.GetValue(clientIdOption);
			var scope = x.GetValue(scopeOption)!;

			if (!string.IsNullOrEmpty(authority) && !string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(scope))
			{
				var redirectUri = x.GetValue(redirectUriOption)!;
				var listenPort = x.GetValue(listenPortOption);
				var host = CreateHost();
				var oidcService = host.Services.GetRequiredService<OidcService>();
				await oidcService.AcquireTokenAsync(authority, clientId, scope, redirectUri, listenPort);
			}
			else
			{
				Console.WriteLine("Use 'oidc-tool --help' to see available commands.");
			}
		});

		var result = rootCommand.Parse(args);
		return await result.InvokeAsync();
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
