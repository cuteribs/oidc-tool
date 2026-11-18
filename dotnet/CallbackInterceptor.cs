using System.Collections.Specialized;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;

namespace OidcTool;

/// <summary>
/// Captures a callback for a non-localhost redirect URI by launching a private Edge/Chrome instance that
/// maps the redirect host to a local listener and trusts a throwaway certificate. No hosts file or cert store changes.
/// </summary>
public static class CallbackInterceptor
{
    public static async Task<NameValueCollection> RunAsync(Uri redirect, int listenPort, string authUrl, Func<NameValueCollection, (int Status, string Html)> respond)
    {
        var browser = FindBrowser() ?? throw new InvalidOperationException($"Intercepting {redirect.Host} requires Edge or Chrome, none found");

        var listener = new TcpListener(IPAddress.Loopback, listenPort);
        listener.Start();
        var local = (IPEndPoint)listener.LocalEndpoint;
        var dir = Directory.CreateTempSubdirectory("oidc-tool-").FullName;

        // --user-data-dir also forces a separate browser instance, which the flags below need.
        var psi = new ProcessStartInfo(browser) { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in new[]
        {
            $"--user-data-dir={dir}",
            $"--host-resolver-rules=MAP {redirect.Host}:{redirect.Port} {local}",
            "--no-proxy-server", // a proxy would resolve the host itself and bypass the MAP rule
            "--no-first-run",
            "--no-default-browser-check",
        })
        {
            psi.ArgumentList.Add(arg);
        }

        X509Certificate2? cert = null;
        if (redirect.Scheme == Uri.UriSchemeHttps)
        {
            cert = CreateCertificate(redirect.Host);
            // Trusts only this throwaway key, only in this browser instance.
            var spki = Convert.ToBase64String(SHA256.HashData(cert.PublicKey.ExportSubjectPublicKeyInfo()));
            psi.ArgumentList.Add($"--ignore-certificate-errors-spki-list={spki}");
        }
        psi.ArgumentList.Add(authUrl);

        var result = new TaskCompletionSource<NameValueCollection>(TaskCreationOptions.RunContinuationsAsynchronously);
        _ = AcceptLoopAsync(listener, cert, redirect.AbsolutePath, respond, result);

        Console.WriteLine($"Intercepting {redirect.Scheme}://{redirect.Host}:{redirect.Port} -> {local}");
        Console.WriteLine($"Opening {Path.GetFileName(browser)}...");
        using var process = Process.Start(psi)!;
        // Drain browser logging so it neither clutters the console nor blocks on a full pipe.
        process.OutputDataReceived += (_, _) => { };
        process.ErrorDataReceived += (_, _) => { };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        try
        {
            return await result.Task;
        }
        finally
        {
            listener.Stop();
            try { process.Kill(entireProcessTree: true); } catch { }
            process.WaitForExit(5000);
            // Browser child processes may hold profile files briefly after the main process exits.
            for (var i = 0; i < 20; i++)
            {
                try { Directory.Delete(dir, true); break; } catch { await Task.Delay(250); }
            }
            cert?.Dispose();
        }
    }

    private static async Task AcceptLoopAsync(TcpListener listener, X509Certificate2? cert, string path,
        Func<NameValueCollection, (int Status, string Html)> respond, TaskCompletionSource<NameValueCollection> result)
    {
        while (!result.Task.IsCompleted)
        {
            TcpClient client;
            try { client = await listener.AcceptTcpClientAsync(); }
            catch { return; } // listener stopped
            _ = HandleAsync(client, cert, path, respond, result);
        }
    }

    private static async Task HandleAsync(TcpClient client, X509Certificate2? cert, string path,
        Func<NameValueCollection, (int Status, string Html)> respond, TaskCompletionSource<NameValueCollection> result)
    {
        using var _ = client;
        try
        {
            Stream stream = client.GetStream();
            if (cert != null)
            {
                var ssl = new SslStream(stream);
                await ssl.AuthenticateAsServerAsync(cert);
                stream = ssl;
            }
            await using (stream)
            {
                // ponytail: minimal HTTP/1.1 parsing; form_post bodies are ASCII url-encoded, so chars == bytes.
                using var reader = new StreamReader(stream, Encoding.ASCII, false, 8192, leaveOpen: true);
                var requestLine = (await reader.ReadLineAsync())?.Split(' ');
                if (requestLine is not { Length: 3 })
                    return;
                var contentLength = 0;
                for (var line = await reader.ReadLineAsync(); !string.IsNullOrEmpty(line); line = await reader.ReadLineAsync())
                {
                    if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                        contentLength = int.Parse(line["Content-Length:".Length..].Trim());
                }

                var target = requestLine[1];
                var query = target.Contains('?') ? target[target.IndexOf('?')..] : "";
                if (target[..(target.Length - query.Length)] != path)
                {
                    await WriteAsync(stream, 404, "");
                    return;
                }

                var body = new char[contentLength];
                await reader.ReadBlockAsync(body);
                var p = HttpUtility.ParseQueryString(requestLine[0] == "POST" ? new string(body) : query);
                var (status, html) = respond(p);
                await WriteAsync(stream, status, html);
                result.TrySetResult(p);
            }
        }
        catch
        {
            // Speculative/aborted browser connections; the real callback arrives on another one.
        }
    }

    private static async Task WriteAsync(Stream stream, int status, string html)
    {
        var body = Encoding.UTF8.GetBytes(html);
        var head = Encoding.ASCII.GetBytes($"HTTP/1.1 {status} {(status == 200 ? "OK" : "Error")}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(head);
        await stream.WriteAsync(body);
        await stream.FlushAsync();
    }

    private static X509Certificate2 CreateCertificate(string host)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(host);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        using var ephemeral = request.CreateSelfSigned(DateTimeOffset.Now.AddMinutes(-5), DateTimeOffset.Now.AddDays(1));
        // SChannel on Windows can't use ephemeral keys; round-trip through PFX.
        return X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pfx), null);
    }

    private static string? FindBrowser()
    {
        string[] candidates;
        if (OperatingSystem.IsWindows())
        {
            candidates = (from rel in new[] { @"Microsoft\Edge\Application\msedge.exe", @"Google\Chrome\Application\chrome.exe" }
                          from env in new[] { "ProgramFiles(x86)", "ProgramFiles", "LocalAppData" }
                          let baseDir = Environment.GetEnvironmentVariable(env)
                          where !string.IsNullOrEmpty(baseDir)
                          select Path.Combine(baseDir, rel)).ToArray();
        }
        else if (OperatingSystem.IsMacOS())
        {
            candidates = ["/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"];
        }
        else
        {
            var path = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator);
            candidates = (from name in new[] { "microsoft-edge", "google-chrome", "chromium", "chromium-browser" }
                          from dir in path
                          select Path.Combine(dir, name)).ToArray();
        }
        return candidates.FirstOrDefault(File.Exists);
    }
}
