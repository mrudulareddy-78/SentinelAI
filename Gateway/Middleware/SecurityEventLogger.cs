// File: Gateway/Middleware/SecurityEventLogger.cs
using System.Globalization;
using System.Text;

namespace Sentinel.Gateway.Middleware;

public static class SecurityEventLogger
{
    private static readonly SemaphoreSlim WriteLock = new(1, 1);
    private static readonly string[] HeaderColumns =
    {
        "timestamp",
        "src_ip",
        "path",
        "threat_type",
        "severity",
        "reason",
        "decision"
    };

    private static string? _securityLogPath;

    public static void Initialize(IWebHostEnvironment environment)
    {
        _securityLogPath = Path.GetFullPath(Path.Combine(environment.ContentRootPath, "..", "Shared", "logs", "security_events.csv"));
        Directory.CreateDirectory(Path.GetDirectoryName(_securityLogPath)!);
        EnsureLogFileExists();
    }

    public static async Task LogAsync(HttpContext context, string threatType, string severity, string reason, string decision = "allow")
    {
        if (string.IsNullOrWhiteSpace(_securityLogPath))
        {
            return;
        }

        var csvLine = string.Join(",", new[]
        {
            CsvEscape(DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture)),
            CsvEscape(context.Connection.RemoteIpAddress?.ToString() ?? "unknown"),
            CsvEscape(context.Request.Path + context.Request.QueryString),
            CsvEscape(threatType),
            CsvEscape(severity),
            CsvEscape(reason),
            CsvEscape(decision)
        });

        await WriteLock.WaitAsync().ConfigureAwait(false);
        try
        {
            await File.AppendAllTextAsync(_securityLogPath!, csvLine + Environment.NewLine, Encoding.UTF8).ConfigureAwait(false);
        }
        finally
        {
            WriteLock.Release();
        }
    }

    private static void EnsureLogFileExists()
    {
        if (string.IsNullOrWhiteSpace(_securityLogPath))
        {
            return;
        }

        if (!File.Exists(_securityLogPath) || new FileInfo(_securityLogPath).Length == 0)
        {
            File.WriteAllText(_securityLogPath, string.Join(",", HeaderColumns) + Environment.NewLine, Encoding.UTF8);
        }
    }

    private static string CsvEscape(string value)
    {
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r'))
        {
            return $"\"{value.Replace("\"", "\"\"")}\"";
        }

        return value;
    }
}
