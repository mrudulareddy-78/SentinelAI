using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Globalization;
using System.Text;

namespace Sentinel.Gateway.Middleware;

public sealed class LoggingMiddleware
{
    private static readonly SemaphoreSlim WriteLock = new(1, 1);
    private static readonly string[] HeaderColumns =
    {
        "timestamp",
        "src_ip",
        "method",
        "path",
        "status_code",
        "duration_ms",
        "payload_size_bytes",
        "auth_header_present"
    };

    private readonly RequestDelegate _next;

    public LoggingMiddleware(RequestDelegate next) // SENTINEL_REDIS
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, DatabaseService dbService)
    {
        var stopwatch = Stopwatch.StartNew();
        var authHeaderPresent = context.Request.Headers.ContainsKey("Authorization");
        var payloadSizeBytes = context.Request.ContentLength ?? 0;
        Exception? pipelineException = null;

        try
        {
            await _next(context).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            pipelineException = ex;
            if (!context.Response.HasStarted)
            {
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            }
        }
        finally
        {
            stopwatch.Stop();
            var timestamp = DateTime.UtcNow;
            var ip = context.Request.Headers["X-Forwarded-For"].ToString();
            if (string.IsNullOrEmpty(ip))
            {
                ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            }


            var iv = context.Items["Sentinel-IV"]?.ToString();
            var payload = context.Items["Sentinel-Payload"]?.ToString();

            await dbService.LogRequestAsync(
                ip: ip,
                method: context.Request.Method,
                path: context.Request.Path + context.Request.QueryString,
                statusCode: context.Response.StatusCode,
                durationMs: stopwatch.Elapsed.TotalMilliseconds,
                payloadSize: payloadSizeBytes,
                authHeader: authHeaderPresent,
                iv: iv,
                payloadExcerpt: payload
            ).ConfigureAwait(false);
        }

        if (pipelineException is not null)
        {
            ExceptionDispatchInfo.Capture(pipelineException).Throw();
        }
    }
}
