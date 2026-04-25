using System.Collections.Concurrent;
using System.Net;

namespace Sentinel.Gateway.Middleware;

public sealed class RateLimitMiddleware
{
    private readonly RequestDelegate _next;
    private static readonly ConcurrentDictionary<string, RequestBucket> Buckets = new();
    private const int RequestsPerMinute = 300;

    public RateLimitMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var clientIp = context.Request.Headers["X-Forwarded-For"].ToString();
        if (string.IsNullOrEmpty(clientIp))
        {
            clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        }

        var bucket = Buckets.AddOrUpdate(clientIp, _ => new RequestBucket(), (_, b) => b.RefreshIfExpired());

        if (!bucket.TryConsume())
        {
            context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            context.Response.Headers["Retry-After"] = bucket.RetryAfterSeconds.ToString();
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"rate_limit_exceeded\"}").ConfigureAwait(false);
            return;
        }

        await _next(context).ConfigureAwait(false);
    }

    private sealed class RequestBucket
    {
        private int _requestCount;
        private DateTime _windowStart = DateTime.UtcNow;
        private const int WindowSizeSeconds = 60;

        public int RetryAfterSeconds => Math.Max(1, (int)((_windowStart.AddSeconds(WindowSizeSeconds) - DateTime.UtcNow).TotalSeconds));

        public RequestBucket RefreshIfExpired()
        {
            if (DateTime.UtcNow - _windowStart > TimeSpan.FromSeconds(WindowSizeSeconds))
            {
                _requestCount = 0;
                _windowStart = DateTime.UtcNow;
            }

            return this;
        }

        public bool TryConsume()
        {
            RefreshIfExpired();
            if (_requestCount >= RequestsPerMinute)
                return false;

            Interlocked.Increment(ref _requestCount);
            return true;
        }
    }
}
