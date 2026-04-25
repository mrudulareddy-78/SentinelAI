using System.Text;
using System.Text.RegularExpressions;

namespace Sentinel.Gateway.Middleware;

public sealed class ValidationMiddleware
{
    private readonly RequestDelegate _next;
    private static readonly HashSet<string> AllowedContentTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "application/json",
        "text/plain",
        "application/x-www-form-urlencoded",
    };

    public ValidationMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!IsValidRequest(context.Request, out var errorMessage))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync($"{{\"error\":\"{errorMessage}\"}}").ConfigureAwait(false);
            return;
        }

        await _next(context).ConfigureAwait(false);
    }

    private static bool IsValidRequest(HttpRequest request, out string errorMessage)
    {
        errorMessage = string.Empty;

        if (request.Path.HasValue && !IsValidPath(request.Path.Value))
        {
            errorMessage = "invalid_request_path";
            return false;
        }

        if (!string.IsNullOrEmpty(request.ContentType) && !IsValidContentType(request.ContentType))
        {
            errorMessage = "invalid_content_type";
            return false;
        }

        if ((request.Method == HttpMethods.Post || request.Method == HttpMethods.Put || request.Method == HttpMethods.Patch)
            && request.ContentLength > 1048576)
        {
            errorMessage = "payload_too_large";
            return false;
        }

        return true;
    }

    private static bool IsValidPath(string path)
    {
        if (path.Length > 2048)
            return false;

        if (path.Contains("//") || path.Contains("..") || path.Contains("\\"))
            return false;

        if (!Regex.IsMatch(path, @"^[a-zA-Z0-9/_\-\.?\&=+]*$"))
            return false;

        return true;
    }

    private static bool IsValidContentType(string contentType)
    {
        var baseType = contentType.Split(';')[0].Trim();
        return AllowedContentTypes.Contains(baseType);
    }
}
