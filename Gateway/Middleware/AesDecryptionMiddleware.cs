using System.Security.Cryptography;
using System.Text;

namespace Sentinel.Gateway.Middleware;

public sealed class AesDecryptionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly byte[] _keyBytes;
    private readonly string _encryptedHeaderName;
    private readonly string _ivHeaderName;

    public AesDecryptionMiddleware(RequestDelegate next, IConfiguration configuration)
    {
        _next = next;
        var keyMaterial = configuration["Aes:KeyMaterial"] ?? "SentinelAES256Key-1234567890ABCD";
        _keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(keyMaterial));
        _encryptedHeaderName = configuration["Aes:EncryptedHeaderName"] ?? "X-Encrypted";
        _ivHeaderName = configuration["Aes:IvHeaderName"] ?? "X-Init-Vector";
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!ShouldProcess(context.Request))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        if (!IsEncryptedRequest(context.Request))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        if (!context.Request.Headers.TryGetValue(_ivHeaderName, out var ivHeaderValues))
        {
            await RejectAsync(context, "missing_iv_header").ConfigureAwait(false);
            return;
        }

        try
        {
            var iv = Convert.FromBase64String(ivHeaderValues.ToString());
            if (iv.Length != 16)
            {
                await RejectAsync(context, "invalid_iv_length").ConfigureAwait(false);
                return;
            }

            var encryptedBody = await ReadRequestBodyAsync(context.Request).ConfigureAwait(false);
            var decryptedBody = DecryptPayload(encryptedBody, iv);
            
            // SENTINEL_NEW: Store for deep packet inspection logs
            context.Items["Sentinel-IV"] = ivHeaderValues.ToString();
            context.Items["Sentinel-Payload"] = Encoding.UTF8.GetString(decryptedBody);

            context.Request.Body = new MemoryStream(decryptedBody);
            context.Request.ContentLength = decryptedBody.Length;
            context.Request.Headers.Remove(_encryptedHeaderName);
            await _next(context).ConfigureAwait(false);
        }
        catch (FormatException)
        {
            await RejectAsync(context, "invalid_base64_payload_or_iv").ConfigureAwait(false);
        }
        catch (CryptographicException)
        {
            await RejectAsync(context, "aes_decryption_failed").ConfigureAwait(false);
        }
    }

    private static bool ShouldProcess(HttpRequest request)
    {
        return HttpMethods.IsPost(request.Method)
            || HttpMethods.IsPut(request.Method)
            || HttpMethods.IsPatch(request.Method);
    }

    private bool IsEncryptedRequest(HttpRequest request)
    {
        return request.Headers.TryGetValue(_encryptedHeaderName, out var encryptedFlag)
            && string.Equals(encryptedFlag.ToString(), "true", StringComparison.OrdinalIgnoreCase);
    }

    private async Task<byte[]> ReadRequestBodyAsync(HttpRequest request)
    {
        request.EnableBuffering();
        request.Body.Position = 0;

        using var reader = new StreamReader(request.Body, Encoding.UTF8, leaveOpen: true);
        var encryptedText = await reader.ReadToEndAsync().ConfigureAwait(false);
        request.Body.Position = 0;
        return Convert.FromBase64String(encryptedText.Trim());
    }

    private byte[] DecryptPayload(byte[] cipherBytes, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = _keyBytes;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
    }

    private static async Task RejectAsync(HttpContext context, string reason)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync($"{{\"error\":\"{reason}\"}}").ConfigureAwait(false);
    }
}
