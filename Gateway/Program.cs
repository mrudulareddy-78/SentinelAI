// File: Gateway/Program.cs
using Sentinel.Gateway;
using Sentinel.Gateway.Middleware;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.UseUrls("http://0.0.0.0:5050");
builder.Services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));
builder.Services.AddSingleton<DatabaseService>();
builder.Services.AddSingleton<JwtTokenService>();

var app = builder.Build();

app.UseMiddleware<SecurityMiddleware>();
app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseMiddleware<ValidationMiddleware>();
app.UseMiddleware<RateLimitMiddleware>();
app.UseMiddleware<LoggingMiddleware>();
app.UseMiddleware<AesDecryptionMiddleware>();
app.UseMiddleware<OpenApiSchemaValidationMiddleware>();
app.UseMiddleware<JwtAuthMiddleware>();

app.MapGet("/health", () => Results.Ok(new { status = "ok", service = "Sentinel Gateway" }));
app.MapGet("/token", (HttpContext context, JwtTokenService tokenService, IConfiguration configuration) =>
{
    var subject = context.Request.Query["subject"].ToString();
    if (string.IsNullOrWhiteSpace(subject))
    {
        subject = "sentinel-student";
    }

    var token = tokenService.CreateToken(subject);
    var lifetimeMinutes = configuration.GetValue("Jwt:TokenLifetimeMinutes", 60);

    return Results.Ok(new
    {
        access_token = token,
        token_type = "Bearer",
        expires_in_minutes = lifetimeMinutes,
        issuer = configuration["Jwt:Issuer"],
        audience = configuration["Jwt:Audience"]
    });
});

app.MapPost("/sentinel/feedback", async (HttpContext context, DatabaseService dbService) =>
{
    var feedback = await context.Request.ReadFromJsonAsync<dynamic>().ConfigureAwait(false);
    if (feedback is null)
    {
        return Results.BadRequest(new { error = "invalid_feedback_payload" });
    }

    var uuid = Guid.NewGuid().ToString();
    await dbService.RecordFeedbackAsync(uuid, feedback).ConfigureAwait(false);

    return Results.Ok(new
    {
        status = "recorded",
        id = uuid,
        engine = "sqlite_wal"
    });
});



app.MapReverseProxy(proxyPipeline =>
{
    proxyPipeline.Use(async (context, next) =>
    {
        context.Response.Headers["X-Sentinel-Gateway"] = "Module1";
        await next().ConfigureAwait(false);
    });
});

app.Run();
