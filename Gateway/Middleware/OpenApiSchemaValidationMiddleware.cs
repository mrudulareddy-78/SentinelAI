// File: Gateway/Middleware/OpenApiSchemaValidationMiddleware.cs
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Json.Schema;
using Microsoft.OpenApi.Models;
using Microsoft.OpenApi.Readers;
using Microsoft.OpenApi.Writers;

namespace Sentinel.Gateway.Middleware;

public sealed class OpenApiSchemaValidationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly Dictionary<(string Method, string PathTemplate), JsonSchema> _schemas;

    public OpenApiSchemaValidationMiddleware(RequestDelegate next, IWebHostEnvironment environment)
    {
        _next = next;
        _schemas = LoadSchemas(environment);
        SecurityEventLogger.Initialize(environment);
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!ShouldValidate(context.Request))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        var method = context.Request.Method.ToUpperInvariant();
        var requestPath = context.Request.Path.Value ?? "/";

        var matchingSchema = FindMatchingSchema(method, requestPath);
        if (matchingSchema is null)
        {
            await SecurityEventLogger.LogAsync(context, "unknown_path", "low", "no schema for request path", "allow").ConfigureAwait(false);
            await _next(context).ConfigureAwait(false);
            return;
        }

        if (!IsJsonRequest(context.Request))
        {
            await RejectAsync(context, "request body must be application/json", requestPath).ConfigureAwait(false);
            await SecurityEventLogger.LogAsync(context, "schema_violation", "high", "request body must be application/json", "block").ConfigureAwait(false);
            return;
        }

        string body;
        context.Request.EnableBuffering();
        context.Request.Body.Position = 0;
        using (var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true))
        {
            body = await reader.ReadToEndAsync().ConfigureAwait(false);
        }

        context.Request.Body.Position = 0;

        if (string.IsNullOrWhiteSpace(body))
        {
            await RejectAsync(context, "request body is required", requestPath).ConfigureAwait(false);
            await SecurityEventLogger.LogAsync(context, "schema_violation", "high", "request body is required", "block").ConfigureAwait(false);
            return;
        }

        JsonNode? bodyNode;
        try
        {
            bodyNode = JsonNode.Parse(body);
        }
        catch (JsonException)
        {
            await RejectAsync(context, "request body is not valid JSON", requestPath).ConfigureAwait(false);
            await SecurityEventLogger.LogAsync(context, "schema_violation", "high", "request body is not valid JSON", "block").ConfigureAwait(false);
            return;
        }

        if (bodyNode is null)
        {
            await RejectAsync(context, "request body is not valid JSON", requestPath).ConfigureAwait(false);
            await SecurityEventLogger.LogAsync(context, "schema_violation", "high", "request body is not valid JSON", "block").ConfigureAwait(false);
            return;
        }

        var result = matchingSchema.Evaluate(bodyNode, new EvaluationOptions { OutputFormat = OutputFormat.List });
        if (!result.IsValid)
        {
            var detail = result.Details?.FirstOrDefault(detailNode => !detailNode.IsValid);
            var reason = detail?.Errors?.FirstOrDefault().Value ?? "schema validation failed";
            await RejectAsync(context, reason, requestPath).ConfigureAwait(false);
            await SecurityEventLogger.LogAsync(context, "schema_violation", "high", reason, "block").ConfigureAwait(false);
            return;
        }

        await _next(context).ConfigureAwait(false);
    }

    private static bool ShouldValidate(HttpRequest request)
    {
        return HttpMethods.IsPost(request.Method) || HttpMethods.IsPut(request.Method) || HttpMethods.IsPatch(request.Method);
    }

    private static bool IsJsonRequest(HttpRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.ContentType))
        {
            return false;
        }

        return request.ContentType.StartsWith("application/json", StringComparison.OrdinalIgnoreCase);
    }

    private static async Task RejectAsync(HttpContext context, string reason, string path)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(new
        {
            blocked_by = "schema_validator",
            reason,
            path
        }).ConfigureAwait(false);
    }

    private JsonSchema? FindMatchingSchema(string method, string requestPath)
    {
        foreach (var entry in _schemas)
        {
            if (!string.Equals(entry.Key.Method, method, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (PathMatches(entry.Key.PathTemplate, requestPath))
            {
                return entry.Value;
            }
        }

        return null;
    }

    private static bool PathMatches(string template, string path)
    {
        var templateSegments = template.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        var pathSegments = path.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);

        if (templateSegments.Length != pathSegments.Length)
        {
            return false;
        }

        for (var index = 0; index < templateSegments.Length; index++)
        {
            var templateSegment = templateSegments[index];
            if (templateSegment.StartsWith("{") && templateSegment.EndsWith("}"))
            {
                continue;
            }

            if (!string.Equals(templateSegment, pathSegments[index], StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }

    private static Dictionary<(string Method, string PathTemplate), JsonSchema> LoadSchemas(IWebHostEnvironment environment)
    {
        var schemaPath = Path.GetFullPath(Path.Combine(environment.ContentRootPath, "..", "schema.yaml"));
        if (!File.Exists(schemaPath))
        {
            return new Dictionary<(string Method, string PathTemplate), JsonSchema>();
        }

        using var stream = File.OpenRead(schemaPath);
        var reader = new OpenApiStreamReader();
        var document = reader.Read(stream, out var diagnostics);
        if (diagnostics.Errors.Count > 0)
        {
            return new Dictionary<(string Method, string PathTemplate), JsonSchema>();
        }

        var schemas = new Dictionary<(string Method, string PathTemplate), JsonSchema>();

        foreach (var pathItem in document.Paths)
        {
            var operations = new Dictionary<OperationType, OpenApiOperation?>
            {
                [OperationType.Post] = TryGetOperation(pathItem.Value.Operations, OperationType.Post),
                [OperationType.Put] = TryGetOperation(pathItem.Value.Operations, OperationType.Put),
                [OperationType.Patch] = TryGetOperation(pathItem.Value.Operations, OperationType.Patch)
            };

            foreach (var operation in operations)
            {
                if (operation.Value?.RequestBody?.Content is null)
                {
                    continue;
                }

                if (!operation.Value.RequestBody.Content.TryGetValue("application/json", out var mediaType) || mediaType.Schema is null)
                {
                    continue;
                }

                var jsonSchema = BuildJsonSchema(mediaType.Schema, document);
                schemas[(operation.Key.ToString().ToUpperInvariant(), pathItem.Key)] = jsonSchema;
            }
        }

        return schemas;
    }

    private static OpenApiOperation? TryGetOperation(IDictionary<OperationType, OpenApiOperation> operations, OperationType type)
    {
        return operations.TryGetValue(type, out var operation) ? operation : null;
    }

    private static JsonSchema BuildJsonSchema(OpenApiSchema schema, OpenApiDocument document)
    {
        var resolved = ResolveSchema(schema, document, new HashSet<string>(StringComparer.Ordinal));

        var writer = new StringWriter();
        var jsonWriter = new OpenApiJsonWriter(writer);
        resolved.SerializeAsV3(jsonWriter);
        jsonWriter.Flush();

        var openApiJson = writer.ToString();
        var openApiNode = JsonNode.Parse(openApiJson) as JsonObject ?? new JsonObject();
        var draftSchemaNode = ConvertOpenApiToJsonSchema(openApiNode);
        return JsonSchema.FromText(draftSchemaNode.ToJsonString());
    }

    private static OpenApiSchema ResolveSchema(OpenApiSchema schema, OpenApiDocument document, HashSet<string> visited)
    {
        if (schema.Reference is null || string.IsNullOrWhiteSpace(schema.Reference.Id))
        {
            return schema;
        }

        if (!visited.Add(schema.Reference.Id))
        {
            return schema;
        }

        if (!document.Components.Schemas.TryGetValue(schema.Reference.Id, out var target))
        {
            return schema;
        }

        return ResolveSchema(target, document, visited);
    }

    private static JsonObject ConvertOpenApiToJsonSchema(JsonObject source)
    {
        var schema = new JsonObject();

        if (source.TryGetPropertyValue("type", out var typeNode) && typeNode is not null)
        {
            schema["type"] = typeNode.DeepClone();
        }

        if (source.TryGetPropertyValue("required", out var requiredNode) && requiredNode is not null)
        {
            schema["required"] = requiredNode.DeepClone();
        }

        if (source.TryGetPropertyValue("enum", out var enumNode) && enumNode is not null)
        {
            schema["enum"] = enumNode.DeepClone();
        }

        if (source.TryGetPropertyValue("minLength", out var minLengthNode) && minLengthNode is not null)
        {
            schema["minLength"] = minLengthNode.DeepClone();
        }

        if (source.TryGetPropertyValue("maxLength", out var maxLengthNode) && maxLengthNode is not null)
        {
            schema["maxLength"] = maxLengthNode.DeepClone();
        }

        if (source.TryGetPropertyValue("minimum", out var minimumNode) && minimumNode is not null)
        {
            schema["minimum"] = minimumNode.DeepClone();
        }

        if (source.TryGetPropertyValue("maximum", out var maximumNode) && maximumNode is not null)
        {
            schema["maximum"] = maximumNode.DeepClone();
        }

        if (source.TryGetPropertyValue("properties", out var propertiesNode) && propertiesNode is JsonObject properties)
        {
            var convertedProperties = new JsonObject();
            foreach (var property in properties)
            {
                if (property.Value is JsonObject propertySchema)
                {
                    convertedProperties[property.Key] = ConvertOpenApiToJsonSchema(propertySchema);
                }
            }

            schema["properties"] = convertedProperties;
            schema["additionalProperties"] = false;
        }

        if (source.TryGetPropertyValue("items", out var itemsNode) && itemsNode is JsonObject itemsSchema)
        {
            schema["items"] = ConvertOpenApiToJsonSchema(itemsSchema);
        }

        return schema;
    }
}
