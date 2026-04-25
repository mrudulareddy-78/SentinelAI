using Microsoft.Data.Sqlite;
using System.Text.Json;

namespace Sentinel.Gateway;

public sealed class DatabaseService
{
    private readonly string _connectionString;
    private readonly ILogger<DatabaseService> _logger;

    public DatabaseService(IConfiguration configuration, IWebHostEnvironment environment, ILogger<DatabaseService> logger)
    {
        _logger = logger;
        var dbPath = Path.GetFullPath(Path.Combine(environment.ContentRootPath, "..", "Shared", "logs", "sentinel.db"));
        Directory.CreateDirectory(Path.GetDirectoryName(dbPath)!);
        
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = dbPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = true,
            Cache = SqliteCacheMode.Shared
        }.ToString();

        InitializeDatabase();
    }

    private void InitializeDatabase()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();
        
        // Elite Feature: Enable WAL Mode for high-performance concurrency
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA journal_mode=WAL;";
        command.ExecuteNonQuery();

        // Schema setup
        using var schemaCommand = connection.CreateCommand();
        schemaCommand.CommandText = @"
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                method TEXT,
                path TEXT,
                status_code INTEGER,
                duration_ms REAL,
                payload_size_bytes INTEGER,
                auth_header_present INTEGER,
                iv TEXT,
                payload_excerpt TEXT
            );
            CREATE TABLE IF NOT EXISTS inferences (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                prediction TEXT,
                confidence_score REAL,
                risk_score INTEGER,
                uncertainty_score REAL,
                review_required BOOLEAN,
                mitre_stage TEXT,
                method TEXT,
                path TEXT,
                status_code INTEGER,
                payload_size_bytes INTEGER,
                country_code TEXT,
                threat_type TEXT,
                xai_reason TEXT
            );
            CREATE TABLE IF NOT EXISTS blacklist (
                ip TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS feedback (
                uuid TEXT PRIMARY KEY,
                timestamp TEXT,
                data TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_requests_ip ON requests(src_ip);
            CREATE INDEX IF NOT EXISTS idx_inferences_ts ON inferences(timestamp);
        ";
        schemaCommand.ExecuteNonQuery();
    }

    public async Task<bool> IsBlacklistedAsync(string ip)
    {
        // Blacklist feature disabled for demo
        return await Task.FromResult(false);
    }


    public async Task LogRequestAsync(string ip, string method, string path, int statusCode, double durationMs, long payloadSize, bool authHeader, string? iv = null, string? payloadExcerpt = null)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT INTO requests (timestamp, src_ip, method, path, status_code, duration_ms, payload_size_bytes, auth_header_present, iv, payload_excerpt)
                VALUES (@ts, @ip, @method, @path, @status, @duration, @size, @auth, @iv, @payload)
            ";
            command.Parameters.AddWithValue("@ts", DateTime.UtcNow.ToString("O"));
            command.Parameters.AddWithValue("@ip", ip);
            command.Parameters.AddWithValue("@method", method);
            command.Parameters.AddWithValue("@path", path);
            command.Parameters.AddWithValue("@status", statusCode);
            command.Parameters.AddWithValue("@duration", durationMs);
            command.Parameters.AddWithValue("@size", payloadSize);
            command.Parameters.AddWithValue("@auth", authHeader ? 1 : 0);
            command.Parameters.AddWithValue("@iv", iv ?? (object)DBNull.Value);
            command.Parameters.AddWithValue("@payload", payloadExcerpt ?? (object)DBNull.Value);
            await command.ExecuteNonQueryAsync();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to log request to database.");
        }
    }

    public async Task RecordFeedbackAsync(string uuid, object feedback)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();
            using var command = connection.CreateCommand();
            command.CommandText = "INSERT INTO feedback (uuid, timestamp, data) VALUES (@uuid, @ts, @data)";
            command.Parameters.AddWithValue("@uuid", uuid);
            command.Parameters.AddWithValue("@ts", DateTime.UtcNow.ToString("O"));
            command.Parameters.AddWithValue("@data", JsonSerializer.Serialize(feedback));
            await command.ExecuteNonQueryAsync();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to record analyst feedback.");
        }
    }
}
