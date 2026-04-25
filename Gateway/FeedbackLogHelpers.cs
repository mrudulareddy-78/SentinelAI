using System.Text;

namespace Sentinel.Gateway;

internal static class FeedbackLogHelpers
{
    internal sealed record AnalystFeedbackRequest(
        string timestamp,
        string src_ip,
        string method,
        string path,
        int status_code,
        double duration_ms,
        int payload_size_bytes,
        bool auth_header_present,
        string prediction,
        double confidence_score,
        double risk_score,
        double uncertainty_score,
        bool review_required,
        string analyst_label,
        string review_action,
        string? notes,
        string? mitre_stage
    );

    internal static void EnsureFeedbackFileExists(string feedbackLogPath)
    {
        if (!File.Exists(feedbackLogPath) || new FileInfo(feedbackLogPath).Length == 0)
        {
            File.WriteAllText(
                feedbackLogPath,
                "timestamp,src_ip,method,path,status_code,duration_ms,payload_size_bytes,auth_header_present,prediction,confidence_score,risk_score,uncertainty_score,review_required,analyst_label,review_action,notes,mitre_stage" + Environment.NewLine,
                Encoding.UTF8);
        }
    }

    internal static async Task AppendFeedbackAsync(string feedbackLogPath, AnalystFeedbackRequest feedback)
    {
        var line = string.Join(",", new[]
        {
            CsvEscape(feedback.timestamp),
            CsvEscape(feedback.src_ip),
            CsvEscape(feedback.method),
            CsvEscape(feedback.path),
            feedback.status_code.ToString(System.Globalization.CultureInfo.InvariantCulture),
            feedback.duration_ms.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture),
            feedback.payload_size_bytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            feedback.auth_header_present ? "true" : "false",
            CsvEscape(feedback.prediction),
            feedback.confidence_score.ToString("0.####", System.Globalization.CultureInfo.InvariantCulture),
            feedback.risk_score.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture),
            feedback.uncertainty_score.ToString("0.####", System.Globalization.CultureInfo.InvariantCulture),
            feedback.review_required ? "true" : "false",
            CsvEscape(feedback.analyst_label),
            CsvEscape(feedback.review_action),
            CsvEscape(feedback.notes ?? string.Empty),
            CsvEscape(feedback.mitre_stage ?? string.Empty)
        });

        await File.AppendAllTextAsync(feedbackLogPath, line + Environment.NewLine, Encoding.UTF8).ConfigureAwait(false);
    }

    private static string CsvEscape(string value)
    {
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r'))
        {
            return $"\"{value.Replace("\"", "\"\"") }\"";
        }

        return value;
    }
}
