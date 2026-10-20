namespace WPShield.NetworkSensor;

/// <summary>
/// Lightweight HTTP metadata extraction from raw TCP payload bytes.
///
/// The parser never returns body content, query strings, headers, or any data beyond the
/// minimal metadata needed for network observation: method, path (query string stripped),
/// status code, and body size. It is intentionally best-effort: if the payload is not clearly
/// HTTP, it returns <c>null</c> and the packet is skipped.
/// </summary>
public static class HttpMetadataParser
{
    private static readonly byte[] CrLf = { (byte)'\r', (byte)'\n' };

    /// <summary>
    /// Tries to parse HTTP metadata from a TCP payload buffer.
    /// </summary>
    /// <param name="buffer">Raw TCP payload bytes.</param>
    /// <param name="offset">Offset within <paramref name="buffer"/> where the payload starts.</param>
    /// <param name="length">Number of payload bytes.</param>
    /// <returns>Parsed metadata, or <c>null</c> if the payload is not recognisable HTTP.</returns>
    public static HttpMetadata? TryParse(byte[] buffer, int offset, int length)
    {
        if (buffer is null || length < 12)
        {
            return null;
        }

        // Look for the end of the first line (request line or status line).
        var endOfLine = FindCrLf(buffer, offset, length);
        if (endOfLine < 0)
        {
            return null;
        }

        var firstLineLength = endOfLine - offset;
        if (firstLineLength < 4 || firstLineLength > 2048)
        {
            return null;
        }

        var firstLine = System.Text.Encoding.UTF8.GetString(buffer, offset, firstLineLength);

        // Request line: "METHOD /path HTTP/1.x"
        if (IsRequestLine(firstLine, out var method, out var path))
        {
            return new HttpMetadata
            {
                IsRequest = true,
                HttpMethod = method,
                Path = StripQueryString(path),
                StatusCode = null,
                BodySizeBytes = ExtractContentLength(buffer, offset, length),
            };
        }

        // Status line: "HTTP/1.x 200 OK"
        if (IsStatusLine(firstLine, out var statusCode))
        {
            return new HttpMetadata
            {
                IsRequest = false,
                HttpMethod = string.Empty,
                Path = string.Empty,
                StatusCode = statusCode,
                BodySizeBytes = ExtractContentLength(buffer, offset, length),
            };
        }

        return null;
    }

    private static int FindCrLf(byte[] buffer, int offset, int length)
    {
        for (var i = offset; i < offset + length - 1; i++)
        {
            if (buffer[i] == (byte)'\r' && buffer[i + 1] == (byte)'\n')
            {
                return i;
            }
        }
        return -1;
    }

    private static bool IsRequestLine(string line, out string method, out string path)
    {
        method = string.Empty;
        path = string.Empty;

        var firstSpace = line.IndexOf(' ');
        if (firstSpace < 0)
        {
            return false;
        }

        var secondSpace = line.IndexOf(' ', firstSpace + 1);
        if (secondSpace < 0)
        {
            return false;
        }

        method = line.Substring(0, firstSpace);

        // Only accept known HTTP methods to avoid false positives on non-HTTP traffic.
        if (!IsKnownHttpMethod(method))
        {
            return false;
        }

        path = line.Substring(firstSpace + 1, secondSpace - firstSpace - 1);
        return true;
    }

    private static bool IsStatusLine(string line, out int? statusCode)
    {
        statusCode = null;

        if (!line.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var firstSpace = line.IndexOf(' ');
        if (firstSpace < 0)
        {
            return false;
        }

        var secondSpace = line.IndexOf(' ', firstSpace + 1);
        if (secondSpace < 0)
        {
            secondSpace = line.Length;
        }

        var statusText = line.Substring(firstSpace + 1, secondSpace - firstSpace - 1);
        if (int.TryParse(statusText, out var code) && code >= 100 && code <= 599)
        {
            statusCode = code;
            return true;
        }

        return false;
    }

    private static bool IsKnownHttpMethod(string method)
    {
        return method switch
        {
            "GET" or "POST" or "PUT" or "DELETE" or "HEAD" or "OPTIONS" or "PATCH" or
            "TRACE" or "CONNECT" => true,
            _ => false,
        };
    }

    private static string StripQueryString(string path)
    {
        var queryStart = path.IndexOf('?');
        if (queryStart < 0)
        {
            return path;
        }

        return path.Substring(0, queryStart);
    }

    private static long? ExtractContentLength(byte[] buffer, int offset, int length)
    {
        // Best-effort: search for "Content-Length: " header in the first bytes of the payload.
        // This is intentionally limited to the first 8 KiB to avoid scanning large bodies.
        var scanEnd = Math.Min(offset + length, offset + 8192);
        var haystack = System.Text.Encoding.UTF8.GetString(buffer, offset, scanEnd - offset);

        var headerName = "Content-Length:";
        var idx = haystack.IndexOf(headerName, StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
        {
            return null;
        }

        var valueStart = idx + headerName.Length;
        while (valueStart < haystack.Length && char.IsWhiteSpace(haystack[valueStart]))
        {
            valueStart++;
        }

        var valueEnd = valueStart;
        while (valueEnd < haystack.Length && char.IsDigit(haystack[valueEnd]))
        {
            valueEnd++;
        }

        if (valueEnd > valueStart && long.TryParse(haystack.Substring(valueStart, valueEnd - valueStart), out var lengthValue))
        {
            return lengthValue;
        }

        return null;
    }
}

/// <summary>
/// Minimal HTTP metadata extracted from a TCP payload. Only fields safe for logging are included.
/// </summary>
public sealed class HttpMetadata
{
    public bool IsRequest { get; init; }
    public string HttpMethod { get; init; } = string.Empty;
    public string Path { get; init; } = string.Empty; // query string stripped
    public int? StatusCode { get; init; }
    public long? BodySizeBytes { get; init; }
}
