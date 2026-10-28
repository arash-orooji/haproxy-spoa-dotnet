using System.Text;

namespace SharePointGuard;

/// <summary>
/// Canonicalizes request paths the way IIS/SharePoint would interpret them, so
/// that encoding tricks (%2e, double encoding, backslashes, "..", mixed case)
/// cannot be used to slip past the rules.
/// </summary>
public static class PathNormalizer
{
    private const int MaxDecodePasses = 3;

    public static string Normalize(string? rawPath)
    {
        if (string.IsNullOrEmpty(rawPath))
        {
            return "/";
        }

        string path = rawPath;

        // Drop any query string that may have slipped into the path.
        int queryIndex = path.IndexOf('?');
        if (queryIndex >= 0)
        {
            path = path[..queryIndex];
        }

        // Decode repeatedly to defeat double/triple percent-encoding.
        for (int i = 0; i < MaxDecodePasses; i++)
        {
            string decoded = Uri.UnescapeDataString(path);
            if (decoded == path)
            {
                break;
            }

            path = decoded;
        }

        // IIS accepts backslashes as separators.
        path = path.Replace('\\', '/');

        var segments = new List<string>();
        foreach (string rawSegment in path.Split('/'))
        {
            if (rawSegment == "..")
            {
                if (segments.Count > 0)
                {
                    segments.RemoveAt(segments.Count - 1);
                }

                continue;
            }

            // IIS ignores trailing dots and spaces in a segment ("ToolPane.aspx." == "ToolPane.aspx").
            string segment = rawSegment.TrimEnd('.', ' ');
            if (segment.Length > 0)
            {
                segments.Add(segment);
            }
        }

        var builder = new StringBuilder(path.Length + 1);
        foreach (string segment in segments)
        {
            builder.Append('/').Append(segment);
        }

        return builder.Length == 0 ? "/" : builder.ToString().ToLowerInvariant();
    }
}
