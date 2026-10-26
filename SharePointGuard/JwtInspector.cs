using System.Text;
using System.Text.Json;

namespace SharePointGuard;

/// <summary>
/// Detects unsigned JSON Web Tokens ("alg": "none"), which were used to
/// bypass authentication in SharePoint Server (CVE-2023-29357).
/// </summary>
public static class JwtInspector
{
    public static bool IsUnsigned(string? headerValue)
    {
        if (string.IsNullOrWhiteSpace(headerValue))
        {
            return false;
        }

        string token = headerValue.Trim();
        if (token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            token = token["Bearer ".Length..].Trim();
        }

        string[] parts = token.Split('.');
        if (parts.Length < 2)
        {
            return false;
        }

        byte[]? headerBytes = DecodeBase64Url(parts[0]);
        if (headerBytes is null)
        {
            return false;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(headerBytes);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            foreach (JsonProperty property in document.RootElement.EnumerateObject())
            {
                if (!property.Name.Equals("alg", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                // A missing/empty algorithm is just as unsigned as "none".
                return property.Value.ValueKind != JsonValueKind.String
                    || string.IsNullOrWhiteSpace(property.Value.GetString())
                    || property.Value.GetString()!.Trim().Equals("none", StringComparison.OrdinalIgnoreCase);
            }

            // A JWT header without an "alg" member is not a valid signed token.
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static byte[]? DecodeBase64Url(string value)
    {
        var builder = new StringBuilder(value.Trim().Replace('-', '+').Replace('_', '/'));
        while (builder.Length % 4 != 0)
        {
            builder.Append('=');
        }

        try
        {
            return Convert.FromBase64String(builder.ToString());
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
