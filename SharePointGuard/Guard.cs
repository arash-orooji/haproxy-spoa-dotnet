using System.Text.RegularExpressions;

namespace SharePointGuard;

/// <summary>
/// Evaluates requests against the configured rules.
/// </summary>
public sealed class Guard(RuleSet ruleSet)
{
    public const string UnsignedJwtRuleId = "SP-JWT-ALG-NONE";

    public RuleSet RuleSet { get; } = ruleSet;

    public Verdict Evaluate(RequestInfo request)
    {
        if (RuleSet.BlockUnsignedJwt
            && (JwtInspector.IsUnsigned(request.Authorization) || JwtInspector.IsUnsigned(request.ProofToken)))
        {
            return Verdict.Block(UnsignedJwtRuleId, "Unsigned JWT (alg=none) authentication bypass attempt (CVE-2023-29357)");
        }

        string path = PathNormalizer.Normalize(request.Path);
        string query = NormalizeQuery(request.Query);
        string? referer = NormalizeReferer(request.Referer);

        foreach (GuardRule rule in RuleSet.Rules)
        {
            try
            {
                if (rule.Matches(request.Method, path, query, referer, request.Source))
                {
                    return Verdict.Block(rule.Id, rule.Description);
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // Inputs crafted to make a rule slow are suspicious in their own right.
                return Verdict.Block(rule.Id, "Rule evaluation timed out");
            }
        }

        return Verdict.Allow;
    }

    internal static string NormalizeQuery(string? query)
    {
        if (string.IsNullOrEmpty(query))
        {
            return string.Empty;
        }

        string value = query.Replace('+', ' ');
        for (int i = 0; i < 3; i++)
        {
            string decoded = Uri.UnescapeDataString(value);
            if (decoded == value)
            {
                break;
            }

            value = decoded;
        }

        return value.ToLowerInvariant();
    }

    internal static string? NormalizeReferer(string? referer)
    {
        if (string.IsNullOrWhiteSpace(referer))
        {
            return null;
        }

        string path = Uri.TryCreate(referer.Trim(), UriKind.Absolute, out Uri? uri) && uri.Scheme is "http" or "https"
            ? uri.AbsolutePath
            : referer.Trim();

        return PathNormalizer.Normalize(path);
    }
}
