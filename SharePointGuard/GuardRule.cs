using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace SharePointGuard;

/// <summary>
/// A single block rule. A request matches when every condition that is set matches.
/// </summary>
public sealed class GuardRule
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);

    private Regex? pathRegex;
    private Regex? queryRegex;
    private Regex? refererRegex;
    private IPNetwork[] allowedNetworks = [];

    public required string Id { get; init; }

    public string Description { get; init; } = string.Empty;

    public bool Enabled { get; init; } = true;

    /// <summary>Regex matched against the normalized (decoded, lower-case) path.</summary>
    public string? Path { get; init; }

    /// <summary>Regex matched against the decoded, lower-case query string.</summary>
    public string? Query { get; init; }

    /// <summary>Regex matched against the normalized path of the Referer header.</summary>
    public string? Referer { get; init; }

    /// <summary>HTTP methods the rule applies to. Empty means all methods.</summary>
    public string[] Methods { get; init; } = [];

    /// <summary>CIDR ranges that are exempt from this rule (e.g. internal admin networks).</summary>
    public string[] AllowFrom { get; init; } = [];

    internal void Compile()
    {
        if (Path is null && Query is null && Referer is null)
        {
            throw new InvalidOperationException($"Rule '{Id}' must define at least one of 'path', 'query' or 'referer'.");
        }

        pathRegex = Build(Path);
        queryRegex = Build(Query);
        refererRegex = Build(Referer);
        allowedNetworks = AllowFrom.Select(IPNetwork.Parse).ToArray();
    }

    internal bool Matches(string method, string normalizedPath, string normalizedQuery, string? normalizedReferer, IPAddress? source)
    {
        if (!Enabled)
        {
            return false;
        }

        if (Methods.Length > 0 && !Methods.Contains(method, StringComparer.OrdinalIgnoreCase))
        {
            return false;
        }

        if (pathRegex is not null && !pathRegex.IsMatch(normalizedPath))
        {
            return false;
        }

        if (queryRegex is not null && !queryRegex.IsMatch(normalizedQuery))
        {
            return false;
        }

        if (refererRegex is not null && (normalizedReferer is null || !refererRegex.IsMatch(normalizedReferer)))
        {
            return false;
        }

        return source is null || !allowedNetworks.Any(network => network.Contains(source));
    }

    private static Regex? Build(string? pattern) =>
        pattern is null
            ? null
            : new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled, RegexTimeout);
}

/// <summary>
/// The full rule configuration, normally loaded from rules.json.
/// </summary>
public sealed class RuleSet
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    /// <summary>Block requests carrying an unsigned ("alg": "none") JWT (CVE-2023-29357).</summary>
    public bool BlockUnsignedJwt { get; init; } = true;

    public List<GuardRule> Rules { get; init; } = [];

    public static RuleSet Load(string path) => Parse(File.ReadAllText(path));

    public static RuleSet Parse(string json)
    {
        RuleSet ruleSet = JsonSerializer.Deserialize<RuleSet>(json, JsonOptions)
            ?? throw new InvalidOperationException("Rule file is empty.");

        var duplicate = ruleSet.Rules.GroupBy(r => r.Id, StringComparer.OrdinalIgnoreCase).FirstOrDefault(g => g.Count() > 1);
        if (duplicate is not null)
        {
            throw new InvalidOperationException($"Duplicate rule id '{duplicate.Key}'.");
        }

        foreach (GuardRule rule in ruleSet.Rules)
        {
            rule.Compile();
        }

        return ruleSet;
    }
}
