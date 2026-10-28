using System.Net;

namespace SharePointGuard;

/// <summary>
/// The parts of an HTTP request that HAProxy forwards to the agent.
/// </summary>
public sealed record RequestInfo(
    string Method,
    string Path,
    string? Query = null,
    string? Referer = null,
    string? Authorization = null,
    string? ProofToken = null,
    IPAddress? Source = null);

/// <summary>
/// The decision for a single request.
/// </summary>
public sealed record Verdict(bool Blocked, string? RuleId = null, string? Reason = null)
{
    public static readonly Verdict Allow = new(false);

    public static Verdict Block(string ruleId, string reason) => new(true, ruleId, reason);
}
