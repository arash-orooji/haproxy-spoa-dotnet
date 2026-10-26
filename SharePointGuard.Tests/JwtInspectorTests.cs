using System.Text;
using NUnit.Framework;

namespace SharePointGuard.Tests;

public class JwtInspectorTests
{
    private static string Token(string headerJson) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(headerJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        + ".eyJhdWQiOiJ4In0.";

    [TestCase("{\"alg\":\"none\",\"typ\":\"JWT\"}")]
    [TestCase("{\"alg\":\"NONE\"}")]
    [TestCase("{\"alg\":\" none \"}")]
    [TestCase("{\"alg\":\"\"}")]
    [TestCase("{\"alg\":null}")]
    [TestCase("{\"typ\":\"JWT\"}")]
    public void Unsigned_tokens_are_detected(string headerJson)
    {
        Assert.That(JwtInspector.IsUnsigned("Bearer " + Token(headerJson)), Is.True);
        Assert.That(JwtInspector.IsUnsigned(Token(headerJson)), Is.True);
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("Basic dXNlcjpwYXNz")]
    [TestCase("NTLM TlRMTVNTUAABAAAAB4IIog==")]
    [TestCase("Bearer not-a-jwt")]
    [TestCase("Bearer !!!.e30.")]
    public void Non_jwt_values_are_ignored(string? value)
    {
        Assert.That(JwtInspector.IsUnsigned(value), Is.False);
    }

    [Test]
    public void Signed_tokens_are_allowed()
    {
        Assert.That(JwtInspector.IsUnsigned("Bearer " + Token("{\"alg\":\"RS256\",\"typ\":\"JWT\"}") + "c2ln"), Is.False);
    }
}
