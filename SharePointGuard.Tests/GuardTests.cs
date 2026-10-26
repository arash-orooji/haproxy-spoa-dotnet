using System.Net;
using NUnit.Framework;

namespace SharePointGuard.Tests;

public class GuardTests
{
    private Guard guard = null!;

    [OneTimeSetUp]
    public void LoadShippedRules()
    {
        guard = new Guard(RuleSet.Load(Path.Combine(AppContext.BaseDirectory, "rules.json")));
    }

    [TestCase("GET", "/")]
    [TestCase("GET", "/sites/hr/SitePages/Home.aspx")]
    [TestCase("GET", "/_layouts/15/start.aspx")]
    [TestCase("GET", "/_layouts/15/SignOut.aspx")]
    [TestCase("GET", "/_api/web")]
    [TestCase("POST", "/_vti_bin/client.svc/ProcessQuery")]
    [TestCase("POST", "/_vti_bin/Lists.asmx")]
    public void Allows_normal_traffic(string method, string path)
    {
        Assert.That(guard.Evaluate(new RequestInfo(method, path)).Blocked, Is.False);
    }

    [TestCase("POST", "/_layouts/15/ToolPane.aspx", "SP-TOOLSHELL-TOOLPANE")]
    [TestCase("GET", "/sites/hr/_layouts/ToolPane.aspx", "SP-TOOLSHELL-TOOLPANE")]
    [TestCase("GET", "/_layouts/15/spinstall0.aspx", "SP-TOOLSHELL-WEBSHELL")]
    [TestCase("GET", "/_admin/operations.aspx", "SP-CENTRAL-ADMIN")]
    [TestCase("POST", "/_vti_adm/admin.asmx", "SP-CENTRAL-ADMIN")]
    [TestCase("GET", "/_layouts/15/Picker.aspx", "SP-PICKER-DESERIALIZATION")]
    [TestCase("GET", "/_layouts/15/quicklinks.aspx", "SP-QUICKLINKS-DATASET")]
    [TestCase("GET", "/_layouts/15/user.aspx", "SP-SITE-ADMIN-PAGES")]
    [TestCase("POST", "/_vti_bin/UserGroup.asmx", "SP-LEGACY-SOAP-ENUM")]
    [TestCase("GET", "/_vti_bin/spdisco.aspx", "SP-SPDISCO")]
    [TestCase("POST", "/_vti_bin/_vti_aut/author.dll", "SP-FRONTPAGE-RPC")]
    [TestCase("GET", "/_api/web/siteusers", "SP-REST-USER-ENUM")]
    [TestCase("GET", "/_vti_bin/listdata.svc", "SP-LISTDATA-ODATA")]
    [TestCase("GET", "/_catalogs/users/simple.aspx", "SP-USER-INFO-LIST")]
    public void Blocks_sensitive_endpoints(string method, string path, string ruleId)
    {
        Verdict verdict = guard.Evaluate(new RequestInfo(method, path));

        Assert.That(verdict.Blocked, Is.True);
        Assert.That(verdict.RuleId, Is.EqualTo(ruleId));
    }

    [TestCase("WSDL")]
    [TestCase("wsdl=1")]
    [TestCase("a=b&disco")]
    public void Blocks_wsdl_disclosure(string query)
    {
        Verdict verdict = guard.Evaluate(new RequestInfo("GET", "/_vti_bin/Lists.asmx", Query: query));

        Assert.That(verdict.RuleId, Is.EqualTo("SP-SERVICE-DISCOVERY"));
    }

    [TestCase("POST", "/_layouts/15/start.aspx", "https://sp.contoso.com/_layouts/SignOut.aspx", true)]
    [TestCase("POST", "/_layouts/15/start.aspx", "/_layouts/15/signout.aspx", true)]
    [TestCase("GET", "/_layouts/15/start.aspx", "https://sp.contoso.com/_layouts/SignOut.aspx", false)]
    [TestCase("POST", "/_layouts/15/SignOut.aspx", "https://sp.contoso.com/_layouts/15/SignOut.aspx", false)]
    [TestCase("POST", "/_layouts/15/start.aspx", "https://sp.contoso.com/SitePages/Home.aspx", false)]
    public void SignOut_referer_bypass(string method, string path, string referer, bool blocked)
    {
        Verdict verdict = guard.Evaluate(new RequestInfo(method, path, Referer: referer));

        Assert.That(verdict.Blocked, Is.EqualTo(blocked));
    }

    [Test]
    public void Blocks_unsigned_jwt()
    {
        var request = new RequestInfo("GET", "/_api/web", Authorization: "Bearer eyJhbGciOiJub25lIn0.e30.");

        Assert.That(guard.Evaluate(request).RuleId, Is.EqualTo(Guard.UnsignedJwtRuleId));
    }

    [Test]
    public void AllowFrom_exempts_trusted_networks()
    {
        var ruleSet = RuleSet.Parse("""
            { "rules": [ { "id": "ADMIN", "path": "(^|/)_admin/", "allowFrom": [ "10.0.0.0/8", "fd00::/8" ] } ] }
            """);
        var admin = new Guard(ruleSet);

        Assert.That(admin.Evaluate(new RequestInfo("GET", "/_admin/x", Source: IPAddress.Parse("10.1.2.3"))).Blocked, Is.False);
        Assert.That(admin.Evaluate(new RequestInfo("GET", "/_admin/x", Source: IPAddress.Parse("fd00::1"))).Blocked, Is.False);
        Assert.That(admin.Evaluate(new RequestInfo("GET", "/_admin/x", Source: IPAddress.Parse("203.0.113.7"))).Blocked, Is.True);
    }

    [Test]
    public void Disabled_rules_are_skipped()
    {
        var ruleSet = RuleSet.Parse("""{ "rules": [ { "id": "PICKER", "path": "picker\\.aspx", "enabled": false } ] }""");

        Assert.That(new Guard(ruleSet).Evaluate(new RequestInfo("GET", "/_layouts/15/picker.aspx")).Blocked, Is.False);
    }

    [Test]
    public void Invalid_rule_files_are_rejected()
    {
        Assert.Throws<InvalidOperationException>(() => RuleSet.Parse("""{ "rules": [ { "id": "EMPTY" } ] }"""));
        Assert.Throws<InvalidOperationException>(() => RuleSet.Parse("""{ "rules": [ { "id": "A", "path": "a" }, { "id": "a", "path": "b" } ] }"""));
    }
}
