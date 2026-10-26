using NUnit.Framework;

namespace SharePointGuard.Tests;

public class PathNormalizerTests
{
    [TestCase(null, "/")]
    [TestCase("", "/")]
    [TestCase("/", "/")]
    [TestCase("/_layouts/15/ToolPane.aspx", "/_layouts/15/toolpane.aspx")]
    [TestCase("/_layouts/15/ToolPane%2easpx", "/_layouts/15/toolpane.aspx")]
    [TestCase("/_layouts/15/ToolPane%252easpx", "/_layouts/15/toolpane.aspx")]
    [TestCase("/_layouts/15%5CToolPane.aspx", "/_layouts/15/toolpane.aspx")]
    [TestCase("/_layouts//15/./x/../ToolPane.aspx", "/_layouts/15/toolpane.aspx")]
    [TestCase("/../../_layouts/15/ToolPane.aspx", "/_layouts/15/toolpane.aspx")]
    [TestCase("/_layouts/15/ToolPane.aspx.", "/_layouts/15/toolpane.aspx")]
    [TestCase("/_layouts/15/ToolPane.aspx%20", "/_layouts/15/toolpane.aspx")]
    [TestCase("/_layouts/15/ToolPane.aspx?a=b", "/_layouts/15/toolpane.aspx")]
    [TestCase("/sites/hr/Shared%20Documents/", "/sites/hr/shared documents")]
    public void Normalize(string? input, string expected)
    {
        Assert.That(PathNormalizer.Normalize(input), Is.EqualTo(expected));
    }
}
