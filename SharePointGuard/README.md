# SharePoint Guard

An HAProxy SPOA (Stream Processing Offload Agent), built with this library on .NET 10. It blocks requests to sensitive and commonly exploited endpoints of **SharePoint Server Subscription Edition** before they reach the farm.

HAProxy sends the method, path, query string, `Referer`, `Authorization` and `X-PROOF_TOKEN` headers, and the client IP to the agent for every request. The agent checks them against [rules.json](rules.json). If a rule matches, it sets `txn.spguard.block` and `txn.spguard.rule`, and HAProxy answers `403 Forbidden` with the rule id in the `X-SPGuard-Rule` header.

Before matching, the agent canonicalizes paths the way IIS reads them, so common evasion tricks do not work:

| Evasion | Example | Normalized to |
|---|---|---|
| Case | `/_layouts/15/TOOLPANE.aspx` | `/_layouts/15/toolpane.aspx` |
| Percent / double encoding | `/_layouts/15/ToolPane%252easpx` | `/_layouts/15/toolpane.aspx` |
| Backslashes | `/_layouts/15%5CToolPane.aspx` | `/_layouts/15/toolpane.aspx` |
| Dot segments | `/_layouts/15/x/../ToolPane.aspx` | `/_layouts/15/toolpane.aspx` |
| Trailing dots / spaces | `/_layouts/15/ToolPane.aspx.` | `/_layouts/15/toolpane.aspx` |
| Site-relative URLs | `/sites/hr/_layouts/15/ToolPane.aspx` | matched (rules use `(^|/)`) |

## Default rules

| Rule id | Blocks |
|---|---|
| `SP-JWT-ALG-NONE` | Unsigned (`"alg": "none"`) JWT in `Authorization` or `X-PROOF_TOKEN` (CVE-2023-29357) |
| `SP-TOOLSHELL-SIGNOUT-REFERER` | State-changing requests with a spoofed `SignOut.aspx` Referer (CVE-2025-49706 / CVE-2025-53771) |
| `SP-TOOLSHELL-TOOLPANE` | `_layouts/ToolPane.aspx` (CVE-2025-49704 / CVE-2025-53770) |
| `SP-TOOLSHELL-WEBSHELL` | Known ToolShell web shells (`spinstall*.aspx`) |
| `SP-CENTRAL-ADMIN` | `/_admin/`, `/_vti_adm/` |
| `SP-PICKER-DESERIALIZATION` | `Picker.aspx` (CVE-2019-0604) |
| `SP-QUICKLINKS-DATASET` | `quicklinks.aspx`, `quicklinksdialogform.aspx` (CVE-2020-1147) |
| `SP-BDC-METADATA` | BDC model upload (`*.bdcm`, `BusinessDataMetadataCatalog`) (CVE-2023-24955) |
| `SP-SITE-ADMIN-PAGES` | Permission and site administration pages (`user.aspx`, `people.aspx`, `viewlsts.aspx`, `settings.aspx`, …) |
| `SP-LEGACY-SOAP-ENUM` | Enumeration SOAP services (`UserGroup.asmx`, `People.asmx`, `Permissions.asmx`, `SiteData.asmx`, `Webs.asmx`, …) |
| `SP-SERVICE-DISCOVERY` | `?wsdl` / `?disco` on `.asmx` / `.svc` services |
| `SP-SPDISCO` | `_vti_bin/spdisco.aspx` |
| `SP-FRONTPAGE-RPC` | FrontPage RPC (`author.dll`, `admin.dll`, `shtml.dll`), `_vti_pvt`, `_vti_inf.html` |
| `SP-REST-USER-ENUM` | `_api/web/siteusers`, `sitegroups`, `roleassignments`, `siteuserinfolist` |
| `SP-LISTDATA-ODATA` | Legacy `_vti_bin/listdata.svc` |
| `SP-USER-INFO-LIST` | Hidden User Information List (`_catalogs/users`) |

Some of these endpoints are used legitimately inside a corporate network: site admin pages, `Picker.aspx` in classic pages, Central Administration. Exempt your internal or admin networks with `allowFrom`, or turn a rule off with `"enabled": false`:

```json
{
  "id": "SP-SITE-ADMIN-PAGES",
  "path": "(^|/)_layouts/(\\d+/)?(user|people|settings)\\.aspx",
  "allowFrom": [ "10.0.0.0/8", "192.168.10.0/24" ]
}
```

A rule can match on `path`, `query`, `referer` (all regexes, case-insensitive, run against normalized values) and `methods`. A request matches a rule only when every condition the rule sets matches. Rules are checked in order, and the first match wins.

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `SPGUARD_PORT` | `12345` | TCP port the agent listens on |
| `SPGUARD_RULES` | `rules.json` next to the binary | Path to the rule file |
| `SPGUARD_DEBUG` | `false` | Log every frame and every allowed request |

HAProxy is set up to **fail closed**. If the agent is unreachable or does not answer within `timeout processing` (500 ms), the request is refused with `503`. To fail open instead, remove the `var(txn.spguard.error)` deny line in [haproxy/haproxy.cfg](haproxy/haproxy.cfg).

## Run it with Docker

The Compose file starts the agent and HAProxy 3.2 (LTS). In this test setup, HAProxy forwards allowed requests to a built-in mock that stands in for SharePoint and returns `200`. To protect a real farm, point `backend sharepoint_servers` at your SharePoint web front ends.

```shell
cd SharePointGuard
docker compose up -d --build
./test.sh                     # 9 allowed + 27 blocked requests
docker compose logs agent     # BLOCK rule=... lines
docker compose down
```

```text
$ curl -i --path-as-is 'http://localhost:8080/_layouts/15/ToolPane%252easpx'
HTTP/1.1 403 Forbidden
x-spguard-rule: SP-TOOLSHELL-TOOLPANE
content-type: text/plain

Blocked by SharePoint Guard (SP-TOOLSHELL-TOOLPANE)
```

## Unit tests

```shell
dotnet test SharePointGuard.Tests
```

> This agent reduces your attack surface, but it does not replace patching. Keep SharePoint Server on the latest cumulative update, enable AMSI, and rotate the machine keys if you were exposed to ToolShell.
