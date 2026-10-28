#!/usr/bin/env bash
# Sends allowed and malicious requests through HAProxy and checks the status codes.
# Usage: ./test.sh [base-url]    (default: http://localhost:3000)
set -u

BASE="${1:-http://localhost:3000}"
UNSIGNED_JWT="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhdWQiOiIwMDAwMDAwMy0wMDAwLTBmZjEtY2UwMC0wMDAwMDAwMDAwMDAifQ."
pass=0
fail=0

check() {
  local expected="$1" name="$2"
  shift 2
  local actual
  actual=$(curl -s -o /dev/null -w '%{http_code}' --path-as-is "$@")
  if [[ "$actual" == "$expected" ]]; then
    printf '  PASS  %-3s %s\n' "$actual" "$name"
    pass=$((pass + 1))
  else
    printf '  FAIL  %-3s %s (expected %s)\n' "$actual" "$name" "$expected"
    fail=$((fail + 1))
  fi
}

echo "Allowed requests"
check 200 "home page"                         "$BASE/"
check 200 "site page"                         "$BASE/sites/hr/SitePages/Home.aspx"
check 200 "document library"                  "$BASE/sites/hr/Shared%20Documents/report.docx"
check 200 "REST: current web"                 "$BASE/_api/web?\$select=Title"
check 200 "CSOM ProcessQuery"                 -X POST "$BASE/_vti_bin/client.svc/ProcessQuery"
check 200 "Lists.asmx (no wsdl)"              -X POST "$BASE/_vti_bin/Lists.asmx"
check 200 "sign-out page itself"              "$BASE/_layouts/15/SignOut.aspx"
check 200 "GET with SignOut referer"          -H "Referer: $BASE/_layouts/SignOut.aspx" "$BASE/_layouts/15/start.aspx"
check 200 "signed JWT"                        -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.c2ln" "$BASE/_api/web"

echo "Blocked requests"
check 403 "ToolShell ToolPane.aspx"           -X POST "$BASE/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx"
check 403 "ToolPane.aspx, lower case"         "$BASE/_layouts/15/toolpane.aspx"
check 403 "ToolPane.aspx, %2e encoded"        "$BASE/_layouts/15/ToolPane%2easpx"
check 403 "ToolPane.aspx, double encoded"     "$BASE/_layouts/15/ToolPane%252easpx"
check 403 "ToolPane.aspx, dot segments"       "$BASE/_layouts/15/x/../ToolPane.aspx"
check 403 "ToolPane.aspx, backslash"          "$BASE/_layouts/15%5cToolPane.aspx"
check 403 "ToolPane.aspx, trailing dot"       "$BASE/_layouts/15/ToolPane.aspx."
check 403 "ToolPane.aspx, site-relative"      "$BASE/sites/hr/_layouts/15/ToolPane.aspx"
check 403 "POST with SignOut referer"         -X POST -H "Referer: /_layouts/SignOut.aspx" "$BASE/_layouts/15/start.aspx"
check 403 "spinstall0.aspx web shell"         "$BASE/_layouts/15/spinstall0.aspx"
check 403 "Central Admin"                     "$BASE/_admin/operations.aspx"
check 403 "Picker.aspx"                       "$BASE/_layouts/15/Picker.aspx"
check 403 "QuickLinks DataSet"                "$BASE/_layouts/15/quicklinksdialogform.aspx"
check 403 "Site permissions page"             "$BASE/_layouts/15/user.aspx"
check 403 "Site contents"                     "$BASE/sites/hr/_layouts/15/viewlsts.aspx"
check 403 "UserGroup.asmx"                    -X POST "$BASE/_vti_bin/UserGroup.asmx"
check 403 "WSDL disclosure"                   "$BASE/_vti_bin/Lists.asmx?WSDL"
check 403 "spdisco.aspx"                      "$BASE/_vti_bin/spdisco.aspx"
check 403 "FrontPage author.dll"              -X POST "$BASE/_vti_bin/_vti_aut/author.dll"
check 403 "_vti_pvt"                          "$BASE/_vti_pvt/service.cnf"
check 403 "REST site users"                   "$BASE/_api/web/siteusers"
check 403 "REST site users, encoded"          "$BASE/_api/web/%73iteusers"
check 403 "ListData.svc"                      "$BASE/_vti_bin/listdata.svc/UserInformationList"
check 403 "User Information List"             "$BASE/_catalogs/users/simple.aspx"
check 403 "BDC metadata upload"               -X POST "$BASE/BusinessDataMetadataCatalog/BDCMetadata.bdcm"
check 403 "Unsigned JWT (Authorization)"      -H "Authorization: Bearer $UNSIGNED_JWT" "$BASE/_api/web"
check 403 "Unsigned JWT (X-PROOF_TOKEN)"      -H "X-PROOF_TOKEN: $UNSIGNED_JWT" "$BASE/_api/web"

echo
echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
