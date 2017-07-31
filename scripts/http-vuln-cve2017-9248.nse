local http = require "http"
local shortport = require "shortport"
local string = require "string"
local stdnse = require "stdnse"
local url = require "url"
local vulns = require "vulns"

description = [[ 
Attempts to detect an encryption oracle in Progress Telerik UI for ASP.NET AJAX
that can lead to the compromise of the machine key and arbitrary file uploads.
The latter could subsequently lead to remote code execution.

The script attempts to access known URIs for subclasses of
Telerik.Web.UI.DialogHandlerNoSession, and if an instance is detected, the
script then attempts to send invalid ciphertext to the instance. If the response
contains a Base-64 related error, it is likely using a vulnerable version of the
library.

References:
http://www.telerik.com/support/kb/aspnet-ajax/details/cryptographic-weakness
]]

---
-- @usage
-- nmap --script http-vuln-cve2017-9248 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-vuln-cve2017-9248: 
-- |   VULNERABLE:
-- |   Progress Telerik UI for ASP.NET AJAX Cryptographic Weakness
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2017-9248
-- |     Risk factor: HIGH  CVSSv3: 9.8 (CRITICAL)
-- |       This cryptographic weakness can lead to the compromise of the machine key and
-- |       arbitrary file uploads, the latter of which could allow remote code execution.
-- |                     
-- |     References:
-- |       http://www.telerik.com/support/kb/aspnet-ajax/details/cryptographic-weakness
-- |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9248
--
-- @xmloutput
-- <table key="CVE-2017-9248">
-- <elem key="title">Progress Telerik UI for ASP.NET AJAX Cryptographic Weakness</elem>
-- <elem key="state">VULNERABLE</elem>
-- <table key="ids">
-- <elem>CVE:CVE-2017-9248</elem>
-- </table>
-- <table key="scores">
-- <elem key="CVSSv3">9.8 (CRITICAL)</elem>
-- </table>
-- <table key="description">
-- <elem>This cryptographic weakness can lead to the compromise of the machine key and&#xa;
-- arbitrary file uploads, the latter of which could allow remote code execution.&#xa;</elem>
-- </table>
-- <table key="refs">
-- <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9248</elem>
-- <elem>http://www.telerik.com/support/kb/aspnet-ajax/details/cryptographic-weakness</elem>
-- </table>
-- </table>
---

author = "Harrison Neal"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local uris = {
    '/Telerik.Web.UI.DialogHandler.aspx',
    '/DesktopModules/Admin/RadEditorProvider/DialogHandler.aspx'
  }

  for i, uri in ipairs(uris) do
    local rsp1 = http.get(host, port, uri, nil)

    if rsp1.status and rsp1.status == 200 then
      if rsp1.body and rsp1.body:find('Loading the dialog') then

        local rsp2 = http.get(host, port, uri .. '?dp=////', nil)

        if rsp2.status and rsp2.status == 200 then
          if rsp2.body and rsp2.body:find('Base%-64') then

            local report = vulns.Report:new(SCRIPT_NAME, host, port)
            local vuln_table = {
              title = 'Progress Telerik UI for ASP.NET AJAX Cryptographic Weakness',
              state = vulns.STATE.VULN,
              IDS = { CVE = 'CVE-2017-9248' },
              risk_factor = 'HIGH',
              scores = { CVSSv3 = '9.8 (CRITICAL)' },
              description = [[
This cryptographic weakness can lead to the compromise of the machine key and
arbitrary file uploads, the latter of which could allow remote code execution.
              ]],
              references = {
                'http://www.telerik.com/support/kb/aspnet-ajax/details/cryptographic-weakness'
              }
            }

            return report:make_output(vuln_table)

          end
        end
      end
    end
  end
end
