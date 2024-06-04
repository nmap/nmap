local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

description = [[
Checks if a machine is vulnerable to MS12-020 RDP vulnerability.

The Microsoft bulletin MS12-020 patches two vulnerabilities: CVE-2012-0152
which addresses a denial of service vulnerability inside Terminal Server, and
CVE-2012-0002 which fixes a vulnerability in Remote Desktop Protocol. Both are
part of Remote Desktop Services.

The script works by checking for the CVE-2012-0152 vulnerability. If this
vulnerability is not patched, it is assumed that CVE-2012-0002 is not patched
either. This script can do its check without crashing the target.

The way this works follows:
* Send one user request. The server replies with a user id (call it A) and a channel for that user.
* Send another user request. The server replies with another user id (call it B) and another channel.
* Send a channel join request with requesting user set to A and requesting channel set to B. If the server replies with a success message, we conclude that the server is vulnerable.
* In case the server is vulnerable, send a channel join request with the requesting user set to B and requesting channel set to B to prevent the chance of a crash.

References:
* http://technet.microsoft.com/en-us/security/bulletin/ms12-020
* http://support.microsoft.com/kb/2621440
* http://zerodayinitiative.com/advisories/ZDI-12-044/
* http://aluigi.org/adv/termdd_1-adv.txt

Original check by by Worawit Wang (sleepya).
]]

---
-- @usage
-- nmap -sV --script=rdp-vuln-ms12-020 -p 3389 <target>
--
-- @output
-- PORT     STATE SERVICE        VERSION
-- 3389/tcp open  ms-wbt-server?
-- | rdp-vuln-ms12-020:
-- |   VULNERABLE:
-- |   MS12-020 Remote Desktop Protocol Denial Of Service Vulnerability
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2012-0152
-- |     Risk factor: Medium  CVSSv2: 4.3 (MEDIUM) (AV:N/AC:M/Au:N/C:N/I:N/A:P)
-- |     Description:
-- |               Remote Desktop Protocol vulnerability that could allow remote attackers to cause a denial of service.
-- |
-- |     Disclosure date: 2012-03-13
-- |     References:
-- |       http://technet.microsoft.com/en-us/security/bulletin/ms12-020
-- |       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0152
-- |
-- |   MS12-020 Remote Desktop Protocol Remote Code Execution Vulnerability
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2012-0002
-- |     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
-- |     Description:
-- |               Remote Desktop Protocol vulnerability that could allow remote attackers to execute arbitrary code on the targeted system.
-- |
-- |     Disclosure date: 2012-03-13
-- |     References:
-- |       http://technet.microsoft.com/en-us/security/bulletin/ms12-020
-- |_      http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0002

author = "Aleksandar Nikolic"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln"}


portrule = shortport.port_or_service({3389},{"ms-wbt-server"})

-- see http://msdn.microsoft.com/en-us/library/cc240836%28v=prot.10%29.aspx for more info
local connectionRequest = "\x03\x00" -- TPKT Header version 03, reserved 0
.. "\x00\x0b" -- Length
.. "\x06"   -- X.224 Data TPDU length
.. "\xe0"    -- X.224 Type (Connection request)
.. "\x00\x00" -- dst reference
.. "\x00\x00" -- src reference
.. "\x00" -- class and options

-- see http://msdn.microsoft.com/en-us/library/cc240836%28v=prot.10%29.aspx
local connectInitial = "\x03\x00\x00\x65" -- TPKT Header
.. "\x02\xf0\x80" -- Data TPDU, EOT
.. "\x7f\x65\x5b" -- Connect-Initial
.. "\x04\x01\x01" -- callingDomainSelector
.. "\x04\x01\x01" -- calledDomainSelector
.. "\x01\x01\xff" -- upwardFlag
.. "\x30\x19" -- targetParams + size
..  "\x02\x01\x22" -- maxChannelIds
..  "\x02\x01\x20" -- maxUserIds
..  "\x02\x01\x00" -- maxTokenIds
..  "\x02\x01\x01" -- numPriorities
..  "\x02\x01\x00" -- minThroughput
..  "\x02\x01\x01" -- maxHeight
..  "\x02\x02\xff\xff" -- maxMCSPDUSize
..  "\x02\x01\x02" -- protocolVersion
.. "\x30\x18" -- minParams + size
.. "\x02\x01\x01" -- maxChannelIds
.. "\x02\x01\x01" -- maxUserIds
.. "\x02\x01\x01" -- maxTokenIds
.. "\x02\x01\x01" -- numPriorities
.. "\x02\x01\x00" -- minThroughput
.. "\x02\x01\x01" -- maxHeight
.. "\x02\x01\xff" -- maxMCSPDUSize
.. "\x02\x01\x02" -- protocolVersion
.. "\x30\x19" -- maxParams + size
.. "\x02\x01\xff" -- maxChannelIds
.. "\x02\x01\xff" -- maxUserIds
.. "\x02\x01\xff" -- maxTokenIds
.. "\x02\x01\x01" -- numPriorities
.. "\x02\x01\x00" -- minThroughput
.. "\x02\x01\x01" -- maxHeight
.. "\x02\x02\xff\xff" -- maxMCSPDUSize
.. "\x02\x01\x02" -- protocolVersion
.. "\x04\x00" -- userData

-- see http://msdn.microsoft.com/en-us/library/cc240835%28v=prot.10%29.aspx
local userRequest = "\x03\x00" -- header
.. "\x00\x08" -- length
.. "\x02\xf0\x80" -- X.224 Data TPDU (2 bytes: 0xf0 = Data TPDU, 0x80 = EOT, end of transmission)
.. "\x28" -- PER encoded PDU contents

local function do_check(host, port)
  local is_vuln = false
  local socket = nmap.new_socket()
  -- If any socket call fails, bail.
  local catch = function ()
    socket:close()
  end
  local try = nmap.new_try(catch)

  try(socket:connect(host, port))
  try(socket:send(connectionRequest))

  local rdp_banner = "\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00"
  local response = try(socket:receive_bytes(#rdp_banner))
  if response ~= rdp_banner then
    --probably not rdp at all
    stdnse.debug1("not RDP")
    return false
  end
  try(socket:send(connectInitial))
  try(socket:send(userRequest))  -- send attach user request
  response = try(socket:receive_bytes(12)) -- receive attach user confirm
  local user1 = string.unpack(">I2", response, 10) -- user_channel-1001 - see http://msdn.microsoft.com/en-us/library/cc240918%28v=prot.10%29.aspx

  try(socket:send(userRequest)) -- send another attach user request
  response = try(socket:receive_bytes(12)) -- receive another attach user confirm
  local user2 = string.unpack(">I2", response, 10) -- second user's channel - 1001
  user2 = user2+1001 -- second user's channel
  local data4 = string.pack(">I2I2", user1, user2)
  local data5 = "\x03\x00\x00\x0c\x02\xf0\x80\x38" -- channel join request TPDU
  local channelJoinRequest = data5 .. data4
  try(socket:send(channelJoinRequest)) -- bogus channel join request user1 requests channel of user2
  response = try(socket:receive_bytes(9))
  if response:sub(8,9) == "\x3e\x00" then
    -- 3e00 indicates a successful join
    -- see http://msdn.microsoft.com/en-us/library/cc240911%28v=prot.10%29.aspx
    -- service is vulnerable
    is_vuln = true
    -- send a valid request to prevent the BSoD
    data4 = string.pack(">I2I2", user2 - 1001, user2)
    channelJoinRequest = data5 .. data4 -- valid join request
    -- Don't bother checking these; we know it's vulnerable and are just cleaning up.
    socket:send(channelJoinRequest)
    local _, _ = socket:receive_bytes(0)
  end
  socket:close()
  return is_vuln
end

action = function(host, port)
  local rdp_vuln_0152  = {
    title = "MS12-020 Remote Desktop Protocol Denial Of Service Vulnerability",
    IDS = {CVE = 'CVE-2012-0152'},
    risk_factor = "Medium",
    scores = {
      CVSSv2 = "4.3 (MEDIUM) (AV:N/AC:M/Au:N/C:N/I:N/A:P)",
    },
    description = [[
    Remote Desktop Protocol vulnerability that could allow remote attackers to cause a denial of service.
    ]],
    references = {
      'http://technet.microsoft.com/en-us/security/bulletin/ms12-020',
    },
    dates = {
      disclosure = {year = '2012', month = '03', day = '13'},
    },
    exploit_results = {},
  }

  local rdp_vuln_0002 = {
    title = "MS12-020 Remote Desktop Protocol Remote Code Execution Vulnerability",
    IDS = {CVE = 'CVE-2012-0002'},
    risk_factor = "High",
    scores = {
      CVSSv2 = "9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)",
    },
    description = [[
    Remote Desktop Protocol vulnerability that could allow remote attackers to execute arbitrary code on the targeted system.
    ]],
    references = {
      'http://technet.microsoft.com/en-us/security/bulletin/ms12-020',
    },
    dates = {
      disclosure = {year = '2012', month = '03', day = '13'},
    },
    exploit_results = {},
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  rdp_vuln_0152.state = vulns.STATE.NOT_VULN
  rdp_vuln_0002.state = vulns.STATE.NOT_VULN

  -- Sleep for 0.2 seconds to make sure the script works even with SYN scan.
  -- Posible reason for this is that Windows resets the connection if we try to
  -- reconnect too fast to the same port after doing a SYN scan and not completing the
  -- handshake. In my tests, sleep values above 0.1s prevent the connection reset.
  stdnse.sleep(0.2)

  local status, is_vuln = pcall(do_check, host, port)
  if not status then
    -- A socket or data unpacking error means the POC didn't work as expected
    -- Report the error in case we actually need to fix something.
    -- Kinda wish we had a LIKELY_NOT_VULN
    local result = ("Server response not as expected: %s"):format(is_vuln)
    rdp_vuln_0152.check_results = result
    rdp_vuln_0002.check_results = result
  elseif is_vuln then
    rdp_vuln_0152.state = vulns.STATE.VULN
    rdp_vuln_0002.state = vulns.STATE.VULN
  end

  return report:make_output(rdp_vuln_0152,rdp_vuln_0002)
end
