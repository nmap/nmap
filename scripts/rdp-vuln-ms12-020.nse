local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
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

action = function(host, port)
  local socket = nmap.new_socket()
  local status, err,response

  -- see http://msdn.microsoft.com/en-us/library/cc240836%28v=prot.10%29.aspx for more info
  local connectionRequestStr = "0300" -- TPKT Header version 03, reserved 0
  .. "000b" -- Length
  .. "06"   -- X.224 Data TPDU length
  .. "e0"    -- X.224 Type (Connection request)
  .. "0000" -- dst reference
  .. "0000" -- src reference
  .. "00" -- class and options
  local connectionRequest = stdnse.fromhex(connectionRequestStr)

  -- see http://msdn.microsoft.com/en-us/library/cc240836%28v=prot.10%29.aspx
  local connectInitialStr = "03000065" -- TPKT Header
  .. "02f080" -- Data TPDU, EOT
  .. "7f655b" -- Connect-Initial
  .. "040101" -- callingDomainSelector
  .. "040101" -- calledDomainSelector
  .. "0101ff" -- upwardFlag
  .. "3019" -- targetParams + size
  ..  "020122" -- maxChannelIds
  ..  "020120" -- maxUserIds
  ..  "020100" -- maxTokenIds
  ..  "020101" -- numPriorities
  ..  "020100" -- minThroughput
  ..  "020101" -- maxHeight
  ..  "0202ffff" -- maxMCSPDUSize
  ..  "020102" -- protocolVersion
  .. "3018" -- minParams + size
  .. "020101" -- maxChannelIds
  .. "020101" -- maxUserIds
  .. "020101" -- maxTokenIds
  .. "020101" -- numPriorities
  .. "020100" -- minThroughput
  .. "020101" -- maxHeight
  .. "0201ff" -- maxMCSPDUSize
  .. "020102" -- protocolVersion
  .. "3019" -- maxParams + size
  .. "0201ff" -- maxChannelIds
  .. "0201ff" -- maxUserIds
  .. "0201ff" -- maxTokenIds
  .. "020101" -- numPriorities
  .. "020100" -- minThroughput
  .. "020101" -- maxHeight
  .. "0202ffff" -- maxMCSPDUSize
  .. "020102" -- protocolVersion
  .. "0400" -- userData
  local connectInitial = stdnse.fromhex(connectInitialStr)

  -- see http://msdn.microsoft.com/en-us/library/cc240835%28v=prot.10%29.aspx
  local userRequestStr = "0300" -- header
  .. "0008" -- length
  .. "02f080" -- X.224 Data TPDU (2 bytes: 0xf0 = Data TPDU, 0x80 = EOT, end of transmission)
  .. "28" -- PER encoded PDU contents
  local userRequest = stdnse.fromhex(userRequestStr)

  local user1,user2
  local pos

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

  socket:connect(host.ip, port)
  status, err = socket:send(connectionRequest)

  status, response = socket:receive_bytes(0)
  if response ~= stdnse.fromhex("0300000b06d00000123400") then
    --probably not rdp at all
    stdnse.debug1("not RDP")
    return nil
  end
  status, err = socket:send(connectInitial)
  status, err = socket:send(userRequest)  -- send attach user request
  status, response = socket:receive_bytes(0) -- receive attach user confirm
  pos,user1 = bin.unpack(">S",response:sub(10,11)) -- user_channel-1001 - see http://msdn.microsoft.com/en-us/library/cc240918%28v=prot.10%29.aspx

  status, err = socket:send(userRequest) -- send another attach user request
  status, response = socket:receive_bytes(0) -- receive another attach user confirm
  pos,user2 = bin.unpack(">S",response:sub(10,11)) -- second user's channel - 1001
  user2 = user2+1001 -- second user's channel
  local data4 = bin.pack(">SS",user1,user2)
  local data5 = stdnse.fromhex("0300000c02f08038") -- channel join request TPDU
  local channelJoinRequest = data5 .. data4
  status, err = socket:send(channelJoinRequest) -- bogus channel join request user1 requests channel of user2
  status, response = socket:receive_bytes(0)
  if response:sub(8,9) == stdnse.fromhex("3e00") then
    -- 3e00 indicates a successful join
    -- see http://msdn.microsoft.com/en-us/library/cc240911%28v=prot.10%29.aspx
    -- service is vulnerable
    -- send a valid request to prevent the BSoD
    data4 = bin.pack(">SS",user2-1001,user2)
    channelJoinRequest = data5 .. data4 -- valid join request
    status, err = socket:send(channelJoinRequest)
    status, response = socket:receive_bytes(0)
    socket:close()
    rdp_vuln_0152.state = vulns.STATE.VULN
    rdp_vuln_0002.state = vulns.STATE.VULN
    return report:make_output(rdp_vuln_0152,rdp_vuln_0002)
  end
  --service is not vulnerable
  socket:close()
  return report:make_output(rdp_vuln_0152,rdp_vuln_0002)
end
