local ipmi = require "ipmi"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

description = [[
  IPMI 2.0 Cipher Zero Authentication Bypass Scanner. This module identifies IPMI 2.0
  compatible systems that are vulnerable to an authentication bypass vulnerability
  through the use of cipher zero.
]]

---
-- @usage
-- nmap -sU --script ipmi-cipher-zero -p 623 <host>
--
-- @output
---PORT      STATE         SERVICE REASON
-- 623/udp open|filtered unknown no-response
-- | ipmi-cipher-zero:
-- |   VULNERABLE:
-- |   IPMI 2.0 RAKP Cipher Zero Authentication Bypass
-- |     State: VULNERABLE
-- |     Risk factor: High
-- |     Description:
-- |
-- |       The issue is due to the vendor shipping their devices with the
-- |       cipher suite '0' (aka 'cipher zero') enabled. This allows a
-- |       remote attacker to authenticate to the IPMI interface using
-- |       an arbitrary password. The only information required is a valid
-- |       account, but most vendors ship with a default 'admin' account.
-- |       This would allow an attacker to have full control over the IPMI
-- |       functionality.
-- |
-- |     References:
-- |       http://fish2.com/ipmi/cipherzero.html
-- |       http://osvdb.org/show/osvdb/93039
-- |_      http://osvdb.org/show/osvdb/93040
--

author = "Claudiu Perta <claudiu.perta@gmail.com>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(623, "asf-rmcp", "udp", {"open", "open|filtered"})

action = function(host, port)

  local vuln_table = {
    title = "IPMI 2.0 RAKP Cipher Zero Authentication Bypass",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    description = [[

The issue is due to the vendor shipping their devices with the
cipher suite '0' (aka 'cipher zero') enabled. This allows a
remote attacker to authenticate to the IPMI interface using
an arbitrary password. The only information required is a valid
account, but most vendors ship with a default 'admin' account.
This would allow an attacker to have full control over the IPMI
functionality
    ]],
    references = {
      'http://fish2.com/ipmi/cipherzero.html',
      'http://osvdb.org/show/osvdb/93040',
      'http://osvdb.org/show/osvdb/93039',
    }
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  local request = ipmi.session_open_cipher_zero_request()

  local socket = nmap.new_socket()
  socket:set_timeout(
      ((host.times and host.times.timeout) or 8) * 1000)
  socket:connect(host, port, "udp")

  -- Send 3 probes
  local tries = 3
  repeat
    socket:send(request)
    tries = tries - 1
  until tries == 0

  local status, reply = socket:receive()
  socket:close()

  if not status then
    stdnse.debug1(string.format("No response (%s)", reply))
    return nil
  end

  nmap.set_port_state(host, port, "open")

  local info = ipmi.parse_open_session_reply(reply)
  if info["session_payload_type"] == ipmi.PAYLOADS["RMCPPLUSOPEN_REP"] then
    vuln_table.state = vulns.STATE.VULN
  end

  return report:make_output(vuln_table)

end
