local nmap = require('nmap')
local shortport = require('shortport')
local sslcert = require('sslcert')
local stdnse = require('stdnse')
local table = require('table')
local vulns = require('vulns')
local have_tls, tls = pcall(require,'tls')

assert(have_tls,
  "This script requires tls.lua from https://nmap.org/nsedoc/lib/tls.html")

description = [[
Detects whether a server is vulnerable to the SSL/TLS "CCS Injection"
vulnerability (CVE-2014-0224), first discovered by Masashi Kikuchi.
The script is based on the ccsinjection.c code authored by Ramon de C Valle
(https://gist.github.com/rcvalle/71f4b027d61a78c42607)

In order to exploit the vulnerablity, a MITM attacker would effectively
do the following:

    o Wait for a new TLS connection, followed by the ClientHello
      ServerHello handshake messages.

    o Issue a CCS packet in both the directions, which causes the OpenSSL
      code to use a zero length pre master secret key. The packet is sent
      to both ends of the connection. Session Keys are derived using a
      zero length pre master secret key, and future session keys also
      share this weakness.

    o Renegotiate the handshake parameters.

    o The attacker is now able to decrypt or even modify the packets
      in transit.

The script works by sending a 'ChangeCipherSpec' message out of order and
checking whether the server returns an 'UNEXPECTED_MESSAGE' alert record
or not. Since a non-patched server would simply accept this message, the
CCS packet is sent twice, in order to force an alert from the server. If
the alert type is different than 'UNEXPECTED_MESSAGE', we can conclude
the server is vulnerable.
]]

---
-- @usage
-- nmap -p 443 --script ssl-ccs-injection <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | ssl-ccs-injection:
-- |   VULNERABLE:
-- |   SSL/TLS MITM vulnerability (CCS Injection)
-- |     State: VULNERABLE
-- |     Risk factor: High
-- |     Description:
-- |       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before
-- |       1.0.1h does not properly restrict processing of ChangeCipherSpec
-- |       messages, which allows man-in-the-middle attackers to trigger use
-- |       of a zero-length master key in certain OpenSSL-to-OpenSSL
-- |       communications, and consequently hijack sessions or obtain
-- |       sensitive information, via a crafted TLS handshake, aka the
-- |       "CCS Injection" vulnerability.
-- |
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
-- |       http://www.cvedetails.com/cve/2014-0224
-- |_      http://www.openssl.org/news/secadv_20140605.txt

author = "Claudiu Perta <claudiu.perta@gmail.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "vuln", "safe" }


portrule = function(host, port)
 return shortport.ssl(host, port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

local Error = {
  NOT_VULNERABLE    = 0,
  CONNECT           = 1,
  PROTOCOL_MISMATCH = 2,
  SSL_HANDSHAKE     = 3,
  TIMEOUT           = 4
}

---
-- Reads an SSL/TLS record and returns true if it's a fatal,
-- 'unexpected_message' alert and false otherwise.
local function alert_unexpected_message(s)
  local status, buffer
  status, buffer = tls.record_buffer(s, buffer, 1)
  if not status then
    return false
  end

  local position, record = tls.record_read(buffer, 1)
  if record == nil then
    return false
  end

  if record.type ~= "alert" then
    -- Mark this as VULNERABLE, we expect an alert record
    return true,true
  end

  for _, body in ipairs(record.body) do
    if body.level == "fatal" and body.description == "unexpected_message" then
      return true,false
    end
  end

  return true,true
end

local function test_ccs_injection(host, port, version)
  local hello = tls.client_hello({
      ["protocol"] = version,
      -- Claim to support every cipher
      -- Doesn't work with IIS, but IIS isn't vulnerable
      ["ciphers"] = stdnse.keys(tls.CIPHERS),
      ["compressors"] = {"NULL"},
      ["extensions"] = {
        -- Claim to support every elliptic curve
        ["elliptic_curves"] = tls.EXTENSION_HELPERS["elliptic_curves"](
          stdnse.keys(tls.ELLIPTIC_CURVES)),
        -- Claim to support every EC point format
        ["ec_point_formats"] = tls.EXTENSION_HELPERS["ec_point_formats"](
          stdnse.keys(tls.EC_POINT_FORMATS)),
      },
    })

  local status, err
  local s
  local specialized = sslcert.getPrepareTLSWithoutReconnect(port)
  if specialized then
    status, s = specialized(host, port)
    if not status then
      stdnse.debug3("Connection to server failed: %s", s)
      return false, Error.CONNECT
    end
  else
    s = nmap.new_socket()
    status, err = s:connect(host, port)
    if not status then
      stdnse.debug3("Connection to server failed: %s", err)
      return false, Error.CONNECT
    end
  end

  -- Set a sufficiently large timeout
  s:set_timeout(10000)

  -- Send Client Hello to the target server
  status, err = s:send(hello)
  if not status then
    stdnse.debug1("Couldn't send Client Hello: %s", err)
    s:close()
    return false, Error.CONNECT
  end

  -- Read response
  local done = false
  local i = 1
  local response
  repeat
    status, response, err = tls.record_buffer(s, response, i)
    if err == "TIMEOUT" or not status then
      stdnse.verbose1("No response from server: %s", err)
      s:close()
      return false, Error.TIMEOUT
    end

    local record
    i, record = tls.record_read(response, i)
    if record == nil then
      stdnse.debug1("Unknown response from server")
      s:close()
      return false, Error.NOT_VULNERABLE
    elseif record.protocol ~= version then
      stdnse.debug1("Protocol version mismatch (%s)", version)
      s:close()
      return false, Error.PROTOCOL_MISMATCH
    end

    if record.type == "handshake" then
      for _, body in ipairs(record.body) do
        if body.type == "server_hello_done" then
          stdnse.debug1("Handshake completed (%s)", version)
          done = true
        end
      end
    end
  until done

  -- Send the change_cipher_spec message twice to
  -- force an alert in the case the server is not
  -- patched.

  -- change_cipher_spec message
  local ccs = tls.record_write(
    "change_cipher_spec", version, "\x01")

  -- Send the first ccs message
  status, err = s:send(ccs)
  if not status then
    stdnse.debug1("Couldn't send first ccs message: %s", err)
    s:close()
    return false, Error.SSL_HANDSHAKE
  end

  -- Send the second ccs message
  status, err = s:send(ccs)
  if not status then
    stdnse.debug1("Couldn't send second ccs message: %s", err)
    s:close()
    return false, Error.SSL_HANDSHAKE
  end

  -- Read the alert message
  local vulnerable
  status,vulnerable = alert_unexpected_message(s)

  -- Leave the target not vulnerable in case of an error. This could occur
  -- when running against a different TLS/SSL implementations (e.g., GnuTLS)
  if not status then
    stdnse.debug1("Couldn't get reply from the server (probably not OpenSSL)")
    s:close()
    return false, Error.SSL_HANDSHAKE
  end

  if not vulnerable then
    stdnse.debug1("Server returned UNEXPECTED_MESSAGE alert, not vulnerable")
    s:close()
    return false, Error.NOT_VULNERABLE
  else
    stdnse.debug1("Vulnerable - alert is not UNEXPECTED_MESSAGE")
    s:close()
    return true
  end
end

action = function(host, port)
  local vuln_table = {
    title = "SSL/TLS MITM vulnerability (CCS Injection)",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    description = [[
OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
does not properly restrict processing of ChangeCipherSpec messages,
which allows man-in-the-middle attackers to trigger use of a zero
length master key in certain OpenSSL-to-OpenSSL communications, and
consequently hijack sessions or obtain sensitive information, via
a crafted TLS handshake, aka the "CCS Injection" vulnerability.
    ]],
    references = {
      'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224',
      'http://www.cvedetails.com/cve/2014-0224',
      'http://www.openssl.org/news/secadv_20140605.txt'
    }
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  -- Iterate over tls.PROTOCOLS
  for tls_version, _ in pairs(tls.PROTOCOLS) do
    local vulnerable, err = test_ccs_injection(host, port, tls_version)

    -- Return an explicit message in case of a TIMEOUT,
    -- to avoid considering this as not vulnerable.
    if err == Error.TIMEOUT then
      return "No reply from server (TIMEOUT)"
    end

    if err ~= Error.PROTOCOL_MISMATCH then
      if vulnerable then
        vuln_table.state = vulns.STATE.VULN
      end
      break
    end
  end

  return report:make_output(vuln_table)
end
