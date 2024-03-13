local nmap = require "nmap"
local shortport = require "shortport"
local table = require "table"
local tableaux = require "tableaux"
local stdnse = require "stdnse"
local string = require "string"
local sslcert = require "sslcert"
local sslv2 = require "sslv2"
local vulns = require "vulns"

description = [[
Determines whether the server supports SSLv2, what ciphers it supports and tests for
CVE-2015-3197, CVE-2016-0703 and CVE-2016-0800 (DROWN)
]]
author = "Bertrand Bonnefoy-Claudet <bertrand@cryptosense.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
-- We can use the set of ciphers detected by sslv2.nse to avoid 1 handshake
dependencies = {"sslv2"}
categories = {"intrusive", "vuln"}

---
-- @output
-- 443/tcp open  https
-- | sslv2-drown:
-- |   ciphers:
-- |     SSL2_DES_192_EDE3_CBC_WITH_MD5
-- |     SSL2_IDEA_128_CBC_WITH_MD5
-- |     SSL2_RC2_128_CBC_WITH_MD5
-- |     SSL2_RC4_128_WITH_MD5
-- |     SSL2_DES_64_CBC_WITH_MD5
-- |   forced_ciphers:
-- |     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
-- |     SSL2_RC4_128_EXPORT40_WITH_MD5
-- |   vulns:
-- |     CVE-2016-0800:
-- |       title: OpenSSL: Cross-protocol attack on TLS using SSLv2 (DROWN)
-- |       state: VULNERABLE
-- |       ids:
-- |         CVE:CVE-2016-0800
-- |       description:
-- |               The SSLv2 protocol, as used in OpenSSL before 1.0.1s and 1.0.2 before 1.0.2g and
-- |       other products, requires a server to send a ServerVerify message before establishing
-- |       that a client possesses certain plaintext RSA data, which makes it easier for remote
-- |       attackers to decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding
-- |       oracle, aka a "DROWN" attack.
-- |
-- |       refs:
-- |         https://www.openssl.org/news/secadv/20160301.txt
-- |_        https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0800
--
-- @xmloutput
-- <table key="ciphers">
--   <elem>SSL2_DES_192_EDE3_CBC_WITH_MD5</elem>
--   <elem>SSL2_IDEA_128_CBC_WITH_MD5</elem>
--   <elem>SSL2_RC2_128_CBC_WITH_MD5</elem>
--   <elem>SSL2_RC4_128_WITH_MD5</elem>
--   <elem>SSL2_DES_64_CBC_WITH_MD5</elem>
-- </table>
-- <table key="forced_ciphers">
--   <elem>SSL2_RC2_128_CBC_EXPORT40_WITH_MD5</elem>
--   <elem>SSL2_RC4_128_EXPORT40_WITH_MD5</elem>
-- </table>
-- <table key="vulns">
--   <table key="CVE-2016-0800">
--     <elem key="title">OpenSSL: Cross-protocol attack on TLS using SSLv2 (DROWN)</elem>
--     <elem key="state">VULNERABLE</elem>
--     <table key="ids">
--       <elem>CVE:CVE-2016-0800</elem>
--     </table>
--     <table key="description">
--       <elem>
--         The SSLv2 protocol, as used in OpenSSL before 1.0.1s and 1.0.2 before
--         1.0.2g and other products, requires a server to send a ServerVerify
--         message before establishing that a client possesses certain plaintext
--         RSA data, which makes it easier for remote attackers to decrypt TLS
--         ciphertext data by leveraging a Bleichenbacher RSA padding oracle, aka
--         a "DROWN" attack.
--       </elem>
--     </table>
--     <table key="refs">
--       <elem>https://www.openssl.org/news/secadv/20160301.txt</elem>
--       <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0800</elem>
--     </table>
--   </table>
-- </table>


-- Those ciphers are weak enough to enable a "General DROWN" attack.
local GENERAL_DROWN_CIPHERS = {}
for k, v in pairs(sslv2.SSL_CIPHERS) do
  -- 40 bits or less, or single-DES (56 bits)
  if v.encrypted_key_length <= 5 or v.str:find("DES_64") then
    GENERAL_DROWN_CIPHERS[v.str] = true
  end
end

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

-- Return whether all values of "t1" are also values in "t2".
local function values_in(t1, t2)
  local set = {}
  for _, e in pairs(t2) do
    set[e] = true
  end
  for _, e in pairs(t1) do
    if not set[e] then
      return false
    end
  end
  return true
end

-- Create a socket ready to begin an SSL negotiation and send client_hello
local function do_setup(host, port)
  local timeout = stdnse.get_timeout(host, 10000, 5000)
  local status, socket, err
  local starttls = sslcert.getPrepareTLSWithoutReconnect(port)
  if starttls then
    status, socket = starttls(host, port)
    if not status then
      stdnse.debug(1, "Can't connect using STARTTLS: %s", socket)
      return nil
    end
  else
    socket = nmap.new_socket()
    socket:set_timeout(timeout)
    status, err = socket:connect(host, port)
    if not status then
      stdnse.debug(1, "Can't connect: %s", err)
      return nil
    end
  end
  socket:set_timeout(timeout)
  socket:send(sslv2.client_hello(tableaux.keys(sslv2.SSL_CIPHER_CODES)))
  local status, buffer = sslv2.record_buffer(socket)
  if not status then
    socket:close()
    return false
  end
  return socket, buffer
end

local function try_force_cipher(host, port, cipher)
  local socket, buffer = do_setup(host, port)
  if not socket then
    return false
  end

  local i, server_hello = sslv2.record_read(buffer)

  local code = sslv2.SSL_CIPHER_CODES[cipher]
  local key_length = sslv2.SSL_CIPHERS[code].key_length
  local encrypted_key_length = sslv2.SSL_CIPHERS[code].encrypted_key_length

  local dummy_key = string.rep("\0", key_length)
  local clear_key = dummy_key:sub(1, key_length - encrypted_key_length)
  local encrypted_key = dummy_key:sub(key_length - encrypted_key_length + 1)

  local dummy_client_master_key = sslv2.client_master_secret(cipher, clear_key, encrypted_key)
  socket:send(dummy_client_master_key)
  local status, buffer = sslv2.record_buffer(socket, buffer, i)
  socket:close()
  if not status then
    return false
  end
  local i, message = sslv2.record_read(buffer, i)

  -- Treat an error as a failure to force the cipher.
  if not message or message.message_type == sslv2.SSL_MESSAGE_TYPES.ERROR then
    return false
  end

  return true
end

local function has_extra_clear_bug(host, port, cipher)
  local socket, buffer = do_setup(host, port)
  if not socket then
    return false
  end

  local i, server_hello = sslv2.record_read(buffer)

  local code = sslv2.SSL_CIPHER_CODES[cipher]
  local key_length = sslv2.SSL_CIPHERS[code].key_length
  local encrypted_key_length = sslv2.SSL_CIPHERS[code].encrypted_key_length

  -- The length of clear_key is intentionally wrong to highlight the bug.
  local clear_key = string.rep("\0", key_length - encrypted_key_length + 1)
  local encrypted_key = string.rep("\0", encrypted_key_length)

  local dummy_client_master_key = sslv2.client_master_secret(cipher, clear_key, encrypted_key)
  socket:send(dummy_client_master_key)
  local status, buffer, err = sslv2.record_buffer(socket, buffer, i)
  socket:close()
  if not status then
    return false
  end
  local i, message = sslv2.record_read(buffer, i)

  -- Treat an error as a failure to force the cipher.
  if not message or message.message_type == sslv2.SSL_MESSAGE_TYPES.ERROR then
    return false
  end

  return true
end

local function registry_get(host, port)
  if host.registry.sslv2 then
    return host.registry.sslv2[port.number .. port.protocol]
  end
end

local function unique (t)
  local tc = {};
  for k,v in ipairs(t) do
    tc[v] = true;
  end
  return tc;
end

function action(host, port)
  local output = stdnse.output_table()
  local report = vulns.Report:new("sslv2-drown", host, port)
  local cve_2015_3197 = {
    title = "OpenSSL: SSLv2 doesn't block disabled ciphers",
    state = vulns.STATE.NOT_VULN,
    IDS = {
      CVE = 'CVE-2015-3197',
    },
    risk_factor = "Low",
    description = [[
      ssl/s2_srvr.c in OpenSSL 1.0.1 before 1.0.1r and 1.0.2 before 1.0.2f does not
      prevent use of disabled ciphers, which makes it easier for man-in-the-middle
      attackers to defeat cryptographic protection mechanisms by performing computations
      on SSLv2 traffic, related to the get_client_master_key and get_client_hello
      functions.
    ]],
    references = {
      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3197",
      "https://www.openssl.org/news/secadv/20160128.txt",
    },
  }
  local cve_2016_0703 = {
    title = "OpenSSL: Divide-and-conquer session key recovery in SSLv2",
    state = vulns.STATE.NOT_VULN,
    IDS = {
      CVE = 'CVE-2016-0703',
    },
    risk_factor = "High",
    description = [[
      The get_client_master_key function in s2_srvr.c in the SSLv2 implementation in
      OpenSSL before 0.9.8zf, 1.0.0 before 1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2 before
      1.0.2a accepts a nonzero CLIENT-MASTER-KEY CLEAR-KEY-LENGTH value for an arbitrary
      cipher, which allows man-in-the-middle attackers to determine the MASTER-KEY value
      and decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding oracle, a
      related issue to CVE-2016-0800.
    ]],
    references = {
      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0703",
      "https://www.openssl.org/news/secadv/20160301.txt",
    },
  }
  local cve_2016_0800 = {
    title = "OpenSSL: Cross-protocol attack on TLS using SSLv2 (DROWN)",
    state = vulns.STATE.NOT_VULN,
    IDS = {
      CVE = 'CVE-2016-0800',
    },
    risk_factor = "High",
    description = [[
      The SSLv2 protocol, as used in OpenSSL before 1.0.1s and 1.0.2 before 1.0.2g and
      other products, requires a server to send a ServerVerify message before establishing
      that a client possesses certain plaintext RSA data, which makes it easier for remote
      attackers to decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding
      oracle, aka a "DROWN" attack.
    ]],
    references = {
      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0800",
      "https://www.openssl.org/news/secadv/20160301.txt",
    },
  }
  local offered_ciphers = registry_get(host, port) or sslv2.test_sslv2(host, port)
  if not offered_ciphers then
    output.vulns = report:make_output()
    if (#output > 0) then
      return output
    else
      return nil
    end
  end
  if next(offered_ciphers) then
    output.ciphers = offered_ciphers
  end

  -- CVE-2015-3197
  local forced_ciphers = {}
  local all_ciphers = unique(offered_ciphers)
  for cipher, code in pairs(sslv2.SSL_CIPHER_CODES) do
    if not all_ciphers[cipher] and try_force_cipher(host, port, cipher) then
      all_ciphers[cipher] = true
      table.insert(forced_ciphers, cipher)
    end
  end
  if next(forced_ciphers) then
    output.forced_ciphers = forced_ciphers
    cve_2015_3197.state = vulns.STATE.VULN
  end

  -- CVE-2016-0703
  local cipher, _ = next(all_ciphers)
  local result = has_extra_clear_bug(host, port, cipher)
  if result then
    cve_2016_0703.state = vulns.STATE.VULN
  end


  -- CVE-2016-0800
  local has_weak_ciphers = false
  for cipher, _ in pairs(all_ciphers) do
    if GENERAL_DROWN_CIPHERS[cipher] then
      has_weak_ciphers = true
      break
    end
  end
  if has_weak_ciphers or cve_2016_0703.state == vulns.STATE.VULN then
    cve_2016_0800.state = vulns.STATE.VULN
  end

  report:add_vulns(cve_2015_3197)
  report:add_vulns(cve_2016_0703)
  report:add_vulns(cve_2016_0800)

  output.vulns = report:make_output()
  if (#output > 0) then
    return output
  end
end
