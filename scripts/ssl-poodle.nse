local nmap = require "nmap"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tls = require "tls"
local listop = require "listop"
local vulns = require "vulns"

description = [[
Checks whether SSLv3 CBC ciphers are allowed (POODLE)

Run with -sV to use Nmap's service scan to detect SSL/TLS on non-standard
ports. Otherwise, ssl-poodle will only run on ports that are commonly used for
SSL.

POODLE is CVE-2014-3566. All implementations of SSLv3 that accept CBC
ciphersuites are vulnerable. For speed of detection, this script will stop
after the first CBC ciphersuite is discovered. If you want to enumerate all CBC
ciphersuites, you can use Nmap's own ssl-enum-ciphers to do a full audit of
your TLS ciphersuites.
]]

---
-- @usage
-- nmap -sV --version-light --script ssl-poodle -p 443 <host>
--
-- @output
-- PORT    STATE SERVICE REASON
-- 443/tcp open  https   syn-ack
-- | ssl-poodle:
-- |   VULNERABLE:
-- |   SSL POODLE information leak
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2014-3566  OSVDB:113251
-- |           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and
-- |           other products, uses nondeterministic CBC padding, which makes it easier
-- |           for man-in-the-middle attackers to obtain cleartext data via a
-- |           padding-oracle attack, aka the "POODLE" issue.
-- |     Disclosure date: 2014-10-14
-- |     Check results:
-- |       TLS_RSA_WITH_3DES_EDE_CBC_SHA
-- |     References:
-- |       https://www.imperialviolet.org/2014/10/14/poodle.html
-- |       http://osvdb.org/113251
-- |       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
-- |_      https://www.openssl.org/~bodo/ssl-poodle.pdf
--

author = "Daniel Miller"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "safe"}

dependencies = {"ssl-enum-ciphers"}

-- Test this many ciphersuites at a time.
-- http://seclists.org/nmap-dev/2012/q3/156
-- http://seclists.org/nmap-dev/2010/q1/859
local CHUNK_SIZE = 64

local function keys(t)
  local ret = {}
  local k, v = next(t)
  while k do
    ret[#ret+1] = k
    k, v = next(t, k)
  end
  return ret
end

-- Add additional context (protocol) to debug output
local function ctx_log(level, protocol, fmt, ...)
  return stdnse.print_debug(level, "(%s) " .. fmt, protocol, ...)
end

local function try_params(host, port, t)
  local timeout = ((host.times and host.times.timeout) or 5) * 1000 + 5000

  -- Create socket.
  local status, sock, err
  local specialized = sslcert.getPrepareTLSWithoutReconnect(port)
  if specialized then
    status, sock = specialized(host, port)
    if not status then
      ctx_log(1, t.protocol, "Can't connect: %s", sock)
      return nil
    end
  else
    sock = nmap.new_socket()
    sock:set_timeout(timeout)
    status, err = sock:connect(host, port)
    if not status then
      ctx_log(1, t.protocol, "Can't connect: %s", err)
      sock:close()
      return nil
    end
  end

  sock:set_timeout(timeout)

  -- Send request.
  local req = tls.client_hello(t)
  status, err = sock:send(req)
  if not status then
    ctx_log(1, t.protocol, "Can't send: %s", err)
    sock:close()
    return nil
  end

  -- Read response.
  local buffer = ""
  local i = 1
  while true do
    status, buffer, err = tls.record_buffer(sock, buffer, i)
    if not status then
      ctx_log(1, t.protocol, "Couldn't read a TLS record: %s", err)
      return nil
    end
    -- Parse response.
    local record
    i, record = tls.record_read(buffer, i)
    if record and record.type == "alert" and record.body[1].level == "warning" then
      ctx_log(1, t.protocol, "Ignoring warning: %s", record.body[1].description)
      -- Try again.
    elseif record then
      sock:close()
      return record
    end
  end
end

local function sorted_keys(t)
  local ret = {}
  for k, _ in pairs(t) do
    ret[#ret+1] = k
  end
  table.sort(ret)
  return ret
end

local function in_chunks(t, size)
  local ret = {}
  for i = 1, #t, size do
    local chunk = {}
    for j = i, i + size - 1 do
      chunk[#chunk+1] = t[j]
    end
    ret[#ret+1] = chunk
  end
  return ret
end

local function remove(t, e)
  for i, v in ipairs(t) do
    if v == e then
      table.remove(t, i)
      return i
    end
  end
  return nil
end

-- https://bugzilla.mozilla.org/show_bug.cgi?id=946147
local function remove_high_byte_ciphers(t)
  local output = {}
  for i, v in ipairs(t) do
    if tls.CIPHERS[v] <= 255 then
      output[#output+1] = v
    end
  end
  return output
end

local function base_extensions(host)
  local tlsname = tls.servername(host)
  return {
    -- Claim to support common elliptic curves
    ["elliptic_curves"] = tls.EXTENSION_HELPERS["elliptic_curves"](tls.DEFAULT_ELLIPTIC_CURVES),
    -- Enable SNI if a server name is available
    ["server_name"] = tlsname and tls.EXTENSION_HELPERS["server_name"](tlsname),
  }
end

-- Recursively copy a table.
-- Only recurs when a value is a table, other values are copied by assignment.
local function tcopy (t)
  local tc = {};
  for k,v in pairs(t) do
    if type(v) == "table" then
      tc[k] = tcopy(v);
    else
      tc[k] = v;
    end
  end
  return tc;
end

-- Find which ciphers out of group are supported by the server.
local function find_ciphers_group(host, port, protocol, group)
  local name, protocol_worked, record, results
  results = {}
  local t = {
    ["protocol"] = protocol,
    ["extensions"] = base_extensions(host),
  }

  -- This is a hacky sort of tristate variable. There are three conditions:
  -- 1. false = either ciphers or protocol is bad. Keep trying with new ciphers
  -- 2. nil = The protocol is bad. Abandon thread.
  -- 3. true = Protocol works, at least some cipher must be supported.
  protocol_worked = false
  while (next(group)) do
    t["ciphers"] = group

    record = try_params(host, port, t)

    if record == nil then
      if protocol_worked then
        ctx_log(2, protocol, "%d ciphers rejected. (No handshake)", #group)
      else
        ctx_log(1, protocol, "%d ciphers and/or protocol rejected. (No handshake)", #group)
      end
      break
    elseif record["protocol"] ~= protocol or record["body"][1]["protocol"] and record.body[1].protocol ~= protocol then
      ctx_log(1, protocol, "Protocol rejected.")
      protocol_worked = nil
      break
    elseif record["type"] == "alert" and record["body"][1]["description"] == "handshake_failure" then
      protocol_worked = true
      ctx_log(2, protocol, "%d ciphers rejected.", #group)
      break
    elseif record["type"] ~= "handshake" or record["body"][1]["type"] ~= "server_hello" then
      ctx_log(2, protocol, "Unexpected record received.")
      break
    else
      protocol_worked = true
      name = record["body"][1]["cipher"]
      ctx_log(1, protocol, "Cipher %s chosen.", name)
      if not remove(group, name) then
        ctx_log(1, protocol, "chose cipher %s that was not offered.", name)
        ctx_log(1, protocol, "removing high-byte ciphers and trying again.")
        local size_before = #group
        group = remove_high_byte_ciphers(group)
        ctx_log(1, protocol, "removed %d high-byte ciphers.", size_before - #group)
        if #group == size_before then
          -- No changes... Server just doesn't like our offered ciphers.
          break
        end
      else
        -- Add cipher to the list of accepted ciphers.
        table.insert(results, name)
        -- POODLE check doesn't care about the rest of the ciphers
        break
      end
    end
  end
  return results, protocol_worked
end

-- POODLE only affects CBC ciphers
local cbc_ciphers = listop.filter(
  function(x) return string.find(x, "_CBC_",1,true) end,
  sorted_keys(tls.CIPHERS)
  )
-- move these to the top, more likely to be supported
for _, c in ipairs({
    "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", --mandatory for TLSv1.0
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA", -- mandatory for TLSv1.1
    "TLS_RSA_WITH_AES_128_CBC_SHA", -- mandatory fro TLSv1.2
  }) do
  remove(cbc_ciphers, c)
  table.insert(cbc_ciphers, 1, c)
end

-- Break the cipher list into chunks of CHUNK_SIZE (for servers that can't
-- handle many client ciphers at once), and then call find_ciphers_group on
-- each chunk.
local function find_ciphers(host, port, protocol)
  local name, protocol_worked, results, chunk
  local ciphers = in_chunks(cbc_ciphers, CHUNK_SIZE)

  results = {}

  -- Try every cipher.
  for _, group in ipairs(ciphers) do
    chunk, protocol_worked = find_ciphers_group(host, port, protocol, group)
    if protocol_worked == nil then return nil end
    for _, name in ipairs(chunk) do
      table.insert(results, name)
    end
    -- Another POODLE shortcut
    if protocol_worked and next(results) then return results end
  end
  return results
end

-- check if draft-ietf-tls-downgrade-scsv-00 is implemented as a mitigation
local function check_fallback_scsv(host, port, protocol, ciphers)
  local results = {}
  local t = {
    ["protocol"] = protocol,
    ["extensions"] = base_extensions(host),
  }

  t["ciphers"] = tcopy(ciphers)
  t.ciphers[#t.ciphers+1] = "TLS_FALLBACK_SCSV"

  -- TODO: remove this check after the next release.
  -- Users are using this script without the necessary tls.lua changes
  if not tls.TLS_ALERT_REGISTRY["inappropriate_fallback"] then
    -- This could get dangerous if mixed with ssl-enum-ciphers
    -- so we make this script dependent on ssl-enum-ciphers and hope for the best.
    tls.CIPHERS["TLS_FALLBACK_SCSV"] = 0x5600
    tls.TLS_ALERT_REGISTRY["inappropriate_fallback"] = 86
  end

  local record = try_params(host, port, t)

  -- cleanup (also remove after next release)
  tls.CIPHERS["TLS_FALLBACK_SCSV"] = nil

  if record and record["type"] == "alert" and record["body"][1]["description"] == "inappropriate_fallback" then
    ctx_log(2, protocol, "TLS_FALLBACK_SCSV rejected properly.")
    return true
  end
  return false
end

portrule = function (host, port)
  return shortport.ssl(host, port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

action = function(host, port)
  local vuln_table = {
    title = "SSL POODLE information leak",
    description = [[
    The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
    products, uses nondeterministic CBC padding, which makes it easier
    for man-in-the-middle attackers to obtain cleartext data via a
    padding-oracle attack, aka the "POODLE" issue.]],
    state = vulns.STATE.NOT_VULN,
    IDS = {
      CVE = 'CVE-2014-3566',
      OSVDB = '113251'
    },
    SCORES = {
      CVSSv2 = '4.3'
    },
    dates = {
      disclosure = {
        year = 2014, month = 10, day = 14
      }
    },
    references = {
      "https://www.openssl.org/~bodo/ssl-poodle.pdf",
      "https://www.imperialviolet.org/2014/10/14/poodle.html"
    }
  }
  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  local ciphers = find_ciphers(host, port, 'SSLv3')
  if ciphers == nil then
    vuln_table.check_results = { "SSLv3 not supported" }
  elseif #ciphers == 0 then
    vuln_table.check_results = { "No CBC ciphersuites found" }
  else
    vuln_table.check_results = ciphers
    if check_fallback_scsv(host, port, 'SSLv3', ciphers) then
      table.insert(vuln_table.check_results, "TLS_FALLBACK_SCSV properly implemented")
      vuln_table.state = vulns.STATE.LIKELY_VULN
    else
      vuln_table.state = vulns.STATE.VULN
    end
  end
  return report:make_output(vuln_table)
end
