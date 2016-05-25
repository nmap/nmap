local comm = require "comm"
local coroutine = require "coroutine"
local math = require "math"
local nmap = require "nmap"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tls = require "tls"

description = [[
This script repeatedly initiates SSLv3/TLS connections, each time trying a new
cipher or compressor while recording whether a host accepts or rejects it. The
end result is a list of all the ciphersuites and compressors that a server accepts.

Each ciphersuite is shown with a letter grade (A through F) indicating the
strength of the connection. The grade is based on the cryptographic strength of
the key exchange and of the stream cipher. The message integrity (hash)
algorithm choice is not a factor.  The output line beginning with
<code>Least strength</code> shows the strength of the weakest cipher offered.

SSLv3/TLSv1 requires more effort to determine which ciphers and compression
methods a server supports than SSLv2. A client lists the ciphers and compressors
that it is capable of supporting, and the server will respond with a single
cipher and compressor chosen, or a rejection notice.

Some servers use the client's ciphersuite ordering: they choose the first of
the client's offered suites that they also support. Other servers prefer their
own ordering: they choose their most preferred suite from among those the
client offers. In the case of server ordering, the script makes extra probes to
discover the server's sorted preference list. Otherwise, the list is sorted
alphabetically.

The script will warn about certain SSL misconfigurations such as MD5-signed
certificates, low-quality ephemeral DH parameters, and the POODLE
vulnerability.

This script is intrusive since it must initiate many connections to a server,
and therefore is quite noisy.
]]

---
-- @usage
-- nmap --script ssl-enum-ciphers -p 443 <host>
--
-- @output
-- PORT    STATE SERVICE REASON
-- 443/tcp open  https   syn-ack
-- | ssl-enum-ciphers:
-- |   SSLv3:
-- |     ciphers:
-- |       TLS_RSA_WITH_RC4_128_MD5 (rsa 2048) - A
-- |       TLS_RSA_WITH_RC4_128_SHA (rsa 2048) - A
-- |       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
-- |     compressors:
-- |       NULL
-- |     cipher preference: server
-- |   TLSv1.0:
-- |     ciphers:
-- |       TLS_RSA_WITH_RC4_128_MD5 (rsa 2048) - A
-- |       TLS_RSA_WITH_RC4_128_SHA (rsa 2048) - A
-- |       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
-- |       TLS_DHE_RSA_WITH_AES_256_CBC_SHA (dh 256) - A
-- |       TLS_DHE_RSA_WITH_AES_128_CBC_SHA (dh 256) - A
-- |     compressors:
-- |       NULL
-- |     cipher preference: server
-- |_  least strength: C
--
-- @xmloutput
-- <table key="SSLv3">
--   <table key="ciphers">
--     <table>
--       <elem key="name">TLS_RSA_WITH_RC4_128_MD5</elem>
--       <elem key="strength">A</elem>
--       <elem key="kex_info">rsa 2048</elem>
--     </table>
--     <table>
--       <elem key="name">TLS_RSA_WITH_RC4_128_SHA</elem>
--       <elem key="strength">A</elem>
--       <elem key="kex_info">rsa 2048</elem>
--     </table>
--     <table>
--       <elem key="name">TLS_RSA_WITH_3DES_EDE_CBC_SHA</elem>
--       <elem key="strength">C</elem>
--       <elem key="kex_info">rsa 2048</elem>
--     </table>
--   </table>
--   <table key="compressors">
--     <elem>NULL</elem>
--   </table>
--   <elem key="cipher preference">server</elem>
-- </table>
-- <table key="TLSv1.0">
--   <table key="ciphers">
--     <table>
--       <elem key="name">TLS_RSA_WITH_RC4_128_MD5</elem>
--       <elem key="strength">A</elem>
--       <elem key="kex_info">rsa 2048</elem>
--     </table>
--     <table>
--       <elem key="name">TLS_RSA_WITH_RC4_128_SHA</elem>
--       <elem key="strength">A</elem>
--       <elem key="kex_info">rsa 2048</elem>
--     </table>
--     <table>
--       <elem key="name">TLS_RSA_WITH_3DES_EDE_CBC_SHA</elem>
--       <elem key="strength">C</elem>
--       <elem key="kex_info">rsa 2048</elem>
--     </table>
--     <table>
--       <elem key="name">TLS_DHE_RSA_WITH_AES_256_CBC_SHA</elem>
--       <elem key="strength">A</elem>
--       <elem key="kex_info">dh 256</elem>
--     </table>
--     <table>
--       <elem key="name">TLS_DHE_RSA_WITH_AES_128_CBC_SHA</elem>
--       <elem key="strength">A</elem>
--       <elem key="kex_info">dh 256</elem>
--     </table>
--   </table>
--   <table key="compressors">
--     <elem>NULL</elem>
--   </table>
--   <elem key="cipher preference">server</elem>
-- </table>
-- <elem key="least strength">C</elem>

author = "Mak Kolybabi <mak@kolybabi.com>, Gabriel Lawrence"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "intrusive"}


-- Test at most this many ciphersuites at a time.
-- http://seclists.org/nmap-dev/2012/q3/156
-- http://seclists.org/nmap-dev/2010/q1/859
local CHUNK_SIZE = 64
local have_ssl, _ = pcall(require,'openssl')

-- Add additional context (protocol) to debug output
local function ctx_log(level, protocol, fmt, ...)
  return stdnse.debug(level, "(%s) " .. fmt, protocol, ...)
end

-- returns a function that yields a new tls record each time it is called
local function get_record_iter(sock)
  local buffer = ""
  local i = 1
  local fragment
  return function ()
    local record
    i, record = tls.record_read(buffer, i, fragment)
    if record == nil then
      local status, err
      status, buffer, err = tls.record_buffer(sock, buffer, i)
      if not status then
        return nil, err
      end
      i, record = tls.record_read(buffer, i, fragment)
      if record == nil then
        return nil, "done"
      end
    end
    fragment = record.fragment
    return record
  end
end

local function try_params(host, port, t)

  -- Use Nmap's own discovered timeout plus 5 seconds for host processing
  -- Default to 10 seconds total.
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
  local get_next_record = get_record_iter(sock)
  local records = {}
  while true do
    local record
    record, err = get_next_record()
    if not record then
      ctx_log(1, t.protocol, "Couldn't read a TLS record: %s", err)
      sock:close()
      return records
    end
    -- Collect message bodies into one record per type
    records[record.type] = records[record.type] or record
    local done = false
    for j = 1, #record.body do -- no ipairs because we append below
      local b = record.body[j]
      done = ((record.type == "alert" and b.level == "fatal") or
        (record.type == "handshake" and b.type == "server_hello_done"))
      table.insert(records[record.type].body, b)
    end
    if done then
      sock:close()
      return records
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
  size = math.floor(size)
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

local function slice(t, i, j)
  local output = {}
  while i <= j do
    output[#output+1] = t[i]
    i = i + 1
  end
  return output
end

local function merge(a, b, cmp)
  local output = {}
  local i = 1
  local j = 1
  while i <= #a and j <= #b do
    local winner, err = cmp(a[i], b[j])
    if not winner then
      return nil, err
    end
    if winner == a[i] then
      output[#output+1] = a[i]
      i = i + 1
    else
      output[#output+1] = b[j]
      j = j + 1
    end
  end
  while i <= #a do
    output[#output+1] = a[i]
    i = i + 1
  end
  while j <= #b do
    output[#output+1] = b[j]
    j = j + 1
  end
  return output
end

local function merge_recursive(chunks, cmp)
  if #chunks == 0 then
    return {}
  elseif #chunks == 1 then
    return chunks[1]
  else
    local m = math.floor(#chunks / 2)
    local a, b = slice(chunks, 1, m), slice(chunks, m+1, #chunks)
    local am, err = merge_recursive(a, cmp)
    if not am then
      return nil, err
    end
    local bm, err = merge_recursive(b, cmp)
    if not bm then
      return nil, err
    end
    return merge(am, bm, cmp)
  end
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

-- Claim to support every elliptic curve and EC point format
local base_extensions = {
  -- Claim to support every elliptic curve
  ["elliptic_curves"] = tls.EXTENSION_HELPERS["elliptic_curves"](sorted_keys(tls.ELLIPTIC_CURVES)),
  -- Claim to support every EC point format
  ["ec_point_formats"] = tls.EXTENSION_HELPERS["ec_point_formats"](sorted_keys(tls.EC_POINT_FORMATS)),
}

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

-- Get a message body from a record which has the specified property set to value
local function get_body(record, property, value)
  for i, b in ipairs(record.body) do
    if b[property] == value then
      return b
    end
  end
  return nil
end

-- Score a ciphersuite implementation (including key exchange info)
local function score_cipher (kex_strength, cipher_info)
  local kex_score, cipher_score
  if not kex_strength or not cipher_info.size then
    return "unknown"
  end
  if kex_strength == 0 then
    return 0
  elseif kex_strength < 512 then
    kex_score = 0.2
  elseif kex_strength < 1024 then
    kex_score = 0.4
  elseif kex_strength < 2048 then
    kex_score = 0.8
  elseif kex_strength < 4096 then
    kex_score = 0.9
  else
    kex_score = 1.0
  end

  if cipher_info.size == 0 then
    return 0
  elseif cipher_info.size < 128 then
    cipher_score = 0.2
  elseif cipher_info.size < 256 then
    cipher_score = 0.8
  else
    cipher_score = 1.0
  end

  -- Based on SSL Labs' 30-30-40 rating without the first 30% (protocol support)
  return 0.43 * kex_score + 0.57 * cipher_score
end

local function letter_grade (score)
  if not tonumber(score) then return "unknown" end
  if score >= 0.80 then
    return "A"
  elseif score >= 0.65 then
    return "B"
  elseif score >= 0.50 then
    return "C"
  elseif score >= 0.35 then
    return "D"
  elseif score >= 0.20 then
    return "E"
  else
    return "F"
  end
end

-- Find which ciphers out of group are supported by the server.
local function find_ciphers_group(host, port, protocol, group, scores)
  local results = {}
  local t = {
    ["protocol"] = protocol,
    ["extensions"] = tcopy(base_extensions),
  }
  if host.targetname then
    t["extensions"]["server_name"] = tls.EXTENSION_HELPERS["server_name"](host.targetname)
  end

  -- This is a hacky sort of tristate variable. There are three conditions:
  -- 1. false = either ciphers or protocol is bad. Keep trying with new ciphers
  -- 2. nil = The protocol is bad. Abandon thread.
  -- 3. true = Protocol works, at least some cipher must be supported.
  local protocol_worked = false
  while (next(group)) do
    t["ciphers"] = group

    local records = try_params(host, port, t)
    local handshake = records.handshake

    if handshake == nil then
      local alert = records.alert
      if alert then
        ctx_log(2, protocol, "Got alert: %s", alert.body[1].description)
        if alert["protocol"] ~= protocol then
          ctx_log(1, protocol, "Protocol rejected.")
          protocol_worked = nil
          break
        elseif get_body(alert, "description", "handshake_failure") then
          protocol_worked = true
          ctx_log(2, protocol, "%d ciphers rejected.", #group)
          break
        end
      elseif protocol_worked then
        ctx_log(2, protocol, "%d ciphers rejected. (No handshake)", #group)
      else
        ctx_log(1, protocol, "%d ciphers and/or protocol rejected. (No handshake)", #group)
      end
      break
    else
      local server_hello = get_body(handshake, "type", "server_hello")
      if not server_hello then
        ctx_log(2, protocol, "Unexpected record received.")
        break
      end
      if server_hello.protocol ~= protocol then
        ctx_log(1, protocol, "Protocol rejected. cipher: %s", server_hello.cipher)
        protocol_worked = (protocol_worked == nil) and nil or false
        break
      else
        protocol_worked = true
        local name = server_hello.cipher
        ctx_log(2, protocol, "Cipher %s chosen.", name)
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
          if scores then
            local info = tls.cipher_info(name)
            -- Some warnings:
            if info.hash and info.hash == "MD5" then
              scores.warnings["Ciphersuite uses MD5 for message integrity"] = true
            end
            if protocol == "SSLv3" and  info.mode and info.mode == "CBC" then
              scores.warnings["CBC-mode cipher in SSLv3 (CVE-2014-3566)"] = true
            elseif info.cipher == "RC4" and tls.PROTOCOLS[protocol] >= 0x0302 then
              scores.warnings["Weak cipher RC4 in TLSv1.1 or newer not needed for BEAST mitigation"] = true
            end
            local kex = tls.KEX_ALGORITHMS[info.kex]
            local extra, kex_strength
            if kex.anon then
              kex_strength = 0
            elseif kex.export then
              if info.kex:find("1024$") then
                kex_strength = 1024
              else
                kex_strength = 512
              end
            else
              if have_ssl and kex.pubkey then
                local certs = get_body(handshake, "type", "certificate")
                -- Assume RFC compliance:
                -- "The sender's certificate MUST come first in the list."
                -- This may not always be the case, so
                -- TODO: reorder certificates and validate entire chain
                -- TODO: certificate validation (date, self-signed, etc)
                local c = sslcert.parse_ssl_certificate(certs.certificates[1])
                if c.pubkey.type == kex.pubkey then
                  local sigalg = c.sig_algorithm:match("([mM][dD][245])")
                  if sigalg then
                    -- MD2 and MD5 are broken
                    kex_strength = 0
                    scores.warnings["Insecure certificate signature: " .. string.upper(sigalg)] = true
                  else
                    sigalg = c.sig_algorithm:match("([sS][hH][aA]1)")
                    if sigalg then
                      -- TODO: Update this when SHA-1 is deprecated in 2016
                      -- kex_strength = 0
                      scores.warnings["Weak certificate signature: SHA1"] = true
                    end
                    kex_strength = tls.rsa_equiv(kex.pubkey, c.pubkey.bits)
                    if c.pubkey.ecdhparams then
                      if c.pubkey.ecdhparams.curve_params.ec_curve_type == "namedcurve" then
                        extra = c.pubkey.ecdhparams.curve_params.curve
                      else
                        extra = string.format("%s %d", c.pubkey.ecdhparams.curve_params.ec_curve_type, c.pubkey.bits)
                      end
                    else
                      extra = string.format("%s %d", kex.pubkey, c.pubkey.bits)
                    end
                  end
                end
              end
              local ske = get_body(handshake, "type", "server_key_exchange")
              if kex.server_key_exchange and ske then
                local kex_info = kex.server_key_exchange(ske.data)
                if kex_info.strength then
                  local rsa_bits = tls.rsa_equiv(kex.type, kex_info.strength)
                  if kex_strength and kex_strength > rsa_bits then
                    kex_strength = rsa_bits
                    scores.warnings["Key exchange parameters of lower strength than certificate key"] = true
                  end
                  kex_strength = kex_strength or rsa_bits
                  if kex_info.ecdhparams then
                    if kex_info.ecdhparams.curve_params.ec_curve_type == "namedcurve" then
                      extra = kex_info.ecdhparams.curve_params.curve
                    else
                      extra = string.format("%s %d", kex_info.ecdhparams.curve_params.ec_curve_type, kex_info.strength)
                    end
                  else
                    extra = string.format("%s %d", kex.type, kex_info.strength)
                  end
                end
              end
            end
            scores[name] = {
              cipher_strength=info.size,
              kex_strength = kex_strength,
              extra = extra,
              letter_grade = letter_grade(score_cipher(kex_strength, info))
            }
          end
        end
      end
    end
  end
  return results, protocol_worked
end

local function get_chunk_size(host, protocol)
  -- Try to make sure we don't send too big of a handshake
  -- https://github.com/ssllabs/research/wiki/Long-Handshake-Intolerance
  local len_t = {
    protocol = protocol,
    ciphers = {},
    extensions = tcopy(base_extensions),
  }
  if host.targetname then
    len_t.extensions.server_name = tls.EXTENSION_HELPERS.server_name(host.targetname)
  end
  local cipher_len_remaining = 255 - #tls.client_hello(len_t)
  -- if we're over 255 anyway, just go for it.
  -- Each cipher adds 2 bytes
  local max_chunks = cipher_len_remaining > 0 and cipher_len_remaining / 2 or CHUNK_SIZE
  -- otherwise, use the min
  return max_chunks < CHUNK_SIZE and max_chunks or CHUNK_SIZE
end

-- Break the cipher list into chunks of CHUNK_SIZE (for servers that can't
-- handle many client ciphers at once), and then call find_ciphers_group on
-- each chunk.
local function find_ciphers(host, port, protocol)

  local ciphers = in_chunks(sorted_keys(tls.CIPHERS), get_chunk_size(host, protocol))

  local results = {}
  local scores = {warnings={}}
  -- Try every cipher.
  for _, group in ipairs(ciphers) do
    local chunk, protocol_worked = find_ciphers_group(host, port, protocol, group, scores)
    if protocol_worked == nil then return nil end
    for _, name in ipairs(chunk) do
      table.insert(results, name)
    end
  end
  if not next(results) then return nil end

  return results, scores
end

local function find_compressors(host, port, protocol, good_ciphers)
  local compressors = sorted_keys(tls.COMPRESSORS)
  local t = {
    ["protocol"] = protocol,
    ["ciphers"] = good_ciphers,
    ["extensions"] = tcopy(base_extensions),
  }
  if host.targetname then
    t["extensions"]["server_name"] = tls.EXTENSION_HELPERS["server_name"](host.targetname)
  end

  local results = {}

  -- Try every compressor.
  local protocol_worked = false
  while (next(compressors)) do
    -- Create structure.
    t["compressors"] = compressors

    -- Try connecting with compressor.
    local records = try_params(host, port, t)
    local handshake = records.handshake

    if handshake == nil then
      local alert = records.alert
      if alert then
        ctx_log(2, protocol, "Got alert: %s", alert.body[1].description)
        if alert["protocol"] ~= protocol then
          ctx_log(1, protocol, "Protocol rejected.")
          protocol_worked = nil
          break
        elseif get_body(alert, "description", "handshake_failure") then
          protocol_worked = true
          ctx_log(2, protocol, "%d compressors rejected.", #compressors)
          -- Should never get here, because NULL should be good enough.
          -- The server may just not be able to handle multiple compressors.
          if #compressors > 1 then -- Make extra-sure it's not crazily rejecting the NULL compressor
            compressors[1] = "NULL"
            for i = 2, #compressors, 1 do
              compressors[i] = nil
            end
            -- try again.
          else
            break
          end
        end
      elseif protocol_worked then
        ctx_log(2, protocol, "%d compressors rejected. (No handshake)", #compressors)
      else
        ctx_log(1, protocol, "%d compressors and/or protocol rejected. (No handshake)", #compressors)
      end
      break
    else
      local server_hello = get_body(handshake, "type", "server_hello")
      if not server_hello then
        ctx_log(2, protocol, "Unexpected record received.")
        break
      end
      if server_hello.protocol ~= protocol then
        ctx_log(1, protocol, "Protocol rejected.")
        protocol_worked = (protocol_worked == nil) and nil or false
        break
      else
        protocol_worked = true
        local name = server_hello.compressor
        ctx_log(2, protocol, "Compressor %s chosen.", name)
        remove(compressors, name)

        -- Add compressor to the list of accepted compressors.
        table.insert(results, name)
        if name == "NULL" then
          break -- NULL is always last choice, and must be included
        end
      end
    end
  end

  return results
end

-- Offer two ciphers and return the one chosen by the server. Returns nil and
-- an error message in case of a server error.
local function compare_ciphers(host, port, protocol, cipher_a, cipher_b)
  local t = {
    ["protocol"] = protocol,
    ["ciphers"] = {cipher_a, cipher_b},
    ["extensions"] = tcopy(base_extensions),
  }
  if host.targetname then
    t["extensions"]["server_name"] = tls.EXTENSION_HELPERS["server_name"](host.targetname)
  end
  local records = try_params(host, port, t)
  local server_hello = records.handshake and get_body(records.handshake, "type", "server_hello")
  if server_hello then
    ctx_log(2, protocol, "compare %s %s -> %s", cipher_a, cipher_b, server_hello.cipher)
    return server_hello.cipher
  else
    ctx_log(2, protocol, "compare %s %s -> error", cipher_a, cipher_b)
    return nil, string.format("Error when comparing %s and %s", cipher_a, cipher_b)
  end
end

-- Try to find whether the server prefers its own ciphersuite order or that of
-- the client.
--
-- The return value is (preference, err). preference is a string:
--   "server": the server prefers its own order. In this case ciphers is non-nil.
--   "client": the server follows the client preference. ciphers is nil.
--   "indeterminate": returned when there are only 0 or 1 ciphers. ciphers is nil.
--   nil: an error ocurred during the test. err is non-nil.
-- err is an error message string that is non-nil when preference is nil or
-- indeterminate.
--
-- The algorithm tries offering two ciphersuites in two different orders. If
-- the server makes a different choice each time, "client" preference is
-- assumed. Otherwise, "server" preference is assumed.
local function find_cipher_preference(host, port, protocol, ciphers)
  -- Too few ciphers to make a decision?
  if #ciphers < 2 then
    return "indeterminate", "Too few ciphers supported"
  end

  -- Do a comparison in both directions to see if server ordering is consistent.
  local cipher_a, cipher_b = ciphers[1], ciphers[2]
  ctx_log(1, protocol, "Comparing %s to %s", cipher_a, cipher_b)
  local winner_forwards, err = compare_ciphers(host, port, protocol, cipher_a, cipher_b)
  if not winner_forwards then
    return nil, err
  end
  local winner_backward, err = compare_ciphers(host, port, protocol, cipher_b, cipher_a)
  if not winner_backward then
    return nil, err
  end
  if winner_forwards ~= winner_backward then
    return "client", nil
  end
  return "server", nil
end

-- Sort ciphers according to server preference with a modified merge sort
local function sort_ciphers(host, port, protocol, ciphers)
  local chunks = {}
  for _, group in ipairs(in_chunks(ciphers, get_chunk_size(host, protocol))) do
    local size = #group
    local chunk = find_ciphers_group(host, port, protocol, group)
    if not chunk then
      return nil, "Network error"
    end
    if #chunk ~= size then
      ctx_log(1, protocol, "warning: %d ciphers offered but only %d accepted", size, #chunk)
    end
    table.insert(chunks, chunk)
  end

  -- The comparison operator for the merge is a 2-cipher ClientHello.
  local function cmp(cipher_a, cipher_b)
    return compare_ciphers(host, port, protocol, cipher_a, cipher_b)
  end
  local sorted, err = merge_recursive(chunks, cmp)
  if not sorted then
    return nil, err
  end
  return sorted
end

local function try_protocol(host, port, protocol, upresults)
  local condvar = nmap.condvar(upresults)

  local results = stdnse.output_table()

  -- Find all valid ciphers.
  local ciphers, scores = find_ciphers(host, port, protocol)
  if ciphers == nil then
    condvar "signal"
    return nil
  end

  if #ciphers == 0 then
    results = {ciphers={},compressors={}}
    setmetatable(results,{
      __tostring=function(t) return "No supported ciphers found" end
    })
    upresults[protocol] = results
    condvar "signal"
    return nil
  end
  -- Find all valid compression methods.
  local compressors
  -- Reduce chunk size by 1 to allow extra room for the extra compressors (2 bytes)
  for _, c in ipairs(in_chunks(ciphers, get_chunk_size(host, protocol) - 1)) do
    compressors = find_compressors(host, port, protocol, c)
    -- I observed a weird interaction between ECDSA ciphers and DEFLATE compression.
    -- Some servers would reject the handshake if no non-ECDSA ciphers were available.
    -- Sending 64 ciphers at a time should be sufficient, but we'll try them all if necessary.
    if compressors and #compressors ~= 0 then
      break
    end
  end

  -- Note the server's cipher preference algorithm.
  local cipher_pref, cipher_pref_err = find_cipher_preference(host, port, protocol, ciphers)

  -- Order ciphers according to server preference, if possible
  if cipher_pref == "server" then
    local sorted, err = sort_ciphers(host, port, protocol, ciphers)
    if sorted then
      ciphers = sorted
    else
      -- Can't sort, fall back to alphabetical order
      table.sort(ciphers)
      cipher_pref_err = err
    end
  else
    -- fall back to alphabetical order
    table.sort(ciphers)
  end

  -- Add rankings to ciphers
  for i, name in ipairs(ciphers) do
    local outcipher = {name=name, kex_info=scores[name].extra, strength=scores[name].letter_grade}
    setmetatable(outcipher,{
      __tostring=function(t)
        if t.kex_info then
          return string.format("%s (%s) - %s", t.name, t.kex_info, t.strength)
        else
          return string.format("%s - %s", t.name, t.strength)
        end
      end
    })
    ciphers[i]=outcipher
  end

  results["ciphers"] = ciphers

  -- Format the compressor table.
  table.sort(compressors)
  results["compressors"] = compressors

  results["cipher preference"] = cipher_pref
  results["cipher preference error"] = cipher_pref_err
  if next(scores.warnings) then
    results["warnings"] = sorted_keys(scores.warnings)
  end

  upresults[protocol] = results
  condvar "signal"
  return nil
end

portrule = function (host, port)
  if shortport.ssl(host, port) or sslcert.getPrepareTLSWithoutReconnect(port) then
    return true
  end
  -- selected by name and we didn't detect something *not* SSL
  if (port.version.name_confidence <= 3 and nmap.version_intensity() == 9) then
    -- check whether it's an SSL service
    local is_ssl = false
    -- probes from nmap-service-probes
    for _, probe in ipairs({
        --TLSSessionReq
        "\x16\x03\0\0\x69\x01\0\0\x65\x03\x03U\x1c\xa7\xe4random1random2random3\z
        random4\0\0\x0c\0/\0\x0a\0\x13\x009\0\x04\0\xff\x01\0\0\x30\0\x0d\0,\0*\0\z
        \x01\0\x03\0\x02\x06\x01\x06\x03\x06\x02\x02\x01\x02\x03\x02\x02\x03\x01\z
        \x03\x03\x03\x02\x04\x01\x04\x03\x04\x02\x01\x01\x01\x03\x01\x02\x05\x01\z
        \x05\x03\x05\x02",
        -- SSLSessionReq
        "\x16\x03\0\0S\x01\0\0O\x03\0?G\xd7\xf7\xba,\xee\xea\xb2`~\xf3\0\xfd\z
        \x82{\xb9\xd5\x96\xc8w\x9b\xe6\xc4\xdb<=\xdbo\xef\x10n\0\0(\0\x16\0\x13\z
        \0\x0a\0f\0\x05\0\x04\0e\0d\0c\0b\0a\0`\0\x15\0\x12\0\x09\0\x14\0\x11\0\z
        \x08\0\x06\0\x03\x01\0",
      }) do
      local status, resp = comm.exchange(host, port, probe)
      if status and resp and (
          resp:match("^\x16\x03[\0-\x03]..\x02...\x03[\0-\x03]") or
          resp:match("^\x15\x03[\0-\x03]\0\x02\x02[F\x28]")
          ) then
        is_ssl = true
        break
      end
    end
    return is_ssl
  end
  return false
end

--- Return a table that yields elements sorted by key when iterated over with pairs()
--  Should probably put this in a formatting library later.
--  Depends on keys() function defined above.
--@param  t    The table whose data should be used
--@return out  A table that can be passed to pairs() to get sorted results
function sorted_by_key(t)
  local out = {}
  setmetatable(out, {
    __pairs = function(_)
      local order = sorted_keys(t)
      return coroutine.wrap(function()
        for i,k in ipairs(order) do
          coroutine.yield(k, t[k])
        end
      end)
    end
  })
  return out
end

action = function(host, port)

  if not have_ssl then
    stdnse.verbose("OpenSSL not available; some cipher scores will be marked as unknown.")
  end

  local results = {}

  local condvar = nmap.condvar(results)
  local threads = {}

  for name, _ in pairs(tls.PROTOCOLS) do
    stdnse.debug1("Trying protocol %s.", name)
    local co = stdnse.new_thread(try_protocol, host, port, name, results)
    threads[co] = true
  end

  repeat
    for thread in pairs(threads) do
      if coroutine.status(thread) == "dead" then threads[thread] = nil end
    end
    if ( next(threads) ) then
      condvar "wait"
    end
  until next(threads) == nil

  if not next(results) then
    return nil
  end

  local least = "A"
  for p, r in pairs(results) do
    for i, c in ipairs(r.ciphers) do
      -- counter-intuitive: "A" < "B", so really looking for max
      least = least < c.strength and c.strength or least
    end
  end
  results["least strength"] = least

  return sorted_by_key(results)
end
