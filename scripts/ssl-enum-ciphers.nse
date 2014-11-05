local coroutine = require "coroutine"
local io = require "io"
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
end result is a list of all the ciphers and compressors that a server accepts.

Each cipher is shown with a strength rating: one of <code>strong</code>,
<code>weak</code>, or <code>unknown strength</code>. The output line
beginning with <code>Least strength</code> shows the strength of the
weakest cipher offered. If you are auditing for weak ciphers, you would
want to look more closely at any port where <code>Least strength</code>
is not <code>strong</code>. The cipher strength database is in the file
<code>nselib/data/ssl-ciphers</code>, or you can use a different file
through the script argument
<code>ssl-enum-ciphers.rankedcipherlist</code>.

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

This script is intrusive since it must initiate many connections to a server,
and therefore is quite noisy.
]]

---
-- @usage
-- nmap --script ssl-enum-ciphers -p 443 <host>
--
-- @args ssl-enum-ciphers.rankedcipherlist A path to a file of cipher names and strength ratings
--
-- @output
-- PORT    STATE SERVICE REASON
-- 443/tcp open  https   syn-ack
-- | ssl-enum-ciphers:
-- |   SSLv3:
-- |     ciphers:
-- |       TLS_RSA_WITH_RC4_128_MD5 - strong
-- |       TLS_RSA_WITH_RC4_128_SHA - strong
-- |       TLS_RSA_WITH_3DES_EDE_CBC_SHA - strong
-- |     compressors:
-- |       NULL
-- |     cipher preference: server
-- |   TLSv1.0:
-- |     ciphers:
-- |       TLS_RSA_WITH_RC4_128_MD5 - strong
-- |       TLS_RSA_WITH_RC4_128_SHA - strong
-- |       TLS_RSA_WITH_3DES_EDE_CBC_SHA - strong
-- |       TLS_RSA_WITH_AES_256_CBC_SHA - strong
-- |       TLS_RSA_WITH_AES_128_CBC_SHA - strong
-- |     compressors:
-- |       NULL
-- |     cipher preference: server
-- |_  least strength: strong
--
-- @xmloutput
-- <table key="SSLv3">
--   <table key="ciphers">
--     <table>
--       <elem key="name">TLS_RSA_WITH_RC4_128_MD5</elem>
--       <elem key="strength">strong</elem>
--     </table>
--     <table>
--       <elem key="name">TLS_RSA_WITH_RC4_128_SHA</elem>
--       <elem key="strength">strong</elem>
--     </table>
--     <table>
--       <elem key="name">TLS_RSA_WITH_3DES_EDE_CBC_SHA</elem>
--       <elem key="strength">strong</elem>
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
--       <elem key="strength">strong</elem>
--     </table>
--     <table>
--       <elem key="name">TLS_RSA_WITH_RC4_128_SHA</elem>
--       <elem key="strength">strong</elem>
--     </table>
--     <table>
--       <elem key="name">TLS_RSA_WITH_3DES_EDE_CBC_SHA</elem>
--       <elem key="strength">strong</elem>
--     </table>
--     <table>
--       <elem key="name">TLS_RSA_WITH_AES_256_CBC_SHA</elem>
--       <elem key="strength">strong</elem>
--     </table>
--     <table>
--       <elem key="name">TLS_RSA_WITH_AES_128_CBC_SHA</elem>
--       <elem key="strength">strong</elem>
--     </table>
--   </table>
--   <table key="compressors">
--     <elem>NULL</elem>
--   </table>
--   <elem key="cipher preference">server</elem>
-- </table>
-- <elem key="least strength">strong</elem>

author = "Mak Kolybabi <mak@kolybabi.com>, Gabriel Lawrence"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "intrusive"}


-- Test this many ciphersuites at a time.
-- http://seclists.org/nmap-dev/2012/q3/156
-- http://seclists.org/nmap-dev/2010/q1/859
local CHUNK_SIZE = 64


cipherstrength = {
   ["broken"] = 0,
   ["weak"]        = 1,
   ["unknown strength"]    = 2,
   ["strong"]      = 3
 }

local rankedciphers={}
local mincipherstrength=9999 --artificial "highest value"
local rankedciphersfilename=false

-- Add additional context (protocol) to debug output
local function ctx_log(level, protocol, fmt, ...)
  return stdnse.debug(level, "(%s) " .. fmt, protocol, ...)
end

-- returns a function that yields a new tls record each time it is called
local function get_record_iter(sock)
  local buffer = ""
  local i = 1
  return function ()
    local record
    i, record = tls.record_read(buffer, i)
    if record == nil then
      local status, err
      status, buffer, err = tls.record_buffer(sock, buffer, i)
      if not status then
        return nil, err
      end
      i, record = tls.record_read(buffer, i)
      if record == nil then
        return nil, "done"
      end
    end
    return record
  end
end

local function try_params(host, port, t)

  -- Use Nmap's own discovered timeout, doubled for safety
  -- Default to 10 seconds.
  local timeout = ((host.times and host.times.timeout) or 5) * 1000 * 2

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

-- Find which ciphers out of group are supported by the server.
local function find_ciphers_group(host, port, protocol, group)
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
        end
      end
    end
  end
  return results, protocol_worked
end

-- Break the cipher list into chunks of CHUNK_SIZE (for servers that can't
-- handle many client ciphers at once), and then call find_ciphers_group on
-- each chunk.
local function find_ciphers(host, port, protocol)
  local name, protocol_worked, results, chunk
  local ciphers = in_chunks(sorted_keys(tls.CIPHERS), CHUNK_SIZE)

  results = {}

  -- Try every cipher.
  for _, group in ipairs(ciphers) do
    chunk, protocol_worked = find_ciphers_group(host, port, protocol, group)
    if protocol_worked == nil then return nil end
    for _, name in ipairs(chunk) do
      table.insert(results, name)
    end
  end
  if not next(results) then return nil end

  return results
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
  for _, group in ipairs(in_chunks(ciphers, CHUNK_SIZE)) do
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
  local ciphers, compressors, results
  local condvar = nmap.condvar(upresults)

  results = stdnse.output_table()

  -- Find all valid ciphers.
  ciphers = find_ciphers(host, port, protocol)
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
  for _, c in ipairs(in_chunks(ciphers, CHUNK_SIZE)) do
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
  local cipherstr
  for i, name in ipairs(ciphers) do
    if rankedciphersfilename and rankedciphers[name] then
      cipherstr=rankedciphers[name]
    else
      cipherstr="unknown strength"
    end
    stdnse.debug2("Strength of %s rated %d.",cipherstr,cipherstrength[cipherstr])
    if mincipherstrength>cipherstrength[cipherstr] then
      stdnse.debug2("Downgrading min cipher strength to %d.",cipherstrength[cipherstr])
      mincipherstrength=cipherstrength[cipherstr]
    end
    local outcipher = {name=name, strength=cipherstr}
    setmetatable(outcipher,{
      __tostring=function(t) return string.format("%s - %s", t.name, t.strength) end
    })
    ciphers[i]=outcipher
  end

  results["ciphers"] = ciphers

  -- Format the compressor table.
  table.sort(compressors)
  results["compressors"] = compressors

  results["cipher preference"] = cipher_pref
  results["cipher preference error"] = cipher_pref_err

  upresults[protocol] = results
  condvar "signal"
  return nil
end

-- Shamelessly stolen from nselib/unpwdb.lua and changed a bit. (Gabriel Lawrence)
local filltable = function(filename,table)
  if #table ~= 0 then
    return true
  end

  local file = io.open(filename, "r")

  if not file then
    return false
  end

  while true do
    local l = file:read()

    if not l then
      break
    end

    -- Comments takes up a whole line
    if not l:match("#!comment:") then
      local lsplit=stdnse.strsplit("%s+", l)
      if cipherstrength[lsplit[2]] then
        table[lsplit[1]] = lsplit[2]
      else
        stdnse.debug1("Strength not defined, ignoring: %s:%s",lsplit[1],lsplit[2])
      end
    end
  end

  file:close()

  return true
end

portrule = function (host, port)
  return shortport.ssl(host, port) or sslcert.getPrepareTLSWithoutReconnect(port)
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
  local name, result, results

  rankedciphersfilename=stdnse.get_script_args("ssl-enum-ciphers.rankedcipherlist")
  if rankedciphersfilename then
    filltable(rankedciphersfilename,rankedciphers)
  else
    rankedciphersfilename = nmap.fetchfile( "nselib/data/ssl-ciphers" )
    stdnse.debug1("Ranked ciphers filename: %s", rankedciphersfilename)
    filltable(rankedciphersfilename,rankedciphers)
  end

  results = {}

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

  if #( stdnse.keys(results) ) == 0 then
    return nil
  end

  if rankedciphersfilename then
    for k, v in pairs(cipherstrength) do
      if v == mincipherstrength then
        -- Should sort before or after SSLv3, TLSv*
        results["least strength"] = k
      end
    end
  end

  return sorted_by_key(results)
end
