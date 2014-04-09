local coroutine = require "coroutine"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tls = require "tls"

description = [[
This script repeatedly initiates SSL/TLS connections, each time trying a new
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
-- |   SSLv3
-- |     Ciphers (6)
-- |       TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA - unknown strength
-- |       TLS_DHE_RSA_WITH_AES_128_CBC_SHA - strong
-- |       TLS_DHE_RSA_WITH_AES_256_CBC_SHA - unknown strength
-- |       TLS_RSA_WITH_3DES_EDE_CBC_SHA - strong
-- |       TLS_RSA_WITH_AES_128_CBC_SHA - strong
-- |       TLS_RSA_WITH_AES_256_CBC_SHA - unknown strength
-- |     Compressors (1)
-- |       uncompressed
-- |   TLSv1.0
-- |     Ciphers (6)
-- |       TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA - unknown strength
-- |       TLS_DHE_RSA_WITH_AES_128_CBC_SHA - strong
-- |       TLS_DHE_RSA_WITH_AES_256_CBC_SHA - unknown strength
-- |       TLS_RSA_WITH_3DES_EDE_CBC_SHA - strong
-- |       TLS_RSA_WITH_AES_128_CBC_SHA - strong
-- |       TLS_RSA_WITH_AES_256_CBC_SHA - unknown strength
-- |     Compressors (1)
-- |       uncompressed
-- |_  Least strength = unknown strength
--
-- @xmloutput
-- <table key="SSLv3">
--   <table key="ciphers">
--     <table>
--       <elem key="strength">strong</elem>
--       <elem key="name">TLS_RSA_WITH_3DES_EDE_CBC_SHA</elem>
--     </table>
--     <table>
--       <elem key="strength">weak</elem>
--       <elem key="name">TLS_RSA_WITH_DES_CBC_SHA</elem>
--     </table>
--     <table>
--       <elem key="strength">strong</elem>
--       <elem key="name">TLS_RSA_WITH_RC4_128_MD5</elem>
--     </table>
--     <table>
--       <elem key="strength">strong</elem>
--       <elem key="name">TLS_RSA_WITH_RC4_128_SHA</elem>
--     </table>
--   </table>
--   <table key="compressors">
--     <elem>NULL</elem>
--   </table>
-- </table>
-- <table key="TLSv1.0">
--   <table key="ciphers">
--     <table>
--       <elem key="strength">strong</elem>
--       <elem key="name">TLS_RSA_WITH_3DES_EDE_CBC_SHA</elem>
--     </table>
--     <table>
--       <elem key="strength">weak</elem>
--       <elem key="name">TLS_RSA_WITH_DES_CBC_SHA</elem>
--     </table>
--     <table>
--       <elem key="strength">strong</elem>
--       <elem key="name">TLS_RSA_WITH_RC4_128_MD5</elem>
--     </table>
--     <table>
--       <elem key="strength">strong</elem>
--       <elem key="name">TLS_RSA_WITH_RC4_128_SHA</elem>
--     </table>
--   </table>
--   <table key="compressors">
--     <elem>NULL</elem>
--   </table>
-- </table>
-- <elem key="least strength">weak</elem>

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

local function try_params(host, port, t)
  local buffer, err, i, record, req, resp, sock, status

  -- Create socket.
  local specialized = sslcert.getPrepareTLSWithoutReconnect(port)
  if specialized then
    local status
    status, sock = specialized(host, port)
    if not status then
      stdnse.print_debug(1, "Can't connect: %s", err)
      return nil
    end
  else
    sock = nmap.new_socket()
    sock:set_timeout(5000)
    local status = sock:connect(host, port)
    if not status then
      stdnse.print_debug(1, "Can't connect: %s", err)
      sock:close()
      return nil
    end
  end

  sock:set_timeout(5000)

  -- Send request.
  req = tls.client_hello(t)
  status, err = sock:send(req)
  if not status then
    stdnse.print_debug(1, "Can't send: %s", err)
    sock:close()
    return nil
  end

  -- Read response.
  buffer = ""
  record = nil
  while true do
    local status
    status, buffer, err = tls.record_buffer(sock, buffer, 1)
    if not status then
      stdnse.print_debug(1, "Couldn't read a TLS record: %s", err)
      return nil
    end
    -- Parse response.
    i, record = tls.record_read(buffer, 1)
    if record and record.type == "alert" and record.body[1].level == "warning" then
      stdnse.print_debug(1, "Ignoring warning: %s", record.body[1].description)
      -- Try again.
    elseif record then
      sock:close()
      return record
    end
    buffer = buffer:sub(i+1)
  end
end

local function keys(t)
  local ret = {}
  for k, _ in pairs(t) do
    ret[#ret+1] = k
  end
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

local function find_ciphers(host, port, protocol)
  local name, protocol_worked, record, results, t,cipherstr
  local ciphers = in_chunks(keys(tls.CIPHERS), CHUNK_SIZE)
  local t = {
        ["protocol"] = protocol,
        ["extensions"] = {
          -- Claim to support every elliptic curve
          ["elliptic_curves"] = tls.EXTENSION_HELPERS["elliptic_curves"](keys(tls.ELLIPTIC_CURVES)),
          -- Claim to support every EC point format
          ["ec_point_formats"] = tls.EXTENSION_HELPERS["ec_point_formats"](keys(tls.EC_POINT_FORMATS)),
        },
      }
  if host.targetname then
    t["extensions"]["server_name"] = tls.EXTENSION_HELPERS["server_name"](host.targetname)
  end

  results = {}

  -- Try every cipher.
  protocol_worked = false
  for _, group in ipairs(ciphers) do
    while (next(group)) do
      -- Create structure.
      t["ciphers"] = group

      record = try_params(host, port, t)

      if record == nil then
        if protocol_worked then
          stdnse.print_debug(2, "%d ciphers rejected. (No handshake)", #group)
        else
          stdnse.print_debug(1, "%d ciphers and/or protocol %s rejected. (No handshake)", #group, protocol)
        end
        break
      elseif record["protocol"] ~= protocol then
        stdnse.print_debug(1, "Protocol %s rejected.", protocol)
        protocol_worked = nil
        break
      elseif record["type"] == "alert" and record["body"][1]["description"] == "handshake_failure" then
        protocol_worked = true
        stdnse.print_debug(2, "%d ciphers rejected.", #group)
        break
      elseif record["type"] ~= "handshake" or record["body"][1]["type"] ~= "server_hello" then
        stdnse.print_debug(2, "Unexpected record received.")
        break
      else
        protocol_worked = true
        name = record["body"][1]["cipher"]
        stdnse.print_debug(2, "Cipher %s chosen.", name)
        remove(group, name)

        -- Add cipher to the list of accepted ciphers.
        table.insert(results, name)
      end
    end
    if protocol_worked == nil then return nil end
  end
  if not protocol_worked then return nil end

  return results
end

local function find_compressors(host, port, protocol, good_cipher)
  local name, protocol_worked, record, results, t
  local compressors = keys(tls.COMPRESSORS)
  local t = {
    ["protocol"] = protocol,
    ["ciphers"] = {good_cipher},
    ["extensions"] = {
      -- Claim to support every elliptic curve
      ["elliptic_curves"] = tls.EXTENSION_HELPERS["elliptic_curves"](keys(tls.ELLIPTIC_CURVES)),
      -- Claim to support every EC point format
      ["ec_point_formats"] = tls.EXTENSION_HELPERS["ec_point_formats"](keys(tls.EC_POINT_FORMATS)),
    },
  }
  if host.targetname then
    t["extensions"]["server_name"] = tls.EXTENSION_HELPERS["server_name"](host.targetname)
  end

  results = {}

  -- Try every compressor.
  protocol_worked = false
  while (next(compressors)) do
    -- Create structure.
    t["compressors"] = compressors

    -- Try connecting with compressor.
    record = try_params(host, port, t)

    if record == nil then
      if protocol_worked then
        stdnse.print_debug(2, "%d compressors rejected. (No handshake)", #compressors)
      else
        stdnse.print_debug(1, "%d compressors and/or protocol %s rejected. (No handshake)", #compressors, protocol)
      end
      break
    elseif record["protocol"] ~= protocol then
      stdnse.print_debug(1, "Protocol %s rejected.", protocol)
      break
    elseif record["type"] == "alert" and record["body"][1]["description"] == "handshake_failure" then
      protocol_worked = true
      stdnse.print_debug(2, "%d compressors rejected.", #compressors)
      break
    elseif record["type"] ~= "handshake" or record["body"][1]["type"] ~= "server_hello" then
      stdnse.print_debug(2, "Unexpected record received.")
      break
    else
      protocol_worked = true
      name = record["body"][1]["compressor"]
      stdnse.print_debug(2, "Compressor %s chosen.", name)
      remove(compressors, name)

      -- Add compressor to the list of accepted compressors.
      table.insert(results, name)
      if name == "NULL" then
        break -- NULL is always last choice, and must be included
      end
    end
  end

  return results
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
  compressors = find_compressors(host, port, protocol, ciphers[1])

  -- Add rankings to ciphers
  local cipherstr
  for i, name in ipairs(ciphers) do
    if rankedciphersfilename and rankedciphers[name] then
      cipherstr=rankedciphers[name]
    else
      cipherstr="unknown strength"
    end
    stdnse.print_debug(2, "Strength of %s rated %d.",cipherstr,cipherstrength[cipherstr])
    if mincipherstrength>cipherstrength[cipherstr] then
      stdnse.print_debug(2, "Downgrading min cipher strength to %d.",cipherstrength[cipherstr])
      mincipherstrength=cipherstrength[cipherstr]
    end
    local outcipher = {name=name, strength=cipherstr}
    setmetatable(outcipher,{
      __tostring=function(t) return string.format("%s - %s", t.name, t.strength) end
    })
    ciphers[i]=outcipher
  end

  -- Format the cipher table.
  table.sort(ciphers, function(a, b) return a["name"] < b["name"] end)
  results["ciphers"] = ciphers

  -- Format the compressor table.
  table.sort(compressors)
  results["compressors"] = compressors

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
        stdnse.print_debug(1,"Strength not defined, ignoring: %s:%s",lsplit[1],lsplit[2])
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
      local order = keys(t)
      table.sort(order)
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
    stdnse.print_debug(1, "Ranked ciphers filename: %s", rankedciphersfilename)
    filltable(rankedciphersfilename,rankedciphers)
  end

  results = {}

  local condvar = nmap.condvar(results)
  local threads = {}

  for name, _ in pairs(tls.PROTOCOLS) do
    stdnse.print_debug(1, "Trying protocol %s.", name)
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

  if #( keys(results) ) == 0 then
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
