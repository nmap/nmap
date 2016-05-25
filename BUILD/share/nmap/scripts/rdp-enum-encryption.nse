description = [[
Determines which Security layer and Encryption level is supported by the
RDP service. It does so by cycling through all existing protocols and ciphers.
When run in debug mode, the script also returns the protocols and ciphers that
fail and any errors that were reported.

The script was inspired by MWR's RDP Cipher Checker
http://labs.mwrinfosecurity.com/tools/2009/01/12/rdp-cipher-checker/
]]

---
-- @usage
-- nmap -p 3389 --script rdp-enum-encryption <ip>
--
-- @output
-- PORT     STATE SERVICE
-- 3389/tcp open  ms-wbt-server
-- | rdp-enum-encryption:
-- |   Security layer
-- |     CredSSP: SUCCESS
-- |     Native RDP: SUCCESS
-- |     SSL: SUCCESS
-- |   RDP Encryption level: High
-- |     128-bit RC4: SUCCESS
-- |_    FIPS 140-1: SUCCESS
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"


local bin = require("bin")
local nmap = require("nmap")
local table = require("table")
local shortport = require("shortport")
local rdp = require("rdp")
local stdnse = require("stdnse")

categories = {"safe", "discovery"}

portrule = shortport.port_or_service(3389, "ms-wbt-server")

local function fail (err) return stdnse.format_output(false, err) end

local function enum_protocols(host, port)
  local PROTOCOLS = {
    ["Native RDP"] = 0,
    ["SSL"] = 1,
    ["CredSSP"] = 3
  }

  local ERRORS = {
    [1] = "SSL_REQUIRED_BY_SERVER",
    [2] = "SSL_NOT_ALLOWED_BY_SERVER",
    [3] = "SSL_CERT_NOT_ON_SERVER",
    [4] = "INCONSISTENT_FLAGS",
    [5] = "HYBRID_REQUIRED_BY_SERVER"
  }

  local res_proto = { name = "Security layer" }

  for k, v in pairs(PROTOCOLS) do
    local comm = rdp.Comm:new(host, port)
    if ( not(comm:connect()) ) then
      return false, fail("Failed to connect to server")
    end
    local cr = rdp.Request.ConnectionRequest:new(v)
    local status, response = comm:exch(cr)
    comm:close()
    if ( not(status) ) then
      return false, response
    end

    local pos, success = bin.unpack("C", response.itut.data)
    if ( success == 2 ) then
      table.insert(res_proto, ("%s: SUCCESS"):format(k))
    elseif ( nmap.debugging() > 0 ) then
      local pos, err = bin.unpack("C", response.itut.data, 5)
      if ( err > 0 ) then
        table.insert(res_proto, ("%s: FAILED (%s)"):format(k, ERRORS[err] or "Unknown"))
      else
        table.insert(res_proto, ("%s: FAILED"):format(k))
      end
    end
  end
  table.sort(res_proto)
  return true, res_proto
end

local function enum_ciphers(host, port)

  local CIPHERS = {
    { ["40-bit RC4"] = 1 },
    { ["56-bit RC4"] = 8 },
    { ["128-bit RC4"] = 2 },
    { ["FIPS 140-1"] = 16 }
  }

  local ENC_LEVELS = {
    [0] = "None",
    [1] = "Low",
    [2] = "Client Compatible",
    [3] = "High",
    [4] = "FIPS Compliant",
  }

  local res_ciphers = {}

  local function get_ordered_ciphers()
    local i = 0
    return function()
      i = i + 1
      if ( not(CIPHERS[i]) ) then  return end
      for k,v in pairs(CIPHERS[i]) do
        return k, v
      end
    end
  end

  for k, v in get_ordered_ciphers() do
    local comm = rdp.Comm:new(host, port)
    if ( not(comm:connect()) ) then
      return false, fail("Failed to connect to server")
    end

    local cr = rdp.Request.ConnectionRequest:new()
    local status, response = comm:exch(cr)
    if ( not(status) ) then
      break
    end

    local msc = rdp.Request.MCSConnectInitial:new(v)
    local status, response = comm:exch(msc)
    comm:close()
    if ( status ) then
      local pos, enc_level = bin.unpack("C", response.itut.data, 95 + 8)
      local pos, enc_cipher= bin.unpack("C", response.itut.data, 95 + 4)
      if ( enc_cipher == v ) then
        table.insert(res_ciphers, ("%s: SUCCESS"):format(k))
      end
      res_ciphers.name = ("RDP Encryption level: %s"):format(ENC_LEVELS[enc_level] or "Unknown")
    elseif ( nmap.debugging() > 0 ) then
      table.insert(res_ciphers, ("%s: FAILURE"):format(k))
    end
  end
  return true, res_ciphers
end

action = function(host, port)
  local result = {}

  local status, res_proto = enum_protocols(host, port)
  if ( not(status) ) then
    return res_proto
  end

  local status, res_ciphers = enum_ciphers(host, port)
  if ( not(status) ) then
    return res_ciphers
  end

  table.insert(result, res_proto)
  table.insert(result, res_ciphers)
  return stdnse.format_output(true, result)
end
