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
-- |   Security layer
-- |     CredSSP (NLA): SUCCESS
-- |     CredSSP with Early User Auth: SUCCESS
-- |     Native RDP: SUCCESS
-- |     RDSTLS: SUCCESS
-- |     SSL: SUCCESS
-- |   RDP Encryption level: High
-- |     40-bit RC4: SUCCESS
-- |     56-bit RC4: SUCCESS
-- |     128-bit RC4: SUCCESS
-- |     FIPS 140-1: SUCCESS
-- |_  RDP Protocol Version:  RDP 5.x, 6.x, 7.x, or 8.x server
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"


local nmap = require("nmap")
local table = require("table")
local shortport = require("shortport")
local rdp = require("rdp")
local stdnse = require("stdnse")
local string = require "string"

categories = {"safe", "discovery"}

portrule = shortport.port_or_service(3389, "ms-wbt-server")

local function fail (err) return stdnse.format_output(false, err) end

local function enum_protocols(host, port)
  local PROTOCOLS = {
    ["Native RDP"] = 0,
    ["SSL"] = 1,
    ["CredSSP (NLA)"] = 3,
    ["RDSTLS"] = 4,
    ["CredSSP with Early User Auth"] = 8
  }

  local ERRORS = {
    [1] = "SSL_REQUIRED_BY_SERVER",
    [2] = "SSL_NOT_ALLOWED_BY_SERVER",
    [3] = "SSL_CERT_NOT_ON_SERVER",
    [4] = "INCONSISTENT_FLAGS",
    [5] = "HYBRID_REQUIRED_BY_SERVER"
  }

  local res_proto = { name = "Security layer" }
  local proto_version

  for k, v in pairs(PROTOCOLS) do
    -- Prevent reconnecting too quickly, improves reliability
    stdnse.sleep(0.2)

    local comm = rdp.Comm:new(host, port)
    if ( not(comm:connect()) ) then
      return false, fail("Failed to connect to server")
    end
    local cr = rdp.Request.ConnectionRequest:new(v)
    local status, response = comm:exch(cr)

    if status then
      if response.itut.data ~= "" then
        local success = string.unpack("B", response.itut.data)

        if ( success == 2 ) then
          table.insert(res_proto, ("%s: SUCCESS"):format(k))
        elseif ( nmap.debugging() > 0 ) then
          local err = string.unpack("B", response.itut.data, 5)
          if ( err > 0 ) then
            table.insert(res_proto, ("%s: FAILED (%s)"):format(k, ERRORS[err] or "Unknown"))
          else
            table.insert(res_proto, ("%s: FAILED"):format(k))
          end
        end
      else
        -- rdpNegData, which contains the negotiation response or failure,
        -- is optional. WinXP SP3 does not return this section which means
        -- we can't tell if the protocol is accepted or not.
        table.insert(res_proto, ("%s: Unknown"):format(k))
      end
    else
      comm:close()
      return false, response
    end

    -- For servers that require TLS or NLA the only way to get the RDP protocol
    -- version to negotiate TLS or NLA. This section does that for TLS. There
    -- is no NLA currently.
    if status and (v == 1) then
      local res, _ = comm.socket:reconnect_ssl()
      if res then
        local msc = rdp.Request.MCSConnectInitial:new(0, 1)
        status, response = comm:exch(msc)
        if status then
          if response.ccr.proto_version then
            proto_version = response.ccr.proto_version
          end
        end
      end
    end

    comm:close()
  end
  table.sort(res_proto)
  return true, res_proto, proto_version
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
  local proto_version

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
    -- Prevent reconnecting too quickly, improves reliability
    stdnse.sleep(0.2)

    local comm = rdp.Comm:new(host, port)
    if ( not(comm:connect()) ) then
      return false, fail("Failed to connect to server")
    end

    local cr = rdp.Request.ConnectionRequest:new()
    local status, _ = comm:exch(cr)
    if ( not(status) ) then
      break
    end

    local msc = rdp.Request.MCSConnectInitial:new(v)
    local status, response = comm:exch(msc)
    comm:close()
    if ( status ) then
      if ( response.ccr and response.ccr.enc_cipher == v ) then
        table.insert(res_ciphers, ("%s: SUCCESS"):format(k))
      end
      res_ciphers.name = ("RDP Encryption level: %s"):format(ENC_LEVELS[response.ccr.enc_level] or "Unknown")

      if response.ccr.proto_version then
        proto_version = response.ccr.proto_version
      end
    elseif ( nmap.debugging() > 0 ) then
      table.insert(res_ciphers, ("%s: FAILURE"):format(k))
    end
  end
  return true, res_ciphers, proto_version
end

action = function(host, port)
  local result = {}

  local status, res_proto, proto_ver = enum_protocols(host, port)
  if ( not(status) ) then
    return res_proto
  end

  local status, res_ciphers, cipher_ver = enum_ciphers(host, port)
  if ( not(status) ) then
    return res_ciphers
  end

  table.insert(result, res_proto)
  table.insert(result, res_ciphers)
  if proto_ver then
    table.insert(result, proto_ver)
  elseif cipher_ver then
    table.insert(result, cipher_ver)
  end
  return stdnse.format_output(true, result)
end
