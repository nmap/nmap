local afp = require "afp"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Shows AFP server information. This information includes the server's
hostname, IPv4 and IPv6 addresses, and hardware type (for example
<code>Macmini</code> or <code>MacBookPro</code>).
]]

---
-- @output
-- PORT    STATE SERVICE
-- 548/tcp open  afp
-- | afp-serverinfo:
-- |   Server Flags:
-- |     Flags hex: 0x837d
-- |     Super Client: true
-- |     UUIDs: false
-- |     UTF8 Server Name: true
-- |     Open Directory: true
-- |     Reconnect: false
-- |     Server Notifications: true
-- |     TCP/IP: true
-- |     Server Signature: true
-- |     Server Messages: true
-- |     Password Saving Prohibited: true
-- |     Password Changing: false
-- |     Copy File: true
-- |   Server Name: foobardigital
-- |   Machine Type: Netatalk
-- |   AFP Versions: AFPVersion 1.1, AFPVersion 2.0, AFPVersion 2.1, AFP2.2, AFPX03, AFP3.1
-- |   UAMs: DHX2
-- |   Server Signature: bbeb480e00000000bbeb480e00000000
-- |   Network Addresses:
-- |     192.0.2.235
-- |     foobardigital.com
-- |_  UTF8 Server Name: foobardigital
--
-- @xmloutput
-- <table key="Server Flags">
--   <elem key="Flags hex">0x837d</elem>
--   <elem key="Super Client">true</elem>
--   <elem key="UUIDs">false</elem>
--   <elem key="UTF8 Server Name">true</elem>
--   <elem key="Open Directory">true</elem>
--   <elem key="Reconnect">false</elem>
--   <elem key="Server Notifications">true</elem>
--   <elem key="TCP/IP">true</elem>
--   <elem key="Server Signature">true</elem>
--   <elem key="Server Messages">true</elem>
--   <elem key="Password Saving Prohibited">true</elem>
--   <elem key="Password Changing">false</elem>
--   <elem key="Copy File">true</elem>
-- </table>
-- <elem key="Server Name">foobardigital</elem>
-- <elem key="Machine Type">Netatalk</elem>
-- <table key="AFP Versions">
--   <elem>AFPVersion 1.1</elem>
--   <elem>AFPVersion 2.0</elem>
--   <elem>AFPVersion 2.1</elem>
--   <elem>AFP2.2</elem>
--   <elem>AFPX03</elem>
--   <elem>AFP3.1</elem>
-- </table>
-- <table key="UAMs">
--   <elem>DHX2</elem>
-- </table>
-- <elem key="Server Signature">
-- bbeb480e00000000bbeb480e00000000</elem>
-- <table key="Network Addresses">
--   <elem>192.0.2.235</elem>
--   <elem>foobardigital.com</elem>
-- </table>
-- <elem key="UTF8 Server Name">foobardigital</elem>

-- Version 0.2
-- Created 2010/02/09 - v0.1 - created by Andrew Orr
-- Revised 2010/02/10 - v0.2 - added checks for optional fields
-- Revised 2015/02/25 - v0.3 - XML structured output

author = "Andrew Orr"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


portrule = shortport.port_or_service(548, "afp")

local commasep = {
  __tostring = function (t)
    return table.concat(t, ", ")
  end
}

action = function(host, port)

  local socket = nmap.new_socket()
  local status
  local result = stdnse.output_table()
  local temp

  -- set a reasonable timeout value
  socket:set_timeout(5000)

  -- do some exception handling / cleanup
  local catch = function()
    socket:close()
  end

  local try = nmap.new_try(catch)

  try( socket:connect(host, port) )

  -- get our data
  local afp_proto = afp.Proto:new( { socket=socket } )

  local response = afp_proto:fp_get_server_info( socket )
  response = response.result

  -- all the server information is output in the order it occurs in the server
  -- response. It might be better rearranged?

  -- output the server flags nicely
  -- Would like to just pass response.flags, but key ordering would be more
  -- work than it's worth.
  local flags = stdnse.output_table()
  flags["Flags hex"] = ("0x%04x"):format(response.flags.raw)
  flags["Super Client"] = response.flags.SuperClient
  flags["UUIDs"] = response.flags.UUIDs
  flags["UTF8 Server Name"] = response.flags.UTF8ServerName
  flags["Open Directory"] = response.flags.OpenDirectory
  flags["Reconnect"] = response.flags.Reconnect
  flags["Server Notifications"] = response.flags.ServerNotifications
  flags["TCP/IP"] = response.flags.TCPoverIP
  flags["Server Signature"] = response.flags.ServerSignature
  flags["Server Messages"] = response.flags.ServerMessages
  flags["Password Saving Prohibited"] = response.flags.NoPasswordSaving
  flags["Password Changing"] = response.flags.ChangeablePasswords
  flags["Copy File"] = response.flags.CopyFile

  result["Server Flags"] = flags

  -- other info
  result["Server Name"] = response.server_name
  result["Machine Type"] = response.machine_type

  -- list the supported AFP versions
  result["AFP Versions"] = response.afp_versions
  setmetatable(result["AFP Versions"], commasep)

  -- list the supported UAMs (User Authentication Modules)
  result["UAMs"] = response.uams
  setmetatable(result["UAMs"], commasep)

  -- server signature, not sure of the format here so just showing a hex string
  if response.flags.ServerSignature then
    result["Server Signature"] = stdnse.tohex(response.server_signature)
  end

  -- listing the network addresses one line each
  -- the default for Mac OS X AFP server is to bind everywhere, so this will
  -- list all network interfaces that the machine has
  if response.network_addresses_count > 0 then
    result["Network Addresses"] = response.network_addresses
  end

  -- similar to above
  if response.directory_names_count > 0 then
    result["Directory Names"] = response.directory_names
  end

  -- and finally the utf8 server name
  if response.flags.UTF8ServerName then
    result["UTF8 Server Name"] = response.utf8_server_name
  end

  return result
end
