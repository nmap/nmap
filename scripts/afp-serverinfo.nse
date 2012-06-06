local afp = require "afp"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
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
-- |   | Server Flags: 0x8ffb
-- |   |   Super Client: Yes
-- |   |   UUIDs: Yes
-- |   |   UTF8 Server Name: Yes
-- |   |   Open Directory: Yes
-- |   |   Reconnect: Yes
-- |   |   Server Notifications: Yes
-- |   |   TCP/IP: Yes
-- |   |   Server Signature: Yes
-- |   |   ServerMessages: Yes
-- |   |   Password Saving Prohibited: No
-- |   |   Password Changing: Yes
-- |   |_  Copy File: Yes
-- |   Server Name: mac-mini
-- |   Machine Type: Macmini2,1
-- |   AFP Versions: AFP3.3, AFP3.2, AFP3.1, AFPX03
-- |   UAMs: DHCAST128, DHX2, Recon1, Client Krb v2, No User Authent
-- |   Server Signature: 000000000000100080000016cbaed4ac
-- |   Network Address 1: 192.168.0.190:548
-- |   Network Address 2: [fe80:0000:0000:0000:0216:cbff:feae:d4ac]:548
-- |   Network Address 3: 192.168.0.190
-- |   Directory Name 1: afpserver/LKDC:SHA1.02EBDBCFABF3C222D6FE9FE4D908893568387654@LKDC:SHA1.02EBDBCFABF3C222D6FE9FE4D908893568387654
-- |_  UTF8 Server Name: mac-mini

-- Version 0.2
-- Created 2010/02/09 - v0.1 - created by Andrew Orr
-- Revised 2010/02/10 - v0.2 - added checks for optional fields

author = "Andrew Orr"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


portrule = shortport.portnumber(548, "tcp")

action = function(host, port)

  local socket = nmap.new_socket()
  local status
  local result = {}
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
  table.insert(result, string.format("| Server Flags: 0x%04x", response.flags.raw))
  table.insert(result, string.format("|   Super Client: %s", response.flags.SuperClient and "Yes" or "No"))
  table.insert(result, string.format("|   UUIDs: %s", response.flags.UUIDs and "Yes" or "No"))
  table.insert(result, string.format("|   UTF8 Server Name: %s", response.flags.UTF8ServerName and "Yes" or "No"))
  table.insert(result, string.format("|   Open Directory: %s", response.flags.OpenDirectory and "Yes" or "No"))
  table.insert(result, string.format("|   Reconnect: %s", response.flags.Reconnect and "Yes" or "No"))
  table.insert(result, string.format("|   Server Notifications: %s", response.flags.ServerNotifications and "Yes" or "No"))
  table.insert(result, string.format("|   TCP/IP: %s", response.flags.TCPoverIP and "Yes" or "No"))
  table.insert(result, string.format("|   Server Signature: %s", response.flags.ServerSignature and "Yes" or "No"))
  table.insert(result, string.format("|   ServerMessages: %s", response.flags.ServerMessages and "Yes" or "No"))
  table.insert(result, string.format("|   Password Saving Prohibited: %s", response.flags.NoPasswordSaving and "Yes" or "No"))
  table.insert(result, string.format("|   Password Changing: %s", response.flags.ChangeablePasswords and "Yes" or "No"))
  table.insert(result, string.format("|_  Copy File: %s", response.flags.CopyFile and "Yes" or "No")) 

  -- other info
  table.insert(result, string.format("Server Name: %s", response.server_name))
  table.insert(result, string.format("Machine Type: %s", response.machine_type))
  
  -- list the supported AFP versions
  temp = "AFP Versions: "
  for i = 1, response.afp_version_count-1 do
    temp = temp .. response.afp_versions[i] .. ", "
  end
  temp = temp .. response.afp_versions[response.afp_version_count]
  table.insert(result, temp)
  
  -- list the supported UAMs (User Authentication Modules)
  temp = "UAMs: "
  for i = 1, response.uam_count-1 do
    temp = temp .. response.uams[i] .. ", "
  end
  temp = temp .. response.uams[response.uam_count]
  table.insert(result, temp)
  
  -- server signature, not sure of the format here so just showing a hex string
  if response.flags.ServerSignature then
    table.insert(result, string.format("Server Signature: %s", stdnse.tohex(response.server_signature)))
  end
  
  -- listing the network addresses one line each
  -- the default for Mac OS X AFP server is to bind everywhere, so this will
  -- list all network interfaces that the machine has
  for i = 1, response.network_addresses_count do
    table.insert(result, string.format("Network Address %d: %s", i, response.network_addresses[i]))
  end
  
  -- similar to above
  for i = 1, response.directory_names_count do
    table.insert(result, string.format("Directory Name %d: %s", i, response.directory_names[i]))
  end
  
  -- and finally the utf8 server name
  if response.flags.UTF8ServerName then
    table.insert(result, string.format("UTF8 Server Name: %s", response.utf8_server_name))
  end
  
  return stdnse.format_output(true, result)
end
