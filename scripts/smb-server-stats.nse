local msrpc = require "msrpc"
local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Attempts to grab the server's statistics over SMB and MSRPC, which uses TCP
ports 445 or 139.

An administrator account is required to pull these statistics on most versions
of Windows, and Vista and above require UAC to be turned down.

Some of the numbers returned here don't feel right to me, but they're definitely
the numbers that Windows returns. Take the values here with a grain of salt.

These statistics are found using a single call to a SRVSVC function,
<code>NetServerGetStatistics</code>. This packet is parsed incorrectly by Wireshark,
up to version 1.0.3 (and possibly higher).
]]

---
-- @usage
-- nmap --script smb-server-stats.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-server-stats.nse -p U:137,T:139 <host>
--
-- @output
-- Host script results:
-- |  smb-server-stats:
-- |  |  Server statistics collected since 2009-09-22 09:56:00 (48d5h53m36s):
-- |  |  |  6513655 bytes (1.56 b/s) sent, 40075383 bytes (9.61 b/s) received
-- |_ |_ |_ 19323 failed logins, 179 permission errors, 0 system errors, 0 print jobs, 2921 files opened
-----------------------------------------------------------------------

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive"}
dependencies = {"smb-brute"}


hostrule = function(host)
  return smb.get_port(host) ~= nil
end

action = function(host)

  local result, stats
  local response = {}
  local subresponse = {}

  result, stats = msrpc.get_server_stats(host)

  if(result == false) then
    return stdnse.format_output(false, response)
  end

  table.insert(response, string.format("Server statistics collected since %s (%s):", stats['start_str'], stats['period_str']))
  table.insert(subresponse, string.format("%d bytes (%.2f b/s) sent, %d bytes (%.2f b/s) received", stats['bytessent'], stats['bytessentpersecond'], stats['bytesrcvd'], stats['bytesrcvdpersecond']))
  table.insert(subresponse, string.format("%d failed logins, %d permission errors, %d system errors, %d print jobs, %d files opened", stats['pwerrors'], stats['permerrors'], stats['syserrors'], stats['jobsqueued'], stats['fopens']))
  table.insert(response, subresponse)

  return stdnse.format_output(true, response)
end


