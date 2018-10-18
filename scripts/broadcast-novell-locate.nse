local ipOps = require "ipOps"
local srvloc = require "srvloc"
local stdnse = require "stdnse"
local stringaux = require "stringaux"
local table = require "table"

description = [[
Attempts to use the Service Location Protocol to discover Novell NetWare Core Protocol (NCP) servers.
]]

---
--
--@output
-- Pre-scan script results:
-- | broadcast-novell-locate:
-- |   Tree name: CQURE-LABTREE
-- |   Server name: linux-l84t
-- |   Addresses
-- |_    192.168.56.33
--
--

-- Version 0.1
-- Created 04/26/2011 - v0.1 - created by Patrik Karlsson

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}


prerule = function() return true end

function action()

  local helper = srvloc.Helper:new()

  local status, bindery = helper:ServiceRequest("bindery.novell", "DEFAULT")
  if ( not(status) or not(bindery) ) then
    helper:close()
    return
  end
  bindery = bindery[1]
  local srvname = bindery:match("%/%/%/(.*)$")

  local status, attrib = helper:AttributeRequest(bindery, "DEFAULT", "svcaddr-ws")
  helper:close()
  attrib = attrib:match("^%(svcaddr%-ws=(.*)%)$")
  if ( not(attrib) ) then return end

  local attribs = stringaux.strsplit(",", attrib)
  if ( not(attribs) ) then return end

  local addrs = { name = "Addresses"}
  local ips = {}
  for _, attr in ipairs(attribs) do
    local addr = attr:match("^%d*%-%d*%-%d*%-(........)")
    if ( addr ) then
      local ip = ipOps.str_to_ip(stdnse.fromhex(addr))

      if ( not(ips[ip]) ) then
        table.insert(addrs, ip)
        ips[ip] = ip
      end
    end
  end

  local output = {}
  local status, treename = helper:ServiceRequest("ndap.novell", "DEFAULT")
  if ( status ) then
    treename = treename[1]
    treename = treename:match("%/%/%/(.*)%.$")
    table.insert(output, ("Tree name: %s"):format(treename))
  end
  table.insert(output, ("Server name: %s"):format(srvname))
  table.insert(output, addrs)

  return stdnse.format_output(true, output)
end
