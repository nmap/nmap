local citrixxml = require "citrixxml"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Extracts the name of the server farm and member servers from Citrix XML
service.
]]

---
-- @usage
-- nmap --script=citrix-enum-servers-xml -p 80,443,8080 <host>
--
-- @output
-- PORT     STATE SERVICE    REASON
-- 8080/tcp open  http-proxy syn-ack
-- | citrix-enum-servers-xml:
-- |   CITRIX-SRV01
-- |_  CITRIX-SRV01

-- Version 0.2

-- Created 11/26/2009 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 12/02/2009 - v0.2 - Use stdnse.format_ouput for output

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.portnumber({8080,80,443}, "tcp")


action = function(host, port)

  local xmldata = citrixxml.request_server_data(host, port)
  local servers = citrixxml.parse_server_data_response(xmldata)
  local response = {}

  for _, srv in ipairs(servers) do
    table.insert(response, srv)
  end

  return stdnse.format_output(true, response)

end
