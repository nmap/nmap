local http = require "http"
local shortport = require "shortport"
local slaxml = require "slaxml"
local stdnse = require "stdnse"
local string = require "string"

description = [[Requests information from a Subversion repository.
]]

---
-- @usage nmap --script http-svn-info <target>
--
-- @args http-svn-info.url This is a URL relative to the scanned host eg. /default.html (default: /)
--
-- @output
-- 443/tcp open  https   syn-ack
-- | http-svn-info:
-- |   Path: .
-- |   URL: https://svn.nmap.org/
-- |   Relative URL: ^/
-- |   Repository Root: https://svn.nmap.org
-- |   Repository UUID: e0a8ed71-7df4-0310-8962-fdc924857419
-- |   Revision: 34938
-- |   Node Kind: directory
-- |   Last Changed Author: yang
-- |   Last Changed Rev: 34938
-- |_  Last Changed Date: Sun, 19 Jul 2015 13:49:59 GMT--
--
-- @xmloutput
-- <elem key="Path">.</elem>
-- <elem key="URL">https://svn.nmap.org/</elem>
-- <elem key="Relative URL">^/</elem>
-- <elem key="Repository Root">https://svn.nmap.org</elem>
-- <elem key="Repository UUID">e0a8ed71-7df4-0310-8962-fdc924857419</elem>
-- <elem key="Revision">34938</elem>
-- <elem key="Node Kind">directory</elem>
-- <elem key="Last Changed Author">yang</elem>
-- <elem key="Last Changed Rev">34938</elem>
-- <elem key="Last Changed Date">Sun, 19 Jul 2015 13:49:59 GMT</elem>


author = "Gyanendra Mishra"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}


portrule = shortport.http

local ELEMENTS = {
    ["repository-uuid"] =  "Repository UUID",
    ["version-name"] = "Last Changed Rev",
    ["creator-displayname"] = "Last Changed Author",
    ["getlastmodified"] = "Last Changed Date",
    ["baseline-relative-path"] = "Relative URL",
    ["href"] = "Repository Root",
    ["getcontentlength"] = "file"
}

local output_order = {
  "Last Changed Author",
  "Last Changed Rev",
  "Last Changed Date",
}

local function get_text_callback(store, name)
  if ELEMENTS[name] == nil then return end
  return function(content) store[ELEMENTS[name]] = content end
end

action = function(host, port)

  local url = stdnse.get_script_args(SCRIPT_NAME .. ".url") or "/"
  local output = {}
  local ordered_output = stdnse.output_table()

  local options = {
    header = {
      ["Depth"] = 0,
    },
  }

  local response = http.generic_request(host, port, "PROPFIND", url, options)
  if response and response.status == 207 then

    local parser = slaxml.parser:new()
    parser._call = {startElement = function(name)
      parser._call.text = get_text_callback(output, name) end,
      closeElement = function(name) parser._call.text = function() return nil end end
    }
    parser:parseSAX(response.body, {stripWhitespace=true})

    if next(output) then

      ordered_output["Path"] = url:match("/([^/]*)$"):len() > 0 and url:match("/([^/]*)$") or url:match("/([^/]*)/$") or "."
      if output["file"] then
        ordered_output["Name"] = url:match("/([^/]*)$")
      end

      ordered_output["URL"] = host.targetname and port.service .. "://" .. host.targetname .. url
      ordered_output["Relative URL"] = output["Relative URL"] and "^/" .. output["Relative URL"] or "^/"
      output["Repository Root"] = output["Repository Root"]:gsub("%/%!svn.*", ""):len() > 0 and output["Repository Root"]:gsub("%/%!svn.*", "")  or "/"
      ordered_output["Repository Root"] = port.service .. "://" .. host.targetname .. output["Repository Root"]
      ordered_output["Repository UUID"] = output["Repository UUID"]
      if url ~= output["Repository Root"] then
        local temp_output = {}
        response = http.generic_request(host, port, "PROPFIND", output["Repository Root"], options)
        if response and response.status == 207 then
          parser._call.startElement = function(name) parser._call.text = get_text_callback(temp_output, name) end
          parser:parseSAX(response.body, {stripWhitespace=true})
          ordered_output["Revision"] = temp_output["Last Changed Rev"]
        end
      else
        ordered_output["Revision"] = output["Last Changed Rev"]
      end

      if not output["file"] then
        ordered_output["Node Kind"] = "directory"
      else
        ordered_output["Node Kind"] = "file"
      end

      for _, value in ipairs(output_order) do
        ordered_output[value] = output[value]
      end

      return ordered_output
    end
  end
end
