local http = require "http"
local shortport = require "shortport"
local slaxml = require "slaxml"
local stdnse = require "stdnse"
local tab = require "tab"
local table = require "table"

description = [[Enumerates users of a Subversion repository by examining logs of most recent commits.
]]

---
-- @usage nmap --script http-svn-enum <target>
--
-- @args http-svn-enum.count The number of logs to fetch. Defaults to the last 1000 commits.
-- @args http-svn-enum.url This is a URL relative to the scanned host eg. /default.html (default: /).
--
-- @output
-- PORT    STATE SERVICE REASON
-- 443/tcp open  https   syn-ack
-- | http-svn-enum:
-- | Author   Count  Revision  Date
-- | gyani    183    34965     2015-07-24
-- | robert   1      34566     2015-06-02
-- | david    2      34785     2015-06-28
--
-- @xmloutput
-- <table></table>
-- <table>
--   <elem>Author</elem>
--   <elem>Count</elem>
--   <elem>Revision</elem>
--   <elem>Date</elem>
-- </table>
-- <table>
--   <elem>gyani</elem>
--   <elem>183</elem>
--   <elem>34965</elem>
--   <elem>2015-07-24</elem>
-- </table>
-- <table>
--   <elem>robert</elem>
--   <elem>1</elem>
--   <elem>34566</elem>
--   <elem>2015-06-02</elem>
-- </table>
-- <table>
--   <elem>david</elem>
--   <elem>2</elem>
--   <elem>34785</elem>
--   <elem>2015-06-28</elem>
-- </table>

author = "Gyanendra Mishra"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

local ELEMENTS = {
  ["creator-displayname"] = "author",
  ["version-name"] = "version",
  ["date"] = "date",
}

local function get_callback(name, unames, temp)
  if ELEMENTS[name] then
    return function(content)
      if not content then content = "unknown" end --useful for "nil" authors
      temp[ELEMENTS[name]] = name == "date" and content:sub(1, 10) or content
      if temp.date and temp.version and temp.author then
        unames[temp.author] = {unames[temp.author] and unames[temp.author][1] + 1 or 1, temp.version, temp.date}
      end
    end
  end
end

portrule = shortport.http

action = function(host, port)

  local count = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".count")) or 1000
  local url = stdnse.get_script_args(SCRIPT_NAME .. ".url") or "/"
  local output, revision, unames  = tab.new(), nil, {}

  local options = {
    header = {
      ["Depth"] = 0,
    },
  }

  -- first we fetch the current revision number
  local response = http.generic_request(host, port, "PROPFIND", url, options)
  if response and response.status == 207 then

    local parser = slaxml.parser:new()
    parser._call = {startElement = function(name)
      parser._call.text =  name == "version-name" and function(content) revision = tonumber(content) end end,
      closeElement = function(name) parser._call.text = function() return nil end end
    }
    parser:parseSAX(response.body, {stripWhitespace=true})

    if revision then

      local start_revision = revision > count and revision - count or 1
      local content = '<?xml version="1.0"?> <S:log-report xmlns:S="svn:"> <S:start-revision>'.. start_revision .. '</S:start-revision> <S:discover-changed-paths/> </S:log-report>'

      options = {
        header = {
          ["Depth"] = 1,
        },
        content = content,
      }

      local temp = {}
      response = http.generic_request(host, port, "REPORT", url, options)
      if response and response.status == 200 then

        parser._call.startElement = function(name) parser._call.text = get_callback(name, unames, temp) end
        parser._call.closeElement = function(name) if name == "log-item" then temp ={} end parser._call.text = function() return nil end end
        parser:parseSAX(response.body, {stripWhitespace=true})

        tab.nextrow(output)
        tab.addrow(output, "Author", "Count", "Revision", "Date")

        for revision_author, data in pairs(unames) do
          tab.addrow(output, revision_author, data[1], data[2], data[3])
        end

        if next(unames) then return output end
      end
    end
  end
end

