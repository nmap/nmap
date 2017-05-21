local http = require "http"
local ipOps = require "ipOps"
local stdnse = require "stdnse"
local string = require "string"
local slaxml = require "slaxml"
local table = require "table"

description = [[
Discovers hostnames that resolve to the target's IP address by querying the online Robtex service at http://ip.robtex.com/.
]]

---
-- @usage
-- nmap --script hostmap-robtex -sn -Pn scanme.nmap.org
--
-- @output
-- | hostmap-robtex:
-- |   hosts:
-- |_    scanme.nmap.org
--
-- @xmloutput
-- <table key="hosts">
--  <elem>nmap.org</elem>
-- </table>
---

author = "Arturo 'Buanzo' Busleiman"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {
  "discovery",
  "safe",
  "external"
}


--- Scrape domains sharing target host ip from robtex website
--
-- //section[@id="x_shared"]//li//text()
-- @param data string containing the retrieved web page
-- @return table containing the host names sharing host.ip
function parse_robtex_response (data)
  local in_li = false
  local result = {}

  local parser = slaxml.parser:new({
      startElement = function(name, nsURI, nsPrefix)
        in_li = in_li or name == "li"
      end,
      closeElement = function(name, nsURI, nsPrefix)
        if name == "li" then
          in_li = false
        end
      end,
      text = function(text)
        if in_li then
          result[#result+1] = text
        end
      end,
    })
  parser:parseSAX(data:match('<section[^>]-id="x_shared".-</section>'))

  return result
end

hostrule = function (host)
  return not ipOps.isPrivate(host.ip)
end

action = function (host)
  local link = "https://www.robtex.com/en/advisory/ip/" .. host.ip:gsub("%.", "/") .. "/"
  local htmldata = http.get_url(link)
  local domains = parse_robtex_response(htmldata.body)
  local output_tab = stdnse.output_table()
  if (#domains > 0) then
    output_tab.hosts = domains
  end
  return output_tab
end
