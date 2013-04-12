local http = require "http"
local ipOps = require "ipOps"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Discovers hostnames that resolve to the target's IP address by querying the Robtex service at http://www.robtex.com/dns/.
]];

---
-- @usage
-- nmap --script hostmap-robtex
--
-- @output
-- Host script results:
-- | hostmap-robtex:
-- |   example.edu
-- |   example.net
-- |   example.edu
-- |_  example.net
-- (some results omitted for brevity)
--

author = "Arturo Busleiman <buanzo@buanzo.com.ar>";
license = "Same as Nmap--See http://nmap.org/book/man-legal.html";
categories = {
  "discovery",
  "safe",
  "external"
};


--- Scrape domains sharing target host ip from robtex website
-- @param data string containing the retrieved web page
-- @return table containing the host names sharing host.ip
function parse_robtex_response (data)
  local result = {};

  for domain in string.gmatch(data, "<span id=\"dns[0-9]+\"><a href=\"//[a-z]+.robtex.com/([^\"]-)%.html\"") do
    if not table.contains(result, domain) then
      table.insert(result, domain);
    end
  end
  return result;
end

hostrule = function (host)
  return not ipOps.isPrivate(host.ip)
end;

action = function (host)
  local link = "http://ip.robtex.com/" .. host.ip .. ".html";
  local htmldata = http.get_url(link);
  local domains = parse_robtex_response(htmldata.body);
  if (#domains > 0) then
    return stdnse.format_output(true, domains);
  end
end;

function table.contains (table, element)
  for _, value in pairs(table) do
    if value == element then
      return true;
    end
  end
  return false;
end
