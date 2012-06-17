local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Finds up to 100 domain names which use the same name server as the target by querying the Robtex service at http://www.robtex.com/dns/.

The target must be specified by DNS name, not IP address.
]];

---
-- @usage
-- nmap --script http-robtex-shared-ns
--
-- @output
-- Host script results:
-- | http-robtex-shared-ns:
-- |   example.edu
-- |   example.net
-- |   example.edu
-- |_  example.net
-- (some results omitted for brevity)
--
-- TODO:
-- * Add list of nameservers, or group output accordingly
--

author = "Arturo Busleiman <buanzo@buanzo.com.ar>";
license = "Same as Nmap--See http://nmap.org/book/man-legal.html";
categories = {
  "discovery",
  "safe",
  "external"
};


--- Scrape domains sharing name servers from robtex website
-- @param data string containing the retrieved web page
-- @return table containing the resolved host names
function parse_robtex_response (data)
  local result = {};

  for linkhref, ns, domain in string.gmatch(data, "<a href=\"(.-)%.html#shared\"%s*title=\"using ns (.-)\">(.-)</a>") do
    if not table.contains(result, domain) then
      table.insert(result, domain);
    end
  end
  return result;
end

hostrule = function (host)
  return host.targetname
end;

action = function (host)
  local link = "http://www.robtex.com/dns/" .. host.targetname .. ".html";
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
