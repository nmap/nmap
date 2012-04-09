description = [[
Tries to find hostnames that resolve to the target's IP address by querying the Robtex service at http://www.robtex.com/dns/.
]];

---
-- @usage
-- nmap --script hostmap-robtex --script-args hostmap-robtex.host='<domain_name>'
--
-- @args hostmap-robtex.host IPv4 address of the host to lookup
--
-- @output
-- Pre-scan script results:
-- | hostmap-robtex:
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

require "http";
require "shortport";

--- Scrape domains sharing name servers from robtex website
-- @param data string containing the retrieved web page
-- @return table containing the resolved host names
function parse_robtex_response (data)
  local result = {};

  for linkhref, ns, domain in string.gmatch(data, "<a href=\"(.-)\.html#shared\" title=\"using ns (.-)\">(.-)</a>") do
    if not table.contains(result, domain) then
      table.insert(result, domain);
    end
  end
  return result;
end

prerule = function ()
  return stdnse.get_script_args("hostmap-robtex.host") ~= nil;
end;

action = function (host, port)
  local target = stdnse.get_script_args("hostmap-robtex.host");

  local link = "http://www.robtex.com/dns/" .. target .. ".html";
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
