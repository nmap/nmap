local http = require "http"
local ipOps = require "ipOps"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Obtains up to 100 forward DNS names for a target IP address by querying the Robtex service (http://www.robtex.com/ip/).
]]

---
-- @usage
-- nmap --script http-robtex-reverse-ip --script-args http-robtex-reverse-ip.host='<ip>'
--
-- @output
-- Pre-scan script results:
-- | http-robtex-reverse-ip:
-- |   *.insecure.org
-- |   *.nmap.com
-- |   *.nmap.org
-- |   *.seclists.org
-- |   insecure.com
-- |   insecure.org
-- |   lists.insecure.org
-- |   nmap.com
-- |   nmap.net
-- |   nmap.org
-- |   seclists.org
-- |   sectools.org
-- |   web.insecure.org
-- |   www.insecure.org
-- |   www.nmap.com
-- |   www.nmap.org
-- |   www.seclists.org
-- |_  images.insecure.org
--
-- @args http-robtex-reverse-ip.host IPv4 address of the host to lookup
--

author = "riemann"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "external"}


--- Scrape reverse ip information from robtex website
-- @param data string containing the retrieved web page
-- @return table containing the resolved host names
function parse_robtex_response(data)
  local data = data:match("<span id=\"shared_ma\">.-<ol.->(.-)</ol>")
  local result = {}
  if data then
    for domain in data:gmatch("<li[^>]*>(.-)</li>") do
      domain = domain:gsub("<[^>]+>","")
      table.insert(result, domain)
    end
  end
  return result
end

prerule = function() return stdnse.get_script_args("http-robtex-reverse-ip.host") ~= nil end

action = function(host, port)

  local target = stdnse.get_script_args("http-robtex-reverse-ip.host")
  local ip = ipOps.ip_to_str(target)
  if ( not(ip) or #ip ~= 4 ) then
    return stdnse.format_output(false, "The argument \"http-robtex-reverse-ip.host\" did not contain a valid IPv4 address")
  end

  local link = "/ip/"..target..".html"
  local htmldata = http.get("www.robtex.com", 443, link, {any_af=true})
  local domains = parse_robtex_response(htmldata.body)
  if ( #domains > 0 ) then
    return stdnse.format_output(true, domains)
  end
end
