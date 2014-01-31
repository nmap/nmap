local http = require "http"
local ipOps = require "ipOps"
local stdnse = require "stdnse"
local string = require "string"
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
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "external"}


--- Scrape reverse ip informations from robtex website
-- @param data string containing the retrieved web page
-- @return table containing the resolved host names
function parse_robtex_response(data)
  local data = string.gsub(data,"\r?\n","")
  local result = {}
  for href, link in string.gmatch(data,"<li><a href=\"([^\"^']-)\" >([^\"^']-)</a></li>") do
    table.insert(result, link)
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

  local link = "https://www.robtex.com/ip/"..target..".html"
  local htmldata = http.get_url(link)
  local domains = parse_robtex_response(htmldata.body)
  if ( #domains > 0 ) then
    return stdnse.format_output(true, domains)
  end
end
