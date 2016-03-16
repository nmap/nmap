local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Finds up to 100 domain names which use the same name server as the target by querying the Robtex service at http://www.robtex.com/dns/.

The target must be specified by DNS name, not IP address.
]]

---
-- @usage
-- nmap --script http-robtex-shared-ns
--
-- @outt
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

author = "Arturo 'Buanzo' Busleiman"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "external"}

local function unescape(s)
    return string.gsub(s, "\\x(%x%x)", function(hex)
        return string.char(tonumber(hex, 16))
    end)
end


--- Scrape domains sharing name servers from robtex website
-- @param data string containing the retrieved web page
-- @return table containing the resolved host names
function parse_robtex_response(data)
  local result = {}

  if ( not(data) ) then
    return
  end

  -- cut out the section we're interested in
  data = data:match('<span id="shared[^"]*_pn_mn">.-<ol.->(.-)</ol>')

  -- process each html list item
  if data then
    for domain in data:gmatch("<li[^>]*>(.-)</li>") do
      domain = domain:gsub("<[^>]+>","")
      if ( domain ) then
        table.insert(result, domain)
      end
    end
  end

  return result
end

local function lookup_dns_server(data)
  return data:match("The primary name server is <a.->(.-)</a>.")
end

local function fetch_robtex_data(url)
  local htmldata = http.get("www.robtex.net", 443, url, {any_af=true})
  if ( not(htmldata) or not(htmldata.body) ) then
    return
  end

  -- fixup hex encodings
  return unescape(htmldata.body)
end

hostrule = function (host) return host.targetname end

action = function(host)
  local base_url = "/?dns=" .. host.targetname
  local data = fetch_robtex_data(base_url)
  local domains = parse_robtex_response(data)

  if ( not(domains) ) then
    local server = lookup_dns_server(data)
    if ( not(server) ) then
      return
    end
    local url = base_url:format(server)
    stdnse.debug2("Querying URL: %s", url)
    data = fetch_robtex_data(url)

    domains = parse_robtex_response(data)
  end

  if (domains and #domains > 0) then
    return stdnse.format_output(true, domains)
  end
end
