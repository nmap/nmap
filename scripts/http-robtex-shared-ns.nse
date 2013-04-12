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

author = "Arturo 'Buanzo' Busleiman"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
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

	-- cut out the section we're interested in
	data = data:match("<span id=\\\"sharednss?\\\">.-<ul.->(.-)</ul>")
	if ( not(data) ) then
		return
	end
	
	-- process each html list item
	for li in data:gmatch("<li>(.-)</li>") do
		local domain = li:match("<a.->(.*)</a>")
		if ( domain ) then
			table.insert(result, domain)
		end
	end
	
  return result
end

local function lookup_dns_server(data)
	return data:match("The primary name server is <a.->(.-)</a>.")
end

local function fetch_robtex_data(url)
  local htmldata = http.get_url(url)
	if ( not(htmldata) or not(htmldata.body) ) then
		return
	end
  
	local url = htmldata.body:match("var%s*uurl%s*='([^']*)")
	if ( not(url) ) then
		return
	end
	
	-- retreive the url having the shared dns information
	htmldata = http.get_url(url)
	if ( not(htmldata) or not(htmldata.body) ) then
		return
	end
	
	-- fixup line breaks
	htmldata = htmldata.body:gsub("(.-)\\\r?\n", "%1")

	-- fixup hex encodings
	return unescape(htmldata)
end

hostrule = function (host) return host.targetname end

action = function(host)
	local base_url = "http://www.robtex.com/dns/%s.html"
	local data = fetch_robtex_data(base_url:format(host.targetname))
  local domains = parse_robtex_response(data)
	
	if ( not(domains) ) then
		local server = lookup_dns_server(data)
		if ( not(server) ) then
			return
		end
		local url = base_url:format(server)
		stdnse.print_debug(2, "%s: Querying URL: %s", SCRIPT_NAME, url)
		data = fetch_robtex_data(url)
		domains = parse_robtex_response(data)
	end

  if (domains and #domains > 0) then
    return stdnse.format_output(true, domains)
  end
end
