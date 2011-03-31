description = [[

This script grabs Google Analytics and Adsense IDs.
They could be used to further look for related websites (that have
the same owner.)

]]

---
-- @args http-affiliate-id.url-path The path to request. Defaults to
-- <code>/</code>.
--
-- @usage
-- nmap --script=http-affiliate-id.nse --script-args http-affiliate-id.url-path=/website <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-affiliate-id: 
-- |  Google Analytics ID: UA-XXXXXXXX-XX
-- |_ Google Adsense ID: pub-YYYYYYYYYYYYYYYY

author = "Hani Benhabiles, Daniel Miller"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}

require 'shortport'
require 'http'
require 'pcre'
require 'stdnse'

portrule = shortport.port_or_service( {80,443}, {"http","https"} )

action = function(host, port)
	local url_path, body,  analyticsid, adsenseid, result
	result = ""
	url_path = stdnse.get_script_args("http-affiliate-id.url-path") or "/"
	body = http.get( host, port, url_path).body

	-- these are the regular expressions for affiliate IDs
	local affiliates = {
	["Google Analytics ID"] = "(?P<id>UA-[0-9]{6,9}-[0-9]{1,2})",
	["Google Adsense ID"] = "(?P<id>pub-[0-9]{16,16})",
	["Amazon Associates ID"] = "href=\"http://www.amazon.com/[^\"]*[&;]tag=(?P<id>\\w+-\\d+)",
	}


	-- Here goes affiliate matching
	for name,re in pairs(affiliates) do
		local regex, limit, limit2, matches, affiliateid
		regex = pcre.new(re, 0, "C")
		limit, limit2, matches = regex:match(body)
		if limit ~= nil then
			affiliateid = matches["id"]
			result = result .. "\n " .. name .. ": " .. affiliateid
		end
	end

	if result ~= "" then
	  return result
	end
end
