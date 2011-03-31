description = [[
Grabs affiliate network IDs from an HTML page. These can be used to
identify pages with the same owner.

Supported IDs:
* Google Analytics
* Google AdSense
* Amazon Associates
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
-- |   Amazon Associates ID: XXXX-XX
-- |   Google Adsense ID: pub-YYYY
-- |_  Google Analytics ID: UA-ZZZZ-ZZ

author = "Hani Benhabiles, Daniel Miller"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}

require 'shortport'
require 'http'
require 'pcre'
require 'stdnse'

-- these are the regular expressions for affiliate IDs
local AFFILIATE_PATTERNS = {
	["Google Analytics ID"] = "(?P<id>UA-[0-9]{6,9}-[0-9]{1,2})",
	["Google Adsense ID"] = "(?P<id>pub-[0-9]{16,16})",
	["Amazon Associates ID"] = "href=\"http://www.amazon.com/[^\"]*[&;]tag=(?P<id>\\w+-\\d+)",
}

portrule = shortport.http

action = function(host, port)
	local url_path, body, result
	result = {}
	url_path = stdnse.get_script_args("http-affiliate-id.url-path") or "/"
	body = http.get(host, port, url_path).body

	-- Here goes affiliate matching
	for name, re in pairs(AFFILIATE_PATTERNS) do
		local regex, limit, limit2, matches, affiliateid
		regex = pcre.new(re, 0, "C")
		limit, limit2, matches = regex:match(body)
		if limit ~= nil then
			affiliateid = matches["id"]
			result[#result + 1] = name .. ": " .. affiliateid
		end
	end

	return stdnse.format_output(true, result)
end
