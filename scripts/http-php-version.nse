description = [[
Attempts to retrieve the PHP version from a web server. PHP has a number
of magic queries that return images or text that can vary with the PHP
version. This script uses the following queries:
* <code>/?=PHPE9568F36-D428-11d2-A769-00AA001ACF42</code>: gets a GIF logo, which changes on April Fool's Day.
* <code>/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000</code>: gets an HTML credits page.

A list of magic queries is at http://www.0php.com/php_easter_egg.php.
The script also checks if any header field value starts with
<code>"PHP"</code> and reports that value if found.
]]

---
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-php-version: Versions from logo query (less accurate): 4.3.11, 4.4.0 - 4.4.4, 4.4.9, 5.0.5-2ubuntu1.1, 5.0.5-pl3-gentoo, 5.1.0 - 5.1.2
-- | Versions from credits query (more accurate): 5.0.5
-- |_Version from header x-powered-by: PHP/5.0.5

author = "Ange Gutek"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require "http"
require "shortport"

portrule = shortport.port_or_service({80, 443, 8080, 8443}, {"http", "https", "http-alt", "https-alt"})

-- These are the magic queries that return fingerprintable data.
local LOGO_QUERY = "/?=PHPE9568F36-D428-11d2-A769-00AA001ACF42"
local CREDITS_QUERY = "/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000"

local LOGO_HASHES = {
	-- www.psychreport.com www.myxeau.com
	["4b2c92409cf0bcf465d199e93a15ac3f"] = {"4.3.11", "4.4.0 - 4.4.4", "4.4.9", "5.0.5-2ubuntu1.1", "5.0.5-pl3-gentoo", "5.1.0 - 5.1.2"},
	-- www.168.hk
	["a57bd73e27be03a62dd6b3e1b537a72c"] = {"PHP4u 3.0", "4.3.2 - 4.3.10"},
	-- www.patelecningbo.com
	["37e194b799d4aaff10e39c4e3b2679a2"] = {"4.3.1", "5.0.0", "5.0.3"},
	-- www.pamzylove.com
	["50caaf268b4f3d260d720a1a29c5fe21"] = {"5.1.4", "5.2.X"},
	-- 206.230.28.196, www.security.lutsk.ua/gb/gb2.php
	["85be3b4be7bfe839cbb3b4f2d30ff983"] = {"4.0.1pl2", "4.1.2", "4.2.2", "4.2.3"},
	["fb3bbd9ccc4b3d9e0b3be89c5ff98a14"] = {"5.3.1RC3", "5.3.1"},
}

local CREDITS_HASHES = {
	-- www.psychreport.com www.myxeau.com
	["50ac182f03fc56a719a41fc1786d937d"] = {"4.3.11", "4.4.0 - 4.4.4", "4.4.9", "5.0.5-2ubuntu1.1", "5.0.5-pl3-gentoo", "5.1.0 - 5.1.2"},
	["6be3565cdd38e717e4eb96868d9be141"] = {"5.0.5"},
	-- www.168.hk
	["913ec921cf487109084a518f91e70859"] = {"PHP4u 3.0", "4.3.2", "4.3.3", "4.3.6", "4.3.8 - 4.3.10"},
	["8fbf48d5a2a64065fc26db3e890b9871"] = {"4.3.10"},
	-- www.patelecningbo.com
	["3c31e4674f42a49108b5300f8e73be26"] = {"4.3.1", "5.0.0", "5.0.3"},
	-- www.pamzylove.com
	["54f426521bf61f2d95c8bfaa13857c51"] = {"5.1.4", "5.2.X", "5.2.12-0.dotdeb.1"},
	-- 206.230.28.196, www.security.lutsk.ua/gb/gb2.php
	["744aecef04f9ed1bc39ae773c40017d1"] = {"4.0.1pl2", "4.1.2", "4.2.2"},
	["a4c057b11fa0fba98c8e26cd7bb762a8"] = {"5.3.1RC3", "5.3.1"},
	["1776a7c1b3255b07c6b9f43b9f50f05e"] = {"5.2.6", "5.2.6-1-lenny8"},
	["c37c96e8728dc959c55219d47f2d543f"] = {"5.2.3 to 5.2.5", "5.2.4-2ubuntu5.10"},
	["1ffc970c5eae684bebc0e0133c4e1f01"] = {"5.2.8"},
	["8a4a61f60025b43f11a7c998f02b1902"] = {"4.3.4"},
	["6a1c211f27330f1ab602c7c574f3a279"] = {"5.2.0-8-etch13 - 5.2.0-8-etch16"},
	["d3894e19233d979db07d623f608b6ece"] = {"5.2.1"},
	["55bc081f2d460b8e6eb326a953c0e71e"] = {"4.4.1"},
	["3422eded2fcceb3c89cabb5156b5d4e2"] = {"4.2.3"},
	["82fa2d6aa15f971f7dadefe4f2ac20e3"] = {"5.1.5"},
	["692a87ca2c51523c17f597253653c777"] = {"4.4.6-0.dotdeb.2"},
	["bed7ceff09e9666d96fdf3518af78e0e"] = {"4.4.2 to 4.4.4"},
}

action = function(host, port)
	local response
	local logo_versions, credits_versions
	local logo_hash, credits_hash
	local header_name, header_value
	local lines

	-- 1st pass : the "special" PHP-logo test
	response = http.get(host, port, LOGO_QUERY)
	if response.body then
		logo_hash = stdnse.tohex(openssl.md5(response.body))
		logo_versions = LOGO_HASHES[logo_hash]
	end

	-- 2nd pass : the PHP-credits test
	response = http.get(host, port, CREDITS_QUERY)
	if response.body then
		credits_hash = stdnse.tohex(openssl.md5(response.body))
		credits_versions = CREDITS_HASHES[credits_hash]
	end

	for name, value in pairs(response.header) do
		if string.match(value, "^PHP") then
			header_name = name
			header_value = value
			break
		end
	end

	lines = {}
	if logo_versions then
		lines[#lines + 1] = "Versions from logo query (less accurate): " .. stdnse.strjoin(", ", logo_versions)
	elseif logo_hash then
		lines[#lines + 1] = "Logo query returned unknown hash " .. logo_hash
	end
	if credits_versions then
		lines[#lines + 1] = "Versions from credits query (more accurate): " .. stdnse.strjoin(", ", credits_versions)
	elseif credits_hash then
		lines[#lines + 1] = "Credits query returned unknown hash " .. credits_hash
	end
	if header_name and header_value then
		lines[#lines + 1] = "Version from header " .. header_name .. ": " .. header_value
	end

	if #lines > 0 then
		return stdnse.strjoin("\n", lines)
	end
end
