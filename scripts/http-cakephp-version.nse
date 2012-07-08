description = [[
Obtains the CakePHP version of a web application built with the CakePHP framework by fingerprinting default files shipped with the CakePHP framework.

This script queries the files 'vendors.php', 'cake.generic.css', 'cake.icon.png' and 'cake.icon.gif' to try to obtain the version of the CakePHP installation.
Since installations that had been upgraded are prone to false positives due to old files that aren't removed, the script displays 3 different versions:
* Codebase: Taken from the existence of vendors.php (1.1.x or 1.2.x if it does and 1.3.x otherwise)
* Stylesheet: Taken from cake.generic.css 
* Icon: Taken from cake.icon.gif or cake.icon.png 

For more information about CakePHP visit: http://www.cakephp.org/.
]]

---
-- @usage
-- nmap -p80,443 --script http-cakephp-version <host/ip>
--
-- @output
-- PORT   STATE SERVICE 
-- 80/tcp open  http
-- | http-cakephp-version: Version of codebase: 1.2.x
-- | Version of icons: 1.2.x
-- | Version of stylesheet: 1.2.6

author = "Paulino Calderon"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","safe"}

local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

local openssl = stdnse.silent_require "openssl"

portrule = shortport.http

-- Queries for fingerprinting
local PNG_ICON_QUERY = "/img/cake.icon.png"
local GIF_ICON_QUERY = "/img/cake.icon.gif"
local STYLESHEET_QUERY = "/css/cake.generic.css"
local VENDORS_QUERY = "/js/vendors.php"

-- Cakephp's stylesheets hashes
local CAKEPHP_STYLESHEET_HASHES = {
	["aaf0340c16415585554a7aefde2778c4"] = {"1.1.12"},
	["8f8a877d924aa26ccd66c84ff8f8c8fe"] = {"1.1.14"},
	["02a661c167affd9deda2a45f4341297e"] = {"1.1.17", "1.1.20"},
	["1776a7c1b3255b07c6b9f43b9f50f05e"] = {"1.2.0 - 1.2.5", "1.3.0 Alpha"},
	["1ffc970c5eae684bebc0e0133c4e1f01"] = {"1.2.6"},
	["2e7f5372931a7f6f86786e95871ac947"] = {"1.2.7 - 1.2.9"},
	["3422eded2fcceb3c89cabb5156b5d4e2"] = {"1.3.0 beta"},
	["3c31e4674f42a49108b5300f8e73be26"] = {"1.3.0 RC1 - 1.3.7"}
}

action = function(host, port)
	local response, png_icon_response, gif_icon_response
	local icon_versions, stylesheet_versions
	local icon_hash, stylesheet_hash
	local output_lines
	local installation_version

	-- Identify servers that answer 200 to invalid HTTP requests and exit as these would invalidate the tests
	local _, http_status, _ = http.identify_404(host,port)
	if ( http_status == 200 ) then
		stdnse.print_debug(1, "%s: Exiting due to ambiguous response from web server on %s:%s. All URIs return status 200.", SCRIPT_NAME, host.ip, port.number)
		return false
	end

	-- Are the default icons there?
	png_icon_response = http.get(host, port, PNG_ICON_QUERY)
	gif_icon_response = http.get(host, port, GIF_ICON_QUERY)
	if png_icon_response.body and png_icon_response.status == 200 then
		icon_versions = {"1.3.x"}
	elseif gif_icon_response.body and gif_icon_response.status == 200 then
		icon_versions = {"1.2.x"}	
	end

	-- Download cake.generic.css and fingerprint
	response = http.get(host, port, STYLESHEET_QUERY)
	if response.body and response.status == 200 then
		stylesheet_hash = stdnse.tohex(openssl.md5(response.body))
		stylesheet_versions = CAKEPHP_STYLESHEET_HASHES[stylesheet_hash]
	end
	-- Is /js/vendors.php there?
	response = http.get(host, port, VENDORS_QUERY)
	if response.body and response.status == 200 then
		installation_version = {"1.1.x","1.2.x"}	
	elseif response.status ~= 200 and (icon_versions or stylesheet_versions) then
		installation_version = {"1.3.x"}	
	end
	-- Prepare output	
	output_lines = {}
	if installation_version then
		output_lines[#output_lines + 1] = "Version of codebase: " .. stdnse.strjoin(", ", installation_version)
	end
	if icon_versions then
		output_lines[#output_lines + 1] = "Version of icons: " .. stdnse.strjoin(", ", icon_versions)
	end
	if stylesheet_versions then
		output_lines[#output_lines + 1] = "Version of stylesheet: " .. stdnse.strjoin(", ", stylesheet_versions)
	elseif stylesheet_hash and nmap.verbosity() >= 2 then
		output_lines[#output_lines + 1] = "Default stylesheet has an unknown hash: " .. stylesheet_hash
	end
	if #output_lines > 0 then
		return stdnse.strjoin("\n", output_lines)
	end
end
