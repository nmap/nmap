local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local unpwdb = require "unpwdb"

description = [[Enumerate Plone users by the author view]]

---
-- @usage
-- nmap --script=http-plone-enum-users --script-args http-plone-enum-users.root="/path/" <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-plone-enum-users:
-- |   admin
-- |   test
-- |   sysadmin
-- |_  manager
--
-- @args http-plone-enum-users.root base path. Defaults to "/"

author = "J. Igor Melo <jigordev@gmail.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

portrule = shortport.port_or_service({80, 443}, {"http", "https"}, "tcp")

check_user = function(host, port, root, username, result)
	local path = root .. "author/" .. username 
	local response = http.get(host, port, path)
	if response.body response.body:match("<h1 class=\"documentFirstHeading") then
		table.insert(result, username)
	end
end

action = function(host, port)
	local root = stdnse.get_script_args(SCRIPT_NAME .. ".root") or "/"
	local result = {}

	-- ensure that root ends with trailing slash
	if not root:match(".*/$") then
		root = root .. "/"
	end

	local status, usernames = unpwdb.usernames()
	if not status then
		return false, "Failed to load usernames"
	end

	for username in usernames do
		check_user(host, port, root, username, result)
	end

	if #result > 0 then
		return result
	end
	return
end
