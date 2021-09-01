local http = require("http")
local shortport = require("shortport")
local stdnse = require("stdnse")

description = [[Search for user and workspace configuration files within the VSCode folder]]

---
-- @usage
-- nmap -p80 www.example.com --script http-vscode
--
-- @output
-- 80/tcp open  http
-- | http-vscode: 
-- |   settings.json
-- |_  sftp.json
--
-- @args http-vscode.path specifies the location of .vscode folder
--       (default: /.vscode)

author = "J. Igor Melo"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "default", "safe", "vuln" }

portrule = shortport.http

action = function(host, port)
	local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/.vscode"
	local response = http.get(host, port, path)
	local result = {}

	if not response or not response.status or not response.status == 200 or not response.body then
		stdnse.debug1("Failed to retrieve file: %s", path)
		return
	end

	local html = response.body
	for link in html:gmatch('<a[^<>]*href="(.-)">') do
		if link:find(".json") then
			table.insert(result, link)
		end
	end
	return result
end