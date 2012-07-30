local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Retrieves information from a listening acarsd daemon. Acarsd decodes
ACARS (Aircraft Communication Addressing and Reporting System) data in
real time.  The information retrieved by this script includes the
daemon version, API version, administrator e-mail address and
listening frequency.

For more information about acarsd, see:
* http://www.acarsd.org/
]]

---
-- @usage
-- nmap --script acarsd-info --script-args "acarsd-info.timeout=10,acarsd-info.bytes=512" -p <port> <host>
--
-- @output
-- PORT    STATE SERVICE
-- 2202/tcp open  unknown
-- | acarsd-info: 
-- |   Version: 1.65
-- |   API Version: API-2005-Oct-18
-- |   Authorization Required: 0
-- |   Admin E-mail: admin@acarsd
-- |   Clients Connected: 1
-- |_  Frequency: 131.7250 & 131.45
--
-- @args acarsd-info.timeout
--		   Set the timeout in seconds. The default value is 10.
-- @args acarsd-info.bytes
--		   Set the number of bytes to retrieve. The default value is 512.
--
-- @changelog
-- 2012-02-23 - v0.1 - created by Brendan Coles - itsecuritysolutions.org
--

author = "Brendan Coles"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe","discovery"}


portrule = shortport.port_or_service (2202, "acarsd", {"tcp"})

action = function(host, port)

	local result = {}

	-- Set timeout
	local timeout = tonumber(nmap.registry.args[SCRIPT_NAME .. '.timeout'])
	if not timeout or timeout < 0 then timeout = 10 end

	-- Set bytes
	local bytes = tonumber(nmap.registry.args[SCRIPT_NAME .. '.bytes'])
	if not bytes then bytes = 512 else tonumber(bytes) end

	-- Connect and retrieve acarsd info in XML format over TCP
	stdnse.print_debug(1, ("%s: Connecting to %s:%s [Timeout: %ss]"):format(SCRIPT_NAME, host.targetname or host.ip, port.number, timeout))
	local status, data = comm.get_banner(host, port, {timeout=timeout*1000,bytes=bytes})
	if not status or not data then
		stdnse.print_debug(1, ("%s: Retrieving data from %s:%s failed [Timeout expired]"):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
		return
	end

	-- Check if retrieved data is valid acarsd data
	if not string.match(data, "acarsd") then
		stdnse.print_debug(1, ("%s: %s:%s is not an acarsd Daemon."):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
		return
	end

	-- Check for restricted access -- Parse daemon info
	if string.match(data, "Authorization needed%. If your client doesnt support this") then

		local version_match = string.match(data, "acarsd\t(.+)\t")
		if version_match then table.insert(result, string.format("Version: %s", version_match)) end
		local api_version_match = string.match(data, "acarsd\t.+\t(API.+[0-9][0-9]?)")
		if api_version_match then table.insert(result, string.format("API Version: %s", api_version_match)) end
		table.insert(result, "Authorization Required: 1")

	-- Check for unrestricted access -- Parse daemon info
	else

		stdnse.print_debug(1, ("%s: Parsing data from %s:%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
		local vars = {
			{"Version","Version"},
			{"API Version","APIVersion"},
			--{"Hostname","Hostname"},
			--{"Port","Port"},
			--{"Server UUID","ServerUUID"},
			{"Authorization Required","NeedAuth"},
			{"Admin E-mail","AdminMail"},
			{"Clients Connected","ClientsConnected"},
			{"Frequency","Frequency"},
			{"License","License"},
		}
		for _, var in ipairs(vars) do
			local tag = var[2]
			local var_match = string.match(data, string.format('<%s>(.+)</%s>', tag, tag))
			if var_match then table.insert(result, string.format("%s: %s", var[1], string.gsub(var_match, "&amp;", "&"))) end
		end

	end
	port.version.name = "acarsd"
	port.version.product = "ACARS Decoder"
	nmap.set_port_version(host, port)        

	-- Return results
	return stdnse.format_output(true, result)

end

