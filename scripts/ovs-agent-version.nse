description = [[
Detects the version of an OVSAgentServer.

Version 2.2 of OVSAgentServer returns a distinctive string in response to an
HTTP GET request. However version 3.0 returns a generic response that looks like
any other BaseHTTP/SimpleXMLRPCServer. Both versions return a distinctive error
message in response to a <code>system.listMethods</code> XML-RPC call, which
however does not distinguish the two versions. Therefore we use this strategy:
(1.) Send a GET request. If the version 2.2 string is returned, return "2.2".
(2.) Send a <code>system.listMethods</code> method call. If an OVSAgentServer
error is returned, return "3.0".
]]

categories = {"version"}

---
-- @output
-- PORT     STATE SERVICE       REASON  VERSION
-- 8899/tcp open  ssl/ovs-agent syn-ack Oracle OVSAgentServer 3.0 (BaseHTTP 0.3; Python SimpleXMLRPCServer; Python 2.5.2)

author = "David Fifield"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

require("http")
require("shortport")

portrule = shortport.port_or_service({8899})

local function set_port_version(host, port, version, server)
	port.version.name = "ovs-agent"
	port.version.product = "Oracle OVSAgentServer"
	port.version.version = version
	if server then
		local basehttp, python = string.match(server, "^BaseHTTP/([%d.]+) Python/([%d.]+)")
		if basehttp and python then
			port.version.extrainfo = string.format("BaseHTTP %s; Python SimpleXMLRPCServer; Python %s", basehttp, python)
		end
	end
	nmap.set_port_version(host, port, "hardmatched")
end

function action(host, port)
	local response
	local version = {}

	response = http.get(host, port, "/")
	if response.status == 200 and string.match(response.body,
		"<title>Python: OVSAgentServer Document</title>") then
		set_port_version(host, port, "2.2", response.header["server"])
		return
	end

	-- So much for version 2.2. If the response to GET was 501, then we may
	-- have a version 3.0.
	if not (response.status == 501) then
		return
	end

	response = http.post(host, port, "/",
		{header = {["Content-Type"] = "text/xml"}}, nil,
		"<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>")
	if response.status == 403 and string.match(response.body,
		"Message: Unauthorized HTTP Access Attempt from %('[%d.]+', %d+%)!%.") then
		set_port_version(host, port, "3.0", response.header["server"])
		return
	end
end
