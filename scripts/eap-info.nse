local bin = require "bin"
local eap = require "eap"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates the authentication methods offered by an EAP (Extensible
Authentication Protocol) authenticator for a given identity or for the
anonymous identity if no argument is passed.
]]

---
-- @usage
-- nmap -e interface --script eap-info [--script-args="eap-info.identity=0-user,eap-info.scan={13,50}"] <target>
--
-- @output
-- Pre-scan script results:
-- | eap-info: 
-- | Available authentication methods with identity="anonymous" on interface eth2
-- |   true     PEAP
-- |   true     EAP-TTLS
-- |   false    EAP-TLS
-- |_  false    EAP-MSCHAP-V2
--
-- @args eap-info.identity Identity to use for the first step of the authentication methods (if omitted "anonymous" will be used).
-- @args eap-info.scan Table of authentication methods to test, e.g. { 4, 13, 25 } for MD5, TLS and PEAP. Default: TLS, TTLS, PEAP, MSCHAP.
-- @args eap-info.interface Network interface to use for the scan, overrides "-e".
-- @args eap-info.timeout Maximum time allowed for the scan (default 10s). Methods not tested because of timeout will be listed as "unknown".

author = "Riccardo Cecolin"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = { "broadcast", "safe" }


prerule = function()
	return nmap.is_privileged()
end

local default_scan = {
   eap.eap_t.TLS,
   eap.eap_t.TTLS,
   eap.eap_t.PEAP,
   eap.eap_t.MSCHAP,
}

local UNKNOWN = "unknown"

action = function()

	local arg_interface = stdnse.get_script_args(SCRIPT_NAME .. ".interface")
	local arg_identity = stdnse.get_script_args(SCRIPT_NAME .. ".identity")
	local arg_scan = stdnse.get_script_args(SCRIPT_NAME .. ".scan")
	local arg_timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
	local iface

	-- trying with provided interface name
	if arg_interface then
		iface = nmap.get_interface_info(arg_interface)
	end

	-- trying with default nmap interface
	if not iface then
		local iname = nmap.get_interface()
		if iname then
			iface = nmap.get_interface_info(iname)
		end
	end

	-- failed
	if not iface then
		return "please specify an interface with -e"
	end	    
	stdnse.print_debug(1, "iface: %s", iface.device)

	local timeout = (arg_timeout or 10) * 1000

	stdnse.print_debug(2, "timeout: %s", timeout)

	local pcap = nmap.new_socket()
	pcap:pcap_open(iface.device, 512, true, "ether proto 0x888e")


	local identity = { name="anonymous", auth = {}, probe = -1 }

	if arg_identity then
		identity.name = tostring(arg_identity)
	end

	local scan
	if arg_scan == nil or type(arg_scan) ~= "table" or #arg_scan == 0 then
		scan = default_scan
	else
		scan = arg_scan
	end	    

	local valid = false
	for i,v in ipairs(scan) do
		v = tonumber(v)
		if v ~= nil and v < 256 and v > 3 then
			stdnse.print_debug(1, "selected: %s", eap.eap_str[v] or "unassigned" )
			identity.auth[v] = UNKNOWN
			valid = true
		end
	end

	if not valid then
		return "no valid scan methods provided"
	end

	local tried_all = false

	local start_time = nmap.clock_ms()
	eap.send_start(iface)	   

	while(nmap.clock_ms() - start_time < timeout) and not tried_all do
		local status, plen, l2_data, l3_data, time = pcap:pcap_receive()		
		if (status) then
			stdnse.print_debug(2, "packet size: 0x%x", plen )
			local packet = eap.parse(l2_data .. l3_data)

			if packet then	      
				stdnse.print_debug(2, "packet valid")

				-- respond to identity requests, using the same session id
				if packet.eap.type == eap.eap_t.IDENTITY and  packet.eap.code == eap.code_t.REQUEST then
					stdnse.print_debug(1, "server identity: %s",packet.eap.body.identity)
					eap.send_identity_response(iface, packet.eap.id, identity.name)
				end

				-- respond with NAK to every auth request to enumerate them until we get a failure
				if packet.eap.type ~= eap.eap_t.IDENTITY and  packet.eap.code == eap.code_t.REQUEST then
					stdnse.print_debug(1, "auth request: %s",eap.eap_str[packet.eap.type])
					identity.auth[packet.eap.type] = true

					identity.probe = -1
					for i,v in pairs(identity.auth) do 
						stdnse.print_debug(1, "identity.auth: %d %s",i,tostring(v))
						if v == UNKNOWN then
							identity.probe = i
							eap.send_nak_response(iface, packet.eap.id, i)
							break
						end		    
					end
					if identity.probe == -1 then tried_all = true end
				end

				-- retry on failure
				if packet.eap.code == eap.code_t.FAILURE then
					stdnse.print_debug(1, "auth failure")
					identity.auth[identity.probe] = false

					-- don't give up at the first failure!
					-- mac spoofing to avoid to wait too much
					local d = string.byte(iface.mac,6)
					d = (d + 1) % 256
					iface.mac = iface.mac:sub(1,5) .. bin.pack("C",d)			 

					tried_all = true
					for i,v in pairs(identity.auth) do 
						if v == UNKNOWN then
							tried_all = false
							break
						end
					end			 
					if not tried_all then
						eap.send_start(iface) 
					end
				end		      

			else
				stdnse.print_debug(1, "packet invalid! wrong filter?")
			end				   
		end
	end

	local results = { ["name"] = ("Available authentication methods with identity=\"%s\" on interface %s"):format(identity.name, iface.device) }
	for i,v in pairs(identity.auth) do
		if v== true then		   
			table.insert(results, 1, ("%-8s %s"):format(tostring(v), eap.eap_str[i] or "unassigned" ))
		else
			table.insert(results, ("%-8s %s"):format(tostring(v), eap.eap_str[i] or "unassigned" ))
		end
	end

	for i,v in ipairs(results) do			 
		stdnse.print_debug(1, "%s", tostring(v))
	end

	return stdnse.format_output(true, results)
end

