local msrpc = require "msrpc"
local smb = require "smb"
local string = require "string"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Queries an MSRPC endpoint mapper for a list of mapped 
services and displays the gathered information.

As it is using smb library, you can specify optional
username and password to use.

Script works much like Microsoft's rpcdump tool
or dcedump tool from SPIKE fuzzer.
]]
---
-- @usage nmap <target> --script=msrpc-enum
--
-- @output
-- PORT    STATE SERVICE      REASON
-- 445/tcp open  microsoft-ds syn-ack
--
-- Host script results:
-- | msrpc-enum:
-- |
-- |     uuid: 3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5
-- |     annotation: DHCP Client LRPC Endpoint
-- |     ncalrpc: dhcpcsvc
-- |
-- |     uuid: 12345678-1234-abcd-ef00-0123456789ab
-- |     annotation: IPSec Policy agent endpoint
-- |     ncalrpc: audit
-- |
-- |     uuid: 3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5
-- |     ip_addr: 0.0.0.0
-- |     annotation: DHCP Client LRPC Endpoint
-- |     tcp_port: 49153
-- |
-- <snip>
-- |
-- |     uuid: 12345678-1234-abcd-ef00-0123456789ab
-- |     annotation: IPSec Policy agent endpoint
-- |     ncalrpc: securityevent
-- |
-- |     uuid: 12345678-1234-abcd-ef00-0123456789ab
-- |     annotation: IPSec Policy agent endpoint
-- |_    ncalrpc: protected_storage
--
-- @xmloutput
-- -snip-
-- <table>
-- <elem key="uuid">c100beab-d33a-4a4b-bf23-bbef4663d017</elem>
-- <elem key="annotation">wcncsvc.wcnprpc</elem>
-- <elem key="ncalrpc">wcncsvc.wcnprpc</elem>
-- </table>
-- <table>
-- <elem key="uuid">6b5bdd1e-528c-422c-af8c-a4079be4fe48</elem>
-- <elem key="annotation">Remote Fw APIs</elem>
-- <elem key="tcp_port">49158</elem>
-- <elem key="ip_addr">0.0.0.0</elem>
-- </table>
-- <table>
-- <elem key="uuid">12345678-1234-abcd-ef00-0123456789ab</elem>
-- <elem key="annotation">IPSec Policy agent endpoint</elem>
-- <elem key="tcp_port">49158</elem>
-- <elem key="ip_addr">0.0.0.0</elem>
-- </table>
-- -snip-

author = "Aleksandar Nikolic"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe","discovery"}

hostrule = function(host)
	return smb.get_port(host) ~= nil
end

action = function(host,port)
	local status, smbstate
	status, smbstate = msrpc.start_smb(host,msrpc.EPMAPPER_PATH,true)
	if(status == false) then
		stdnse.print_debug("SMB: " .. smbstate)
		return false, smbstate
	end
	local bind_result,epresult -- bind to endpoint mapper service
	status, bind_result = msrpc.bind(smbstate,msrpc.EPMAPPER_UUID, msrpc.EPMAPPER_VERSION, nil)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		stdnse.print_debug("SMB: " .. bind_result)
		return false, bind_result
	end	
	local results = {}
	status, epresult = msrpc.epmapper_lookup(smbstate,nil) -- get the initial handle
	if not status then 
		stdnse.print_debug("SMB: " .. epresult)
		return false, epresult
	
	end
	local handle = epresult.new_handle
	epresult.new_handle = nil
	table.insert(results,epresult)

	while not (epresult == nil) do
		status, epresult = msrpc.epmapper_lookup(smbstate,handle) -- get next result until there are no more
		if not status then 
			break
		end
		epresult.new_handle = nil
		table.insert(results,epresult)
	end
	return results
end
