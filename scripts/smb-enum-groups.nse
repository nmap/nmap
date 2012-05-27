local msrpc = require "msrpc"
local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Obtains a list of groups from the remote Windows system, as well as a list of the group's users. 
This works similarly to <code>enum.exe</code> with the <code>/G</code> switch. 

The following MSRPC functions in SAMR are used to find a list of groups and the RIDs of their users. Keep
in mind that MSRPC refers to groups as "Aliases". 

* <code>Bind</code>: bind to the SAMR service.
* <code>Connect4</code>: get a connect_handle.
* <code>EnumDomains</code>: get a list of the domains.
* <code>LookupDomain</code>: get the RID of the domains. 
* <code>OpenDomain</code>: get a handle for each domain.
* <code>EnumDomainAliases</code>: get the list of groups in the domain.
* <code>OpenAlias</code>: get a handle to each group.
* <code>GetMembersInAlias</code>: get the RIDs of the members in the groups. 
* <code>Close</code>: close the alias handle.
* <code>Close</code>: close the domain handle.
* <code>Close</code>: close the connect handle.

Once the RIDs have been termined, the
* <code>Bind</code>: bind to the LSA service.
* <code>OpenPolicy2</code>: get a policy handle.
* <code>LookupSids2</code>: convert SIDs to usernames. 

I (Ron Bowes) originally looked into the possibility of using the SAMR function <code>LookupRids2</code> 
to convert RIDs to usernames, but the function seemed to return a fault no matter what I tried. Since 
enum.exe also switches to LSA to convert RIDs to usernames, I figured they had the same issue and I do 
the same thing. 
]]

---
-- @usage
-- nmap --script smb-enum-users.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 <host>
--
-- @output
-- Host script results:
-- |  smb-enum-groups:
-- |  |  WINDOWS2003\HelpServicesGroup: SUPPORT_388945a0
-- |  |  WINDOWS2003\IIS_WPG: SYSTEM, SERVICE, NETWORK SERVICE, IWAM_WINDOWS2003
-- |  |  WINDOWS2003\TelnetClients: <empty>
-- |  |  Builtin\Print Operators: <empty>
-- |  |  Builtin\Replicator: <empty>
-- |  |  Builtin\Network Configuration Operators: <empty>
-- |  |  Builtin\Performance Monitor Users: <empty>
-- |  |  Builtin\Users: INTERACTIVE, Authenticated Users, ron, ASPNET, test
-- |  |  Builtin\Power Users: <empty>
-- |  |  Builtin\Backup Operators: <empty>
-- |  |  Builtin\Remote Desktop Users: <empty>
-- |  |  Builtin\Administrators: Administrator, ron, test
-- |  |  Builtin\Performance Log Users: NETWORK SERVICE
-- |  |  Builtin\Guests: Guest, IUSR_WINDOWS2003
-- |_ |_ Builtin\Distributed COM Users: <empty>
-----------------------------------------------------------------------

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive"}
dependencies = {"smb-brute"}


hostrule = function(host)
	return smb.get_port(host) ~= nil
end

action = function(host)
	local status, groups = msrpc.samr_enum_groups(host)
	if(not(status)) then
		return stdnse.format_output(false, "Couldn't enumerate groups: " .. groups)
	end

	local response = {}

	for domain_name, domain_data in pairs(groups) do

		for rid, group_data in pairs(domain_data) do
			local members = group_data['members']
			if(#members > 0) then
				members = stdnse.strjoin(", ", group_data['members'])
			else
				members = "<empty>"
			end
			table.insert(response, string.format("%s\\%s (RID: %s): %s", domain_name, group_data['name'], rid, members))
		end
	end

	return stdnse.format_output(true, response)
end

