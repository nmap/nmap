description = [[
Attempts to enumerate domains on a system, along with their policies. This generally requires
credentials, except against Windows 2000. In addition to the actual domain, the "Builtin" 
domain is generally displayed. Windows returns this in the list of domains, but its policies 
don't appear to be used anywhere. 

Much of the information provided is useful to a penetration tester, because it tells the
tester what types of policies to expect. For example, if passwords have a minimum length of 8, 
the tester can trim his database to match; if the minimum length is 14, the tester will
probably start looking for sticky notes on people's monitors. 

Another useful piece of information is the password lockouts -- a penetration tester often wants
to know whether or not there's a risk of negatively impacting a network, and this will 
indicate it. The SID is displayed, which may be useful in other tools; the users are listed, 
which uses different functions than <code>smb-enum-users.nse</code> (though likely won't 
get different results), and the date and time the domain was created may give some insight into
its history. 

After the initial <code>bind</code> to SAMR, the sequence of calls is:
* <code>Connect4</code>: get a connect_handle
* <code>EnumDomains</code>: get a list of the domains (stop here if you just want the names).
* <code>QueryDomain</code>: get the SID for the domain.
* <code>OpenDomain</code>: get a handle for each domain.
* <code>QueryDomainInfo2</code>: get the domain information.
* <code>QueryDomainUsers</code>: get a list of the users in the domain.
]]

---
--@usage
-- nmap --script smb-enum-domains.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-enum-domains.nse -p U:137,T:139 <host>
--
--@output
-- Host script results:
-- |  smb-enum-domains:  
-- |  |  WINDOWS2003 (S-1-5-21-4146152237-3614947961-1862238888)
-- |  |  |  Groups: HelpServicesGroup, IIS_WPG, TelnetClients
-- |  |  |  Users: Administrator, ASPNET, Guest, IUSR_WINDOWS2003, IWAM_WINDOWS2003, ron, SUPPORT_388945a0, test
-- |  |  |  Creation time: 2009-10-17 12:46:43
-- |  |  |  Passwords: min length: n/a; min age: n/a; max age: 42 days; history: n/a
-- |  |  |_ Account lockout disabled
-- |  |  Builtin (S-1-5-32)
-- |  |  |  Groups: Administrators, Backup Operators, Distributed COM Users, Guests, Network Configuration Operators, Performance Log Users, Performance Monitor Users, Power Users, Print Operators, Remote Desktop Users, Replicator, Users
-- |  |  |  Users: n/a
-- |  |  |  Creation time: 2009-10-17 12:46:43
-- |  |  |  Passwords: min length: n/a; min age: n/a; max age: 42 days; history: n/a
-- |_ |_ |_ Account lockout disabled
--
-----------------------------------------------------------------------

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive"}
dependencies = {"smb-brute"}

require 'msrpc'
require 'smb'
require 'stdnse'

-- TODO: This script needs some love...

hostrule = function(host)
	return smb.get_port(host) ~= nil
end

local function get_domain_info(smbstate, domain)
	local sid
	local domain_handle

	-- Call LookupDomain()
	status, lookupdomain_result = msrpc.samr_lookupdomain(smbstate, connect_handle, domain)
	if(status == false) then
		return false, "Couldn't look up the domain: " .. lookupdomain_result
	end

	-- Save the sid
	sid = lookupdomain_result['sid']

	-- Call OpenDomain()
	status, opendomain_result = msrpc.samr_opendomain(smbstate, connect_handle, sid)
	if(status == false) then
		return false, opendomain_result
	end

	-- Save the domain handle
	domain_handle = opendomain_result['domain_handle']

	-- Call QueryDomainInfo2() to get domain properties. We call these for three types -- 1, 8, and 12, since those return
	-- the most useful information. 
	status_1,  querydomaininfo2_result_1  = msrpc.samr_querydomaininfo2(smbstate, domain_handle, 1)
	status_8,  querydomaininfo2_result_8  = msrpc.samr_querydomaininfo2(smbstate, domain_handle, 8)
	status_12, querydomaininfo2_result_12 = msrpc.samr_querydomaininfo2(smbstate, domain_handle, 12)

	if(status_1 == false) then
		return false, querydomaininfo2_result_1
	end

	if(status_8 == false) then
		return false, querydomaininfo2_result_8
	end

	if(status_12 == false) then
		return false, thenquerydomaininfo2_result_12
	end

	-- Call EnumDomainUsers() to get users
	status, enumdomainusers_result = msrpc.samr_enumdomainusers(smbstate, domain_handle)
	if(status == false) then
		return false, enumdomainusers_result
	end

	-- Call EnumDomainAliases() to get groups
	local status, enumdomaingroups_result = msrpc.samr_enumdomainaliases(smbstate, domain_handle)
	if(status == false) then
		return false, enumdomaingroups_result
	end

	-- Close the domain handle
	msrpc.samr_close(smbstate, domain_handle)

	-- Create a list of groups
	local groups = {}
	if(enumdomaingroups_result['sam'] ~= nil and enumdomaingroups_result['sam']['entries'] ~= nil) then
		for _, group in ipairs(enumdomaingroups_result['sam']['entries']) do
			table.insert(groups, group.name)
		end
	end

	-- Create the list of users
	local names = {}
	if(enumdomainusers_result['sam'] ~= nil and enumdomainusers_result['sam']['entries'] ~= nil) then
		for _, name in ipairs(enumdomainusers_result['sam']['entries']) do
			table.insert(names, name.name)
		end
	end

	-- Our output table
	local response = {}

	-- Finally, start filling in the response!
	response['name'] = string.format("%s (%s)", domain, sid)

	-- Add the list of groups as a comma-separated list
	if(groups and (#groups > 0)) then
		table.insert(response, string.format("Groups: %s", stdnse.strjoin(", ", groups)))
	else
		table.insert(response, string.format("Groups: n/a"))
	end

	-- Add the list of users as a comma-separated list
	if(names and (#names > 0)) then
		table.insert(response, string.format("Users: %s", stdnse.strjoin(", ", names)))
	else
		table.insert(response, string.format("Users: n/a"))
	end



	if(querydomaininfo2_result_8['info']['domain_create_time'] ~= 0) then
		table.insert(response, string.format("Creation time: %s", os.date("%Y-%m-%d %H:%M:%S", querydomaininfo2_result_8['info']['domain_create_time'])))
	end

	-- Password characteristics
	local min_password_length = querydomaininfo2_result_1['info']['min_password_length']
	local max_password_age    = querydomaininfo2_result_1['info']['max_password_age'] / 60 / 60 / 24
	local min_password_age    = querydomaininfo2_result_1['info']['min_password_age'] / 60 / 60 / 24
	local password_history    = querydomaininfo2_result_1['info']['password_history_length']

	if(min_password_length > 0) then
		min_password_length = string.format("%d characters", min_password_length)
	else
		min_password_length = "n/a"
	end

	if(max_password_age > 0 and max_password_age < 5000) then
		max_password_age = string.format("%d days", max_password_age)
	else
		max_password_age = "n/a"
	end

	if(min_password_age > 0) then
		min_password_age = string.format("%d days", min_password_age)
	else
		min_password_age = "n/a"
	end

	if(password_history > 0) then
		password_history = string.format("%d passwords", password_history)
	else
		password_history = "n/a"
	end

	table.insert(response, string.format("Passwords: min length: %s; min age: %s; max age: %s; history: %s", min_password_length, min_password_age, max_password_age, password_history))

	local lockout_duration = querydomaininfo2_result_12['info']['lockout_duration']
	if(lockout_duration < 0) then
		lockout_duration = string.format("for %d minutes", querydomaininfo2_result_12['info']['lockout_duration'])
	else
		lockout_duration = "until manually reset"
	end

	if(querydomaininfo2_result_12['info']['lockout_threshold'] > 0) then
		table.insert(response, string.format("Password lockout: %d attempts in under %d minutes will lock the account %s",  querydomaininfo2_result_12['info']['lockout_threshold'], querydomaininfo2_result_12['info']['lockout_window'] / 60, lockout_duration))
	else
		table.insert(response, string.format("Account lockout disabled"))
	end

	local password_properties = querydomaininfo2_result_1['info']['password_properties']
	
	if(#password_properties > 0) then
		local password_properties_response = {}
		password_properties_response['name'] = "Password properties:"
		for j = 1, #password_properties, 1 do
			table.insert(password_properties_response, msrpc.samr_PasswordProperties_tostr(password_properties[j]))
		end
		table.insert(response, password_properties_response)
	end

	return true, response
end


action = function(host)

	local response = {}
	local status, smbstate
	local i, j

	-- Create the SMB session
	status, smbstate  = msrpc.start_smb(host, msrpc.SAMR_PATH)
	if(status == false) then
		return stdnse.format_output(false, smbstate)
	end

	-- Bind to SAMR service
	status, bind_result = msrpc.bind(smbstate, msrpc.SAMR_UUID, msrpc.SAMR_VERSION, nil)
	if(status == false) then
		return stdnse.format_output(false, bind_result)
	end

	-- Call connect4()
	status, connect4_result = msrpc.samr_connect4(smbstate, host.ip)
	if(status == false) then
		return stdnse.format_output(false, connect4_result)
	end

	-- Save the connect_handle
	connect_handle = connect4_result['connect_handle']

	-- Call EnumDomains()
	status, enumdomains_result = msrpc.samr_enumdomains(smbstate, connect_handle)
	if(status == false) then
		return stdnse.format_output(false, enumdomains_result)
	end

	-- If no domains were returned, print an error (I don't expect this will actually happen)
	if(#enumdomains_result['sam']['entries'] == 0) then
		return stdnse.format_output(false, "Couldn't find any domains")
	end

	for i = 1, #enumdomains_result['sam']['entries'], 1 do
		local domain = enumdomains_result['sam']['entries'][i]['name']
		local status, domain_info = get_domain_info(smbstate, domain)

		if(not(status)) then
			local error_table = {}
			error_table['name'] = "Domain: " .. domain
			error_table['warning'] = "Couldn't get info for the domain: " .. domain_info
			table.insert(response, error_table)
		else
			table.insert(response, domain_info)
		end

	end

	-- Close the connect handle
	msrpc.samr_close(smbstate, connect_handle)

	-- Close the SMB session
	msrpc.stop_smb(smbstate)

	return stdnse.format_output(true, response)
end

