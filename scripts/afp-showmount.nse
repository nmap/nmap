description = [[ Shows AFP shares and ACLs ]]

---
--@output
-- PORT    STATE SERVICE
-- 548/tcp open  afp
-- | afp-showmount:  
-- |   Yoda's Public Folder
-- |     Owner: Search,Read,Write
-- |     Group: Search,Read
-- |     Everyone: Search,Read
-- |     User: Search,Read
-- |   Vader's Public Folder
-- |     Owner: Search,Read,Write
-- |     Group: Search,Read
-- |     Everyone: Search,Read
-- |     User: Search,Read
-- |_    Options: IsOwner

-- Version 0.3
-- Created 01/03/2010 - v0.1 - created by Patrik Karlsson
-- Revised 01/13/2010 - v0.2 - Fixed a bug where a single share wouldn't show due to formatting issues
-- Revised 01/20/2010 - v0.3 - removed superflous functions

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require 'shortport'
require 'stdnse'
require 'afp'

portrule = shortport.portnumber(548, "tcp")

--- Converts a group bitmask of Search, Read and Write to table
--
-- @param acls number containing bitmasked acls
-- @return table of ACLs
function acl_group_to_long_string(acls)
	
	local acl_table = {}
	
	if bit.band( acls, afp.ACLS.OwnerSearch ) == afp.ACLS.OwnerSearch then
		table.insert( acl_table, "Search")
	end 
	
	if bit.band( acls, afp.ACLS.OwnerRead ) == afp.ACLS.OwnerRead then
		table.insert( acl_table, "Read")
	end
	
	if bit.band( acls, afp.ACLS.OwnerWrite ) == afp.ACLS.OwnerWrite then
		table.insert( acl_table, "Write")
	end
	
	return acl_table
end


--- Converts a numeric acl to string
--
-- @param acls number containig acls as recieved from <code>fp_get_file_dir_parms</code>
-- @return table of long ACLs
function acls_to_long_string( acls )

	local owner = acl_group_to_long_string( bit.band( acls, 255 ) )
	local group = acl_group_to_long_string( bit.band( bit.rshift(acls, 8), 255 ) )
	local everyone = acl_group_to_long_string( bit.band( bit.rshift(acls, 16), 255 ) )
	local user = acl_group_to_long_string( bit.band( bit.rshift(acls, 24), 255 ) )

	local blank = bit.band( acls, afp.ACLS.BlankAccess ) == afp.ACLS.BlankAccess and "Blank" or nil
	local isowner = bit.band( acls, afp.ACLS.UserIsOwner ) == afp.ACLS.UserIsOwner and "IsOwner" or nil

	local options = {}
	
	if blank then
		table.insert(options, "Blank")
	end
	
	if isowner then
		table.insert(options, "IsOwner")
	end
	
	local acls_tbl = {}
	
	table.insert( acls_tbl, string.format( "Owner: %s", stdnse.strjoin(",", owner) ) )
	table.insert( acls_tbl, string.format( "Group: %s", stdnse.strjoin(",", group) ) )
	table.insert( acls_tbl, string.format( "Everyone: %s", stdnse.strjoin(",", everyone) ) )
	table.insert( acls_tbl, string.format( "User: %s", stdnse.strjoin(",", user) ) )
	
	if #options > 0 then
		table.insert( acls_tbl, string.format( "Options: %s", stdnse.strjoin(",", options ) ) )
	end

 	return acls_tbl
	
end

action = function(host, port)

	local socket = nmap.new_socket()
	local status
	local result = {}
	
	-- set a reasonable timeout value
	socket:set_timeout(5000)
	
	-- do some exception handling / cleanup
	local catch = function()
		socket:close()
	end
	
	local try = nmap.new_try(catch)

	try( socket:connect(host.ip, port.number, "tcp") )

	response = try( afp.open_session(socket) )
	response = try( afp.fp_login( socket, "AFP3.1", "No User Authent") )
	response = try( afp.fp_get_user_info( socket ) )	
	response = try( afp.fp_get_srvr_parms( socket ) )
	
	volumes = response.volumes
	
	for _, vol in pairs(volumes) do
		table.insert( result, vol )

		status, response = afp.fp_open_vol( socket, afp.VOL_BITMAP.ID, vol )

		if status then
			local vol_id = response.volume_id
			stdnse.print_debug(string.format("Vol_id: %d", vol_id))
			
			local path = {}
			path.type = afp.PATH_TYPE.LongNames
			path.name = ""
			path.len = path.name:len()
		
			response = try( afp.fp_get_file_dir_parms( socket, vol_id, 2, 0, afp.DIR_BITMAP.AccessRights, path ) )	
		 	local acls = acls_to_long_string(response.acls)
			acls.name = nil
			try( afp.fp_close_vol( socket, vol_id ) )
			table.insert( result, acls )
		end
				
	end
			
	return stdnse.format_output(true, result)

end