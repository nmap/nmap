description = [[
Attempts to get useful information about files from AFP volumes.
The output is intended to resemble the output of <code>ls</code>.
]]

---
--
--@output
-- PORT    STATE SERVICE
-- 548/tcp open  afp     syn-ack
-- | afp-ls: 
-- |   Macintosh HD
-- |     PERMISSION  UID  GID  SIZE    TIME              FILENAME
-- |     -rw-r--r--  501  80   15364   2010-06-13 17:52  .DS_Store
-- |     ----------  0    80   0       2009-10-05 07:42  .file
-- |     drwx------  501  20   0       2009-11-04 17:28  .fseventsd
-- |     -rw-------  0    0    393216  2010-06-14 01:49  .hotfiles.btree
-- |     drwx------  0    80   0       2009-11-04 18:19  .Spotlight-V100
-- |     d-wx-wx-wx  0    80   0       2009-11-04 18:25  .Trashes
-- |     drwxr-xr-x  0    0    0       2009-05-18 21:29  .vol
-- |     drwxrwxr-x  0    80   0       2009-04-28 00:06  Applications
-- |     drwxr-xr-x  0    0    0       2009-05-18 21:43  bin
-- |     drwxr-xr-x  501  80   0       2010-08-10 22:55  bundles
-- |   Patrik Karlsson's Public Folder
-- |     PERMISSION  UID  GID  SIZE  TIME              FILENAME
-- |     -rw-------  501  20   6148  2010-12-27 23:45  .DS_Store
-- |     -rw-r--r--  501  20   0     2007-07-24 21:17  .localized
-- |     drwx-wx-wx  501  20   0     2009-06-19 04:01  Drop Box
-- |   patrik
-- |     PERMISSION  UID  GID  SIZE   TIME              FILENAME
-- |     -rw-------  501  20   11281  2010-06-14 22:51  .bash_history
-- |     -rw-r--r--  501  20   33     2011-01-19 20:11  .bashrc
-- |     -rw-------  501  20   3      2007-07-24 21:17  .CFUserTextEncoding
-- |     drwx------  501  20   0      2010-09-12 14:52  .config
-- |     drwx------  501  20   0      2010-09-12 12:29  .cups
-- |     -rw-r--r--  501  20   15364  2010-06-13 18:34  .DS_Store
-- |     drwxr-xr-x  501  20   0      2010-09-12 14:13  .fontconfig
-- |     -rw-------  501  20   102    2010-06-14 01:46  .lesshst
-- |     -rw-r--r--  501  20   241    2010-06-14 01:45  .profile
-- |     -rw-------  501  20   218    2010-09-12 16:35  .recently-used.xbel
-- |   
-- |   Information retrieved as: patrik
-- |_  Output restricted to 10 entries per volume. (See afp-ls.maxfiles)
--
-- @args afp-ls.maxfiles If set, limits the amount of files returned by the script (default 10).
--

-- Version 0.1
-- Created 04/03/2011 - v0.1 - created by Patrik Karlsson


author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require 'shortport'
require 'stdnse'
require 'afp'
require 'tab'

dependencies = {"afp-brute"}

portrule = shortport.portnumber(548, "tcp")

local function createFileTable()
	local filetab = tab.new()

	tab.add(filetab, 1, "PERMISSION")
	tab.add(filetab, 2, "UID")
	tab.add(filetab, 3, "GID")
	tab.add(filetab, 4, "SIZE")
	tab.add(filetab, 5, "TIME")
	tab.add(filetab, 6, "FILENAME")
	tab.nextrow(filetab)
	
	return filetab
end


action = function(host, port)

	local afpHelper = afp.Helper:new()
	local args = nmap.registry.args
	local users = nmap.registry.afp or { ['nil'] = 'nil' }
	local maxfiles = tonumber(stdnse.get_script_args("afp-ls.maxfiles") or 10)
	local output = {}
	
	if ( args['afp.username'] ) then
		users = {}
		users[args['afp.username']] = args['afp.password']
	end	
	
	for username, password in pairs(users) do

		local status, response = afpHelper:OpenSession(host, port)
		if ( not status ) then
			stdnse.print_debug(response)
			return
		end

		-- if we have a username attempt to authenticate as the user
		-- Attempt to use No User Authentication?
		if ( username ~= 'nil' ) then
			status, response = afpHelper:Login(username, password)
		else
			status, response = afpHelper:Login()
		end

		if ( not status ) then
			stdnse.print_debug("afp-showmount: Login failed", response)
			stdnse.print_debug(3, "afp-showmount: Login error: %s", response)
			return
		end

		status, vols = afpHelper:ListShares()

		if status then
			for _, vol in ipairs( vols ) do
				local status, tbl = afpHelper:Dir( vol )
				if ( not(status) ) then
					return ("\n\nERROR: Failed to list the contents of %s"):format(vol)
				end
						
				local file_tab = createFileTable()
				local counter = maxfiles or 10
				for _, item in ipairs(tbl[1]) do
					if ( item and item.name ) then
						local status, result = afpHelper:GetFileUnixPermissions( vol, item.name )
						if ( status ) then
							local status, fsize = afpHelper:GetFileSize( vol, item.name)
							if ( not(status) ) then
								return ("\n\nERROR: Failed to retreive file size for %/%s"):format(vol, item.name)
							end
							local status, date = afpHelper:GetFileDates( vol, item.name)
							if ( not(status) ) then
								return ("\n\nERROR: Failed to retreive file dates for %/%s"):format(vol, item.name)
							end
									
							tab.addrow(file_tab, result.privs, result.uid, result.gid, fsize, date.create, item.name)

							counter = counter - 1
						end
					end
					if ( counter == 0 ) then break end
				end
				local result_part = { name = vol }
				table.insert(result_part, tab.dump(file_tab))
				table.insert(output, result_part)
			end
		end
		
		status, response = afpHelper:Logout()
		status, response = afpHelper:CloseSession()
					
		-- stop after first succesfull attempt
		if ( output and #output > 0 ) then
			table.insert(output, "")
			table.insert(output, ("Information retrieved as: %s"):format(username))
			if ( maxfiles > 0 ) then
				table.insert(output, ("Output restricted to %d entries per volume. (See afp-ls.maxfiles)"):format(maxfiles))
			end
			return stdnse.format_output(true, output)
		end
	end
	return
end
