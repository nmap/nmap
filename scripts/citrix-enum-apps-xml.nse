local citrixxml = require "citrixxml"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[ 
Extracts a list of applications, ACLs, and settings from the Citrix XML
service.

The script returns more output with higher verbosity.
]]

---
-- @usage
-- nmap --script=citrix-enum-apps-xml -p 80,443,8080 <host>
--
-- @output
-- PORT     STATE SERVICE
-- 8080/tcp open  http-proxy
-- | citrix-enum-apps-xml:  
-- |   Application: Notepad; Users: Anonymous
-- |   Application: iexplorer; Users: Anonymous
-- |_  Application: registry editor; Users: WIN-B4RL0SUCJ29\Joe; Groups: WIN-B4RL0SUCJ29\HR, *CITRIX_BUILTIN*\*CITRIX_ADMINISTRATORS*
--
-- PORT     STATE SERVICE
-- 8080/tcp open  http-proxy
-- | citrix-enum-apps-xml:  
-- |   Application: Notepad
-- |     Disabled: false
-- |     Desktop: false
-- |     On Desktop: false
-- |     Encryption: basic
-- |     In start menu: false
-- |     Publisher: labb1farm
-- |     SSL: false
-- |     Remote Access: false
-- |     Users: Anonymous
-- |   Application: iexplorer
-- |     Disabled: false
-- |     Desktop: false
-- |     On Desktop: false
-- |     Encryption: basic
-- |     In start menu: false
-- |     Publisher: labb1farm
-- |     SSL: false
-- |     Remote Access: false
-- |     Users: Anonymous
-- |   Application: registry editor
-- |     Disabled: false
-- |     Desktop: false
-- |     On Desktop: false
-- |     Encryption: basic
-- |     In start menu: false
-- |     Publisher: labb1farm
-- |     SSL: false
-- |     Remote Access: false
-- |     Users: WIN-B4RL0SUCJ29\Joe
-- |_    Groups: WIN-B4RL0SUCJ29\HR, *CITRIX_BUILTIN*\*CITRIX_ADMINISTRATORS*

-- Version 0.2
-- Created 11/26/2009 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 12/02/2009 - v0.2 - Use stdnse.format_ouput for output

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.portnumber({8080,80,443}, "tcp")

--- Creates a table which is suitable for use with stdnse.format_output
--
-- @param appdata table with results from parse_appdata_response
-- @param mode string short or long, see usage above
-- @return table suitable for stdnse.format_output
function format_output(appdata, mode)

		local result = {}
		local setting_titles = { {appisdisabled="Disabled"}, {appisdesktop="Desktop"}, {AppOnDesktop="On Desktop"}, 
									{Encryption="Encryption"}, {AppInStartmenu="In start menu"},
									{PublisherName="Publisher"}, {SSLEnabled="SSL"}, {RemoteAccessEnabled="Remote Access"} }


		if mode == "short" then
			for app_name, AppData in ipairs(appdata) do
				local line = "Application: " .. AppData.FName

				if AppData.AccessList then

					if AppData.AccessList.User then			
						line = line .. "; Users: " ..  stdnse.strjoin(", ", AppData.AccessList.User)
					end

					if AppData.AccessList.Group then
						line = line .. "; Groups: " .. stdnse.strjoin(", ", AppData.AccessList.Group)
					end

					table.insert(result, line)
				end
			end

		else

			for app_name, AppData in ipairs(appdata) do
				local result_part = {}
				
				result_part.name = "Application: " .. AppData.FName
				
				local settings = AppData.Settings

				for _, setting_pairs in ipairs(setting_titles) do
					for setting_key, setting_title in pairs(setting_pairs) do
						local setting_value = settings[setting_key] and settings[setting_key] or ""
						table.insert(result_part, setting_title .. ": " .. setting_value )
					end
				end


				if AppData.AccessList then
					if AppData.AccessList.User then
						table.insert(result_part, "Users: " .. stdnse.strjoin(", ", AppData.AccessList.User) )
					end	
			
					if AppData.AccessList.Group then 
						table.insert(result_part, "Groups: " .. stdnse.strjoin(", ", AppData.AccessList.Group) )
					end
				
					table.insert(result, result_part)
				end
				
			end

		end

		return result

	end
	
	
action = function(host,port)		

		local response = citrixxml.request_appdata(host.ip, port.number, {ServerAddress="",attr={addresstype="dot"},DesiredDetails={"all","access-list"} }) 
		local appdata = citrixxml.parse_appdata_response(response)
	
		local response = format_output(appdata, (nmap.verbosity() > 1 and "long" or "short"))
	
		return stdnse.format_output(true, response)

end
