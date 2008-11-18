
description = [[
Pulls back information about the remote system from the registry. Getting all
of the information requires an administrative account, although a user account
will still get a lot of it. Guest probably won't get any, nor will anonymous. 
This goes for all operating systems, including Windows 2000. 

Windows Vista doesn't appear to have the WINREG binding (or it's different and
I don't know it), so this doesn't support Vista at all. 
]]

---
-- @usage
-- nmap --script smb-system-info.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-system-info.nse -p U:137,T:139 <host>
--
-- @output
-- Host script results:
-- |  smb-system-info:
-- |  OS Details
-- |  |_ Microsoft Windows Server 2003 Service Pack 2 (ServerNT 5.2 build 3790)
-- |  |_ Installed on 2007-11-26 23:40:40
-- |  |_ Registered to IPC (organization: MYCOMPANY)
-- |  |_ Path: %SystemRoot%\system32;%SystemRoot%;%SystemRoot%\System32\Wbem;C:\Program Files\Microsoft SQL Server\90\Tools\binn\;C:\Program Files\IBM\Rational AppScan\
-- |  |_ Systemroot: C:\WINDOWS
-- |  |_ Page files: C:\pagefile.sys 2046 4092 (cleared at shutdown => 0)
-- |  Hardware
-- |  |_ CPU 0: Intel(R) Xeon(TM) CPU 2.80GHz [2780mhz GenuineIntel]
-- |  |_ Identifier 0: x86 Family 15 Model 2 Stepping 9
-- |  |_ CPU 1: Intel(R) Xeon(TM) CPU 2.80GHz [2780mhz GenuineIntel]
-- |  |_ Identifier 1: x86 Family 15 Model 2 Stepping 9
-- |  |_ CPU 2: Intel(R) Xeon(TM) CPU 2.80GHz [2780mhz GenuineIntel]
-- |  |_ Identifier 2: x86 Family 15 Model 2 Stepping 9
-- |  |_ CPU 3: Intel(R) Xeon(TM) CPU 2.80GHz [2780mhz GenuineIntel]
-- |  |_ Identifier 3: x86 Family 15 Model 2 Stepping 9
-- |  |_ Video driver: RAGE XL PCI Family (Microsoft Corporation)
-- |  Browsers
-- |  |_ Internet Explorer 7.0000
-- |_ |_ Firefox 3.0.3 (en-US)
-- 
-- @args smb* This script supports the <code>smbusername</code>,
-- <code>smbpassword</code>, <code>smbhash</code>, <code>smbguest</code>, and
-- <code>smbtype</code> script arguments of the <code>smb</code> module.
-----------------------------------------------------------------------



author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive"}

require 'msrpc'
require 'smb'
require 'stdnse'

hostrule = function(host)
	return smb.get_port(host) ~= nil
end

---Retrieves the requested value from the registry. 
--@param smbstate The SMB table we're using, bound to the WINREG service. 
--@param handle   The handle to the hive (HKLM or HKU, for example).
--@param key      The full path of the key to retrieve (like <code>"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"</code>).
--@param value    The value to retrieve (like <code>"NUMBER_OF_PROCESSORS"</code>).
--@return Status (true or false).
--@return The value (if status is true) or an error string (if status is false).
local function reg_get_value(smbstate, handle, key, value)

	-- Open the key
	status, openkey_result = msrpc.winreg_openkey(smbstate, handle, key)
    if(status == false) then
        return false, openkey_result
    end

	-- Query the value
	status, queryvalue_result = msrpc.winreg_queryvalue(smbstate, openkey_result['handle'], value)
    if(status == false) then
        return false, queryvalue_result
    end

	-- Close the key
	status, closekey_result = msrpc.winreg_closekey(smbstate, openkey_result['handle'], value)
    if(status == false) then
        return false, closekey_result
    end

	return true, queryvalue_result['value']
end

local function get_info_registry(host)

	local result = {}

	-- Create the SMB session
	status, smbstate = msrpc.start_smb(host, msrpc.WINREG_PATH)
	if(status == false) then
		return false, smbstate
	end

    -- Bind to WINREG service
    status, bind_result = msrpc.bind(smbstate, msrpc.WINREG_UUID, msrpc.WINREG_VERSION, nil)
    if(status == false) then
        msrpc.stop_smb(smbstate)
        return false, bind_result
    end

	-- Open HKEY_LOCAL_MACHINE
    status, openhklm_result = msrpc.winreg_openhklm(smbstate)
    if(status == false) then
        msrpc.stop_smb(smbstate)
        return false, openhklm_result
    end

	-- Processor information
	result['status-number_of_processors'], result['number_of_processors']   = reg_get_value(smbstate, openhklm_result['handle'], "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "NUMBER_OF_PROCESSORS")
	if(status == false) then
		result['number_of_processors'] = 0
	end
	result['status-os'], result['os']                                         = reg_get_value(smbstate, openhklm_result['handle'], "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "OS")
	result['status-path'], result['path']                                     = reg_get_value(smbstate, openhklm_result['handle'], "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "Path")
	result['status-processor_architecture'], result['processor_architecture'] = reg_get_value(smbstate, openhklm_result['handle'], "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "PROCESSOR_ARCHITECTURE")
	result['status-processor_identifier'], result['processor_identifier']     = reg_get_value(smbstate, openhklm_result['handle'], "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "PROCESSOR_IDENTIFIER")
	result['status-processor_level'], result['processor_level']               = reg_get_value(smbstate, openhklm_result['handle'], "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "PROCESSOR_LEVEL")
	result['status-processor_revision'], result['processor_revision']         = reg_get_value(smbstate, openhklm_result['handle'], "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "PROCESSOR_REVISION")

	for i = 0, result['number_of_processors'] - 1, 1 do
		result['status-~mhz'..i], result['~mhz' .. i]                               = reg_get_value(smbstate, openhklm_result['handle'], "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\" .. i, "~MHz")
		result['status-identifier'..i], result['identifier' .. i]                   = reg_get_value(smbstate, openhklm_result['handle'], "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\" .. i, "Identifier")
		result['status-processornamestring'..i], result['processornamestring' .. i] = reg_get_value(smbstate, openhklm_result['handle'], "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\" .. i, "ProcessorNameString")
		result['status-vendoridentifier'..i], result['vendoridentifier' .. i]       = reg_get_value(smbstate, openhklm_result['handle'], "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\" .. i, "VendorIdentifier")
	end
--	status, result['physicalmemory']   = reg_get_value(smbstate, openhklm_result['handle'], "HARDWARE\\ResourceMap\\System Resources\\Physical Memory", ".Translated")

	-- TODO: Known DLLs?

	-- Paging file
	result['status-pagingfiles'], result['pagingfiles']                         = reg_get_value(smbstate, openhklm_result['handle'], "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", "PagingFiles")
	result['status-clearpagefileatshutdown'], result['clearpagefileatshutdown'] = reg_get_value(smbstate, openhklm_result['handle'], "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", "ClearPageFileAtShutdown")

	-- OS Information
	result['status-csdversion'], result['csdversion']              = reg_get_value(smbstate, openhklm_result['handle'], "Software\\Microsoft\\Windows NT\\CurrentVersion", "CSDVersion")
	if(result['status-csdversion'] == false) then
		result['csdversion'] = "(no service packs)"
	end
	result['status-currentbuildnumber'], result['currentbuildnumber']  = reg_get_value(smbstate, openhklm_result['handle'], "Software\\Microsoft\\Windows NT\\CurrentVersion", "CurrentBuildNumber")
	result['status-currenttype'], result['currenttype']                = reg_get_value(smbstate, openhklm_result['handle'], "Software\\Microsoft\\Windows NT\\CurrentVersion", "CurrentType")
	result['status-currentversion'], result['currentversion']          = reg_get_value(smbstate, openhklm_result['handle'], "Software\\Microsoft\\Windows NT\\CurrentVersion", "CurrentVersion")
	result['status-installdate'], result['installdate']                = reg_get_value(smbstate, openhklm_result['handle'], "Software\\Microsoft\\Windows NT\\CurrentVersion", "InstallDate")
	if(result['status-installdate'] ~= false) then
		result['installdate'] = os.date("%Y-%m-%d %H:%M:%S", result['installdate'])
	end

	result['status-productname'], result['productname']                        = reg_get_value(smbstate, openhklm_result['handle'], "Software\\Microsoft\\Windows NT\\CurrentVersion", "Productname")
	result['status-registeredowner'], result['registeredowner']                = reg_get_value(smbstate, openhklm_result['handle'], "Software\\Microsoft\\Windows NT\\CurrentVersion", "RegisteredOwner")
	result['status-registeredorganization'], result['registeredorganization']  = reg_get_value(smbstate, openhklm_result['handle'], "Software\\Microsoft\\Windows NT\\CurrentVersion", "RegisteredOrganization")
	result['status-systemroot'], result['systemroot']                          = reg_get_value(smbstate, openhklm_result['handle'], "Software\\Microsoft\\Windows NT\\CurrentVersion", "SystemRoot")
	result['status-producttype'], result['producttype']                        = reg_get_value(smbstate, openhklm_result['handle'], "System\\CurrentControlSet\\Control\\ProductOptions", "ProductType")
	result['status-productsuite'], result['productsuite']                      = reg_get_value(smbstate, openhklm_result['handle'], "System\\CurrentControlSet\\Control\\ProductOptions", "ProductSuite")

	-- Driver information
	result['status-video_driverdesc'], result['video_driverdesc']        = reg_get_value(smbstate, openhklm_result['handle'], "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "DriverDesc")

	-- Software versions
	result['status-ie_version'], result['ie_version']              = reg_get_value(smbstate, openhklm_result['handle'], "Software\\Microsoft\\Internet Explorer\\Version Vector", "IE")
	result['status-ff_version'], result['ff_version']              = reg_get_value(smbstate, openhklm_result['handle'], "Software\\Mozilla\\Mozilla Firefox", "CurrentVersion")
	if(result['status-ff_version'] == false) then
		result['ff_version'] = "<not installed>"
	end

	msrpc.stop_smb(smbstate)
	
	return true, result
end

action = function(host)

	status, result = get_info_registry(host)

	if(status == false) then
		if(nmap.debugging() > 0) then
			return "ERROR: " .. result
		else
			return nil
		end
	else

		local response = " \n"

		if(result['status-os'] == true) then
			response = response .. string.format("OS Details\n")
			response = response .. string.format("|_ %s %s (%s %s build %s)\n",                   result['productname'], result['csdversion'], result['producttype'], result['currentversion'], result['currentbuildnumber'])
			response = response .. string.format("|_ Installed on %s\n",                          result['installdate'])
			response = response .. string.format("|_ Registered to %s (organization: %s)\n",      result['registeredowner'], result['registeredorganization'])
			response = response .. string.format("|_ Path: %s\n",                                 result['path'])
			response = response .. string.format("|_ Systemroot: %s\n",                           result['systemroot'])
			response = response .. string.format("|_ Page files: %s (cleared at shutdown => %s)\n", result['pagingfiles'], result['clearpagefileatshutdown'])
	
			response = response .. string.format("Hardware\n")
			for i = 0, result['number_of_processors'] - 1, 1 do
				response = response .. string.format("|_ CPU %d: %s [%dmhz %s]\n", i, result['processornamestring'..i], result['~mhz'..i], result['vendoridentifier'..i])
				response = response .. string.format("|_ Identifier %d: %s\n",  i, result['identifier'..i])
			end
			response = response .. string.format("|_ Video driver: %s\n", result['video_driverdesc'])

			response = response .. string.format("Browsers\n")
			response = response .. string.format("|_ Internet Explorer %s\n", result['ie_version'])
			if(result['status-ff_version']) then
				response = response .. string.format("|_ Firefox %s\n", result['ff_version'])
			end
		elseif(result['status-productname'] == true) then
			if(nmap.debugging() > 0) then
				response = response .. string.format("|_ Access was denied for certain values; try an administrative account for more complete information\n")
			end
			response = response .. string.format("OS Details\n")
			response = response .. string.format("|_ %s %s (%s %s build %s)\n",                   result['productname'], result['csdversion'], result['producttype'], result['currentversion'], result['currentbuildnumber'])
			response = response .. string.format("|_ Installed on %s\n",                          result['installdate'])
			response = response .. string.format("|_ Registered to %s (organization: %s)\n",      result['registeredowner'], result['registeredorganization'])
			response = response .. string.format("|_ Systemroot: %s\n",                           result['systemroot'])
		else
			if(nmap.debugging() > 0) then
				response = string.format("|_ Account being used was unable to probe for information, try using an administrative account\n")
			else
				response = nil
			end
		end

		return response
	end
end


