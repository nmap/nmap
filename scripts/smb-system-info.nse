local datetime = require "datetime"
local msrpc = require "msrpc"
local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Pulls back information about the remote system from the registry. Getting all
of the information requires an administrative account, although a user account
will still get a lot of it. Guest probably won't get any, nor will anonymous.
This goes for all operating systems, including Windows 2000.

Windows Vista disables remote registry access by default, so unless it was enabled,
this script won't work.

If you know of more information stored in the Windows registry that could be interesting,
post a message to the nmap-dev mailing list and I (Ron Bowes) will add it to my todo list.
Adding new checks to this is extremely easy.

WARNING: I have experienced crashes in <code>regsvc.exe</code> while making registry calls
against a fully patched Windows 2000 system; I've fixed the issue that caused it,
but there's no guarantee that it (or a similar vuln in the same code) won't show
up again. Since the process automatically restarts, it doesn't negatively impact
the system, besides showing a message box to the user.
]]

---
-- @usage
-- nmap --script smb-system-info.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-system-info.nse -p U:137,T:139 <host>
--
-- @output
-- Host script results:
-- |  smb-system-info:
-- |  |  OS Details
-- |  |  |  Microsoft Windows 2000 Service Pack 4 (ServerNT 5.0 build 2195)
-- |  |  |  Installed on 2008-10-10 05:47:19
-- |  |  |  Registered to Ron (organization: Government of Manitoba)
-- |  |  |  Path: %SystemRoot%\system32;%SystemRoot%;%SystemRoot%\System32\Wbem;C:\Program Files\Graphviz2.20\Bin;
-- |  |  |  Systemroot: C:\WINNT
-- |  |  |_ Page files: C:\pagefile.sys 192 384 (cleared at shutdown => 0)
-- |  |  Hardware
-- |  |  |  CPU 0: Intel(R) Xeon(TM) CPU 2.80GHz [2800mhz GenuineIntel]
-- |  |  |  |_ Identifier 0: x86 Family 15 Model 3 Stepping 8
-- |  |  |_ Video driver: VMware SVGA II
-- |  |  Browsers
-- |  |  |  Internet Explorer 6.0000
-- |_ |_ |_ Firefox 3.0.12 (en-US)
-----------------------------------------------------------------------



author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive"}
dependencies = {"smb-brute"}


-- TODO: This script needs some love

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
  local status, openkey_result = msrpc.winreg_openkey(smbstate, handle, key)
  if(status == false) then
    return false, openkey_result
  end

  -- Query the value
  local status, queryvalue_result = msrpc.winreg_queryvalue(smbstate, openkey_result['handle'], value)
  if(status == false) then
    return false, queryvalue_result
  end

  -- Close the key
  local status, closekey_result = msrpc.winreg_closekey(smbstate, openkey_result['handle'], value)
  if(status == false) then
    return false, closekey_result
  end

  return true, queryvalue_result['value']
end

local function get_info_registry(host)

  local result = {}

  -- Create the SMB session
  local status, smbstate = msrpc.start_smb(host, msrpc.WINREG_PATH)
  if(status == false) then
    return false, smbstate
  end

  -- Bind to WINREG service
  local status, bind_result = msrpc.bind(smbstate, msrpc.WINREG_UUID, msrpc.WINREG_VERSION, nil)
  if(status == false) then
    msrpc.stop_smb(smbstate)
    return false, bind_result
  end

  -- Open HKEY_LOCAL_MACHINE
  local status, openhklm_result = msrpc.winreg_openhklm(smbstate)
  if(status == false) then
    msrpc.stop_smb(smbstate)
    return false, openhklm_result
  end

  -- Processor information
  result['status-number_of_processors'], result['number_of_processors']   = reg_get_value(smbstate, openhklm_result['handle'], "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "NUMBER_OF_PROCESSORS")
  if(result['status-number_of_processors'] == false) then
    result['number_of_processors'] = 0
  end
  result['status-os'], result['os']                                         = reg_get_value(smbstate, openhklm_result['handle'], "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "OS")
  result['status-path'], result['path']                                     = reg_get_value(smbstate, openhklm_result['handle'], "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "Path")
  result['status-processor_architecture'], result['processor_architecture'] = reg_get_value(smbstate, openhklm_result['handle'], "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "PROCESSOR_ARCHITECTURE")
  result['status-processor_identifier'], result['processor_identifier']     = reg_get_value(smbstate, openhklm_result['handle'], "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "PROCESSOR_IDENTIFIER")
  result['status-processor_level'], result['processor_level']               = reg_get_value(smbstate, openhklm_result['handle'], "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "PROCESSOR_LEVEL")
  result['status-processor_revision'], result['processor_revision']         = reg_get_value(smbstate, openhklm_result['handle'], "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "PROCESSOR_REVISION")

  -- remove trailing zero terminator
  local num_procs = result['number_of_processors']:match("^[^%z]*")

  for i = 0, tonumber(num_procs) - 1, 1 do
    result['status-~mhz'..i], result['~mhz' .. i]                               = reg_get_value(smbstate, openhklm_result['handle'], "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\" .. i, "~MHz")
    result['status-identifier'..i], result['identifier' .. i]                   = reg_get_value(smbstate, openhklm_result['handle'], "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\" .. i, "Identifier")
    result['status-processornamestring'..i], result['processornamestring' .. i] = reg_get_value(smbstate, openhklm_result['handle'], "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\" .. i, "ProcessorNameString")
    result['status-vendoridentifier'..i], result['vendoridentifier' .. i]       = reg_get_value(smbstate, openhklm_result['handle'], "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\" .. i, "VendorIdentifier")
  end
  -- status, result['physicalmemory']   = reg_get_value(smbstate, openhklm_result['handle'], "HARDWARE\\ResourceMap\\System Resources\\Physical Memory", ".Translated")

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
    result['installdate'] = datetime.format_timestamp(result['installdate'])
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

  local status, result = get_info_registry(host)

  if(status == false) then
    return stdnse.format_output(false, result)
  end

  local response = {}

  if(result['status-os'] == true) then
    local osdetails = {}
    osdetails['name'] = "OS Details"
    table.insert(osdetails, string.format("%s %s (%s %s build %s)",                     result['productname'], result['csdversion'], result['producttype'], result['currentversion'], result['currentbuildnumber']))
    table.insert(osdetails, string.format("Installed on %s",                            result['installdate']))
    table.insert(osdetails, string.format("Registered to %s (organization: %s)",        result['registeredowner'], result['registeredorganization']))
    table.insert(osdetails, string.format("Path: %s",                                   result['path']))
    table.insert(osdetails, string.format("Systemroot: %s",                             result['systemroot']))
    table.insert(osdetails, string.format("Page files: %s (cleared at shutdown => %s)", result['pagingfiles'], result['clearpagefileatshutdown']))
    table.insert(response, osdetails)

    local hardware = {}
    hardware['name'] = "Hardware"
    -- remove trailing zero terminator
    local num_procs = result['number_of_processors']:match("^[^%z]*")
    for i = 0, tonumber(num_procs) - 1, 1 do
      if(result['status-processornamestring'..i] == false) then
        result['status-processornamestring'..i] = "Unknown"
      end

      local processor = {}
      processor['name'] = string.format("CPU %d: %s [%dmhz %s]", i, string.gsub(result['processornamestring'..i], '  ', ''), result['~mhz'..i], result['vendoridentifier'..i])
      table.insert(processor, string.format("Identifier %d: %s",  i, result['identifier'..i]))
      table.insert(hardware, processor)
    end
    table.insert(hardware, string.format("Video driver: %s", result['video_driverdesc']))
    table.insert(response, hardware)

    local browsers = {}
    browsers['name'] = "Browsers"
    table.insert(browsers, string.format("Internet Explorer %s", result['ie_version']))
    if(result['status-ff_version']) then
      table.insert(browsers, string.format("Firefox %s", result['ff_version']))
    end
    table.insert(response, browsers)

    return stdnse.format_output(true, response)
  elseif(result['status-productname'] == true) then

    local osdetails = {}
    osdetails['name'] = 'OS Details'
    osdetails['warning'] = "Access was denied for certain values; try an administrative account for more complete information"

    table.insert(osdetails, string.format("%s %s (%s %s build %s)",              result['productname'], result['csdversion'], result['producttype'], result['currentversion'], result['currentbuildnumber']))
    table.insert(osdetails, string.format("Installed on %s",                     result['installdate']))
    table.insert(osdetails, string.format("Registered to %s (organization: %s)", result['registeredowner'], result['registeredorganization']))
    table.insert(osdetails, string.format("Systemroot: %s",                      result['systemroot']))
    table.insert(response, osdetails)

    return stdnse.format_output(true, response)
  end

  return stdnse.format_output(false, "Account being used was unable to probe for information, try using an administrative account")
end


