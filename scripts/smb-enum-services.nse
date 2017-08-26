local msrpc = require "msrpc"
local smb = require "smb"
local smbauth = require "smbauth"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local http = require "http"
local shortport = require "shortport"

description = [[
Retrieves the list of services running on a remote Windows system.
This script is not yet complete, its under development.

References:
* https://msdn.microsoft.com/en-us/library/windows/desktop/ms682637(v=vs.85).aspx
* https://msdn.microsoft.com/en-us/library/windows/desktop/ms682651(v=vs.85).aspx
* https://github.com/samba-team/samba/blob/d8a5565ae647352d11d622bd4e73ff4568678a7c/librpc/idl/svcctl.idl
]]

-- @usage
-- nmap --script smb-enum-services.nse -p445 <host>
-- nmap --script smb-enum-services.nse --script-args smbusername=<username>,smbpass=<password> -p445 <host>

author = "Rewanth Cool"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive"}

portrule = shortport.port_or_service({445, 139}, "microsoft-ds", "tcp", "open")

action = function(host, port)

  local status, smbstate = msrpc.start_smb(host, msrpc.SVCCTL_PATH)
  status, bind_result = msrpc.bind(smbstate, msrpc.SVCCTL_UUID, msrpc.SVCCTL_VERSION, nil)

  if(status == false) then
    smb.stop(smbstate)
    return false, bind_result
  end

  -- Open the service manager
  stdnse.debug2("Opening the remote service manager")

  status, open_result = msrpc.svcctl_openscmanagerw(smbstate, host.ip)

  if(status == false) then
    smb.stop(smbstate)
    return false, open_result
  end

  -- Fetches service name, display name and service status of every service.
  status, result = msrpc.svcctl_enumservicesstatusw(smbstate, open_result["handle"])

  -- Close the service manager
  stdnse.debug2("Closing the remote service manager")

  status, close_result = msrpc.svcctl_closeservicehandle(smbstate, open_result['handle'])

  if(status == false) then
    smb.stop(smbstate)
    return false, close_result
  end

  smb.stop(smbstate)

  return result

end
