local bin = require "bin"
local msrpc = require "msrpc"
local smb = require "smb"
local string = require "string"
local vulns = require "vulns"
local stdnse = require "stdnse"

description = [[
Tests whether target machines are vulnerable to ms10-061 Printer Spooler impersonation vulnerability.

This vulnerability was used in Stuxnet worm.  The script checks for
the vuln in a safe way without a possibility of crashing the remote
system as this is not a memory corruption vulnerability.  In order for
the check to work it needs access to at least one shared printer on
the remote system.  By default it tries to enumerate printers by using
LANMAN API which on some systems is not available by default. In that
case user should specify printer share name as printer script
argument.  To find a printer share, smb-enum-shares can be used.
Also, on some systems, accessing shares requires valid credentials
which can be specified with smb library arguments smbuser and
smbpassword.

References:
  - http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-2729
  - http://technet.microsoft.com/en-us/security/bulletin/MS10-061
  - http://blogs.technet.com/b/srd/archive/2010/09/14/ms10-061-printer-spooler-vulnerability.aspx
]]
---
-- @usage nmap  -p 445 <target> --script=smb-vuln-ms10-061
--
-- @args printer Printer share name. Optional, by default script tries to enumerate available printer shares.
--
-- @output
-- PORT    STATE SERVICE      REASON
-- 445/tcp open  microsoft-ds syn-ack

-- Host script results:
-- | smb-vuln-ms10-061:
-- |   VULNERABLE:
-- |   Print Spooler Service Impersonation Vulnerability
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2010-2729
-- |     Risk factor: HIGH  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
-- |     Description:
-- |       The Print Spooler service in Microsoft Windows XP,Server 2003 SP2,Vista,Server 2008, and 7, when printer sharing is enabled,
-- |       does not properly validate spooler access permissions, which allows remote attackers to create files in a system directory,
-- |       and consequently execute arbitrary code, by sending a crafted print request over RPC, as exploited in the wild in September 2010,
-- |       aka "Print Spooler Service Impersonation Vulnerability."
-- |
-- |     Disclosure date: 2010-09-5
-- |     References:
-- |       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-2729
-- |       http://technet.microsoft.com/en-us/security/bulletin/MS10-061
-- |_      http://blogs.technet.com/b/srd/archive/2010/09/14/ms10-061-printer-spooler-vulnerability.aspx
--
-- @see stuxnet-detect.nse

author = "Aleksandar Nikolic"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln","intrusive"}

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

action = function(host,port)

  local ms10_061  = {
    title = "Print Spooler Service Impersonation Vulnerability",
    IDS = {CVE = 'CVE-2010-2729'},
    risk_factor = "HIGH",
    scores = {
      CVSSv2 = "9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)",
    },
    description = [[
The Print Spooler service in Microsoft Windows XP,Server 2003 SP2,Vista,Server 2008, and 7, when printer sharing is enabled,
does not properly validate spooler access permissions, which allows remote attackers to create files in a system directory,
and consequently execute arbitrary code, by sending a crafted print request over RPC, as exploited in the wild in September 2010,
aka "Print Spooler Service Impersonation Vulnerability."
    ]],
    references = {
      'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-2729',
      'http://technet.microsoft.com/en-us/security/bulletin/MS10-061',
      'http://blogs.technet.com/b/srd/archive/2010/09/14/ms10-061-printer-spooler-vulnerability.aspx'
    },
    dates = {
      disclosure = {year = '2010', month = '09', day = '5'},
    },
    exploit_results = {},
  }
  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  ms10_061.state = vulns.STATE.NOT_VULN
  local status, smbstate
  status, smbstate = msrpc.start_smb(host, msrpc.SPOOLSS_PATH,true)
  if(status == false) then
    stdnse.debug1("SMB: " .. smbstate)
    return false, smbstate
  end

  local bind_result
  status, bind_result = msrpc.bind(smbstate,msrpc.SPOOLSS_UUID, msrpc.SPOOLSS_VERSION, nil)
  if(status == false) then
    msrpc.stop_smb(smbstate)
    stdnse.debug1("SMB: " .. bind_result)
    return false, bind_result
  end
  local printer = stdnse.get_script_args(SCRIPT_NAME .. '.printer')
  -- if printer not set find available printers
  if not printer then
    stdnse.debug1("No printer specified, trying to find one...")
    local lanman_result
    local REMSmb_NetShareEnum_P  = "WrLeh"
    local REMSmb_share_info_1 = "B13BWz"
    status, lanman_result = msrpc.call_lanmanapi(
      smbstate, 0, REMSmb_NetShareEnum_P, REMSmb_share_info_1, "\x01\x00\x7e\xff")
    if status == false then
      stdnse.debug1("SMB: " .. lanman_result)
      stdnse.debug1("SMB: Looks like LANMAN API is not available. Try setting printer script arg.")
    end

    local parameters = lanman_result.parameters
    local data = lanman_result.data
    local pos, status, convert, entry_count, available_entries = bin.unpack("<SSSS", parameters)
    pos = 0
    local share_type, name, _
    for i = 1, entry_count, 1 do
      _,share_type = bin.unpack(">s",data,pos+14)
      pos, name = bin.unpack("<z", data, pos)

      -- pos needs to be rounded to the next even multiple of 20
      pos = pos + ( 20 - (#name % 20) ) - 1
      if share_type == 1 then -- share is printer
        stdnse.debug1("Found printer share %s.", name)
        printer = name
      end
    end
  end
  if not printer then
    stdnse.debug1("No printer found, system may be unpatched but it needs at least one printer shared to be vulnerable.")
    return false
  end
  stdnse.debug1("Using %s as printer.",printer)
  -- call RpcOpenPrinterEx - opnum 69
  local status, result = msrpc.spoolss_open_printer(smbstate,"\\\\"..host.ip.."\\"..printer)
  if not status then
    return false
  end
  local printer_handle = string.sub(result.data,25,#result.data-4)
  stdnse.debug1("Printer handle %s",stdnse.tohex(printer_handle))
  -- call RpcStartDocPrinter - opnum 17
  status,result = msrpc.spoolss_start_doc_printer(smbstate,printer_handle,",") -- patched version will allow this
  if not status then
    return false
  end
  local print_job_id = string.sub(result.data,25,#result.data-4)
  stdnse.debug1("Start doc printer job id %s",stdnse.tohex(print_job_id))

  -- call RpcWritePrinter - 19
  status, result = msrpc.spoolss_write_printer(smbstate,printer_handle,"aaaa")
  if not status then
    return false
  end
  local write_result = string.sub(result.data,25,#result.data-4)
  stdnse.debug1("Written %s bytes to a file.",stdnse.tohex(write_result))
  if stdnse.tohex(write_result) == "00000000" then -- patched version would report 4 bytes written
    ms10_061.state = vulns.STATE.VULN -- identified by diffing patched an unpatched version
  end
  -- call abort_printer to stop the actual printing in case the remote system is not vulnerable
  -- we care about the environment and don't want to spend more paper then needed :)
  status,result = msrpc.spoolss_abort_printer(smbstate,printer_handle)

  return report:make_output(ms10_061)
end
