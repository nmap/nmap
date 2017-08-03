local nmap = require "nmap"
local smb = require "smb"
local vulns = require "vulns"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Attempts to detect if a Microsoft SMBv1 server is vulnerable to a remote code
 execution vulnerability (ms17-010, a.k.a. EternalBlue).
 The vulnerability is actively exploited by WannaCry and Petya ransomware and other malware.

The script connects to the $IPC tree, executes a transaction on FID 0 and
 checks if the error "STATUS_INSUFF_SERVER_RESOURCES" is returned to
 determine if the target is not patched against ms17-010. Additionally it checks
 for known error codes returned by patched systems.

Tested on Windows XP, 2003, 7, 8, 8.1, 10, 2008, 2012 and 2016.

References:
* https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
* https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
* https://msdn.microsoft.com/en-us/library/ee441489.aspx
* https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/smb/smb_ms17_010.rb
* https://github.com/cldrn/nmap-nse-scripts/wiki/Notes-about-smb-vuln-ms17-010
]]

---
-- @usage nmap -p445 --script smb-vuln-ms17-010 <target>
-- @usage nmap -p445 --script vuln <target>
--
-- @see smb-double-pulsar-backdoor.nse
--
-- @output
-- Host script results:
-- | smb-vuln-ms17-010:
-- |   VULNERABLE:
-- |   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2017-0143
-- |     Risk factor: HIGH
-- |       A critical remote code execution vulnerability exists in Microsoft SMBv1
-- |        servers (ms17-010).
-- |
-- |     Disclosure date: 2017-03-14
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
-- |       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
-- |_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
--
-- @xmloutput
-- <table key="CVE-2017-0143">
-- <elem key="title">Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)</elem>
-- <elem key="state">VULNERABLE</elem>
-- <table key="ids">
-- <elem>CVE:CVE-2017-0143</elem>
-- </table>
-- <table key="description">
-- <elem>A critical remote code execution vulnerability exists in Microsoft SMBv1&#xa; servers (ms17-010).&#xa;</elem>
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="month">03</elem>
-- <elem key="year">2017</elem>
-- <elem key="day">14</elem>
-- </table>
-- </table>
-- <elem key="disclosure">2017-03-14</elem>
-- <table key="refs">
-- <elem>https://technet.microsoft.com/en-us/library/security/ms17-010.aspx</elem>
-- <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143</elem>
-- <elem>https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/</elem>
-- </table>
-- </table>
--
-- @args smb-vuln-ms17-010.sharename Share name to connect. Default: IPC$
---

author = "Paulino Calderon <paulino()calderonpale.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

local function check_ms17010(host, port, sharename)
  local status, smbstate = smb.start_ex(host, true, true, "\\\\".. host.ip .. "\\" .. sharename, nil, nil, nil)
  if not status then
    stdnse.debug1("Could not connect to '%s'", sharename)
    return false, string.format("Could not connect to '%s'", sharename)
  else
    local overrides = {}
    local smb_header, smb_params, smb_cmd

    stdnse.debug1("Connected to share '%s'", sharename)

    overrides['parameters_length'] = 0x10

    --SMB_COM_TRANSACTION opcode is 0x25
    smb_header = smb.smb_encode_header(smbstate, 0x25, overrides)
    smb_params = string.pack(">I2 I2 I2 I2 B B I2 I4 I2 I2 I2 I2 I2 B B I2 I2 I2 I2 I2 I2",
      0x0,     -- Total Parameter count (2 bytes)
      0x0,     -- Total Data count (2 bytes)
      0xFFFF,  -- Max Parameter count (2 bytes)
      0xFFFF,  -- Max Data count (2 bytes)
      0x0,     -- Max setup Count (1 byte)
      0x0,     -- Reserved (1 byte)
      0x0,     -- Flags (2 bytes)
      0x0,     -- Timeout (4 bytes)
      0x0,     -- Reserved (2 bytes)
      0x0,     -- ParameterCount (2 bytes)
      0x4a00,  -- ParameterOffset (2 bytes)
      0x0,     -- DataCount (2 bytes)
      0x4a00,  -- DataOffset (2 bytes)
      0x02,    -- SetupCount (1 byte)
      0x0,     -- Reserved (1 byte)
      0x2300,  -- PeekNamedPipe opcode
      0x0,     --
      0x0700,  -- BCC (Length of "\PIPE\")
      0x5c50,  -- \P
      0x4950,  -- IP
      0x455c   -- E\
      )
    stdnse.debug2("SMB: Sending SMB_COM_TRANSACTION")
    local result, err = smb.smb_send(smbstate, smb_header, smb_params, '', overrides)
    if(result == false) then
      stdnse.debug1("There was an error in the SMB_COM_TRANSACTION request")
      return false, err
    end

    local result, smb_header, _, _ = smb.smb_read(smbstate)
    local _ , smb_cmd, err = string.unpack("<c4 B I4", smb_header)
    if smb_cmd == 37 then -- SMB command for Trans is 0x25
      stdnse.debug1("Valid SMB_COM_TRANSACTION response received")

      --STATUS_INSUFF_SERVER_RESOURCES indicate that the machine is not patched
      if err == 0xc0000205 then
        stdnse.debug1("STATUS_INSUFF_SERVER_RESOURCES response received")
        return true
      elseif err == 0xc0000022 then
        stdnse.debug1("STATUS_ACCESS_DENIED response received. This system is likely patched.")
        return false, "This system is patched."
      elseif err == 0xc0000008 then
        stdnse.debug1("STATUS_INVALID_HANDLE response received. This system is likely patched.")
        return false, "This system is patched."
      end
      stdnse.debug1("Error code received:%s", stdnse.tohex(err))
    else
      stdnse.debug1("Received invalid command id.")
      return false, string.format("Unexpected SMB response:%s", stdnse.tohex(err))
    end
  end
end

action = function(host,port)
  local vuln_status, err
  local vuln = {
    title = "Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)",
    IDS = {CVE = 'CVE-2017-0143'},
    risk_factor = "HIGH",
    description = [[
A critical remote code execution vulnerability exists in Microsoft SMBv1
 servers (ms17-010).
    ]],
    references = {
      'https://technet.microsoft.com/en-us/library/security/ms17-010.aspx',
      'https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/'
    },
    dates = {
      disclosure = {year = '2017', month = '03', day = '14'},
    }
  }
  local sharename = stdnse.get_script_args(SCRIPT_NAME .. ".sharename") or "IPC$"
  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  vuln.state = vulns.STATE.NOT_VULN

  vuln_status, err = check_ms17010(host, port, sharename)
  if vuln_status then
    stdnse.debug1("This host is missing the patch for ms17-010!")
    vuln.state = vulns.STATE.VULN
  else
    if nmap.verbosity() >=2 then
      return err
    end
  end
  return report:make_output(vuln)
end
