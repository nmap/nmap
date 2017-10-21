local smb = require "smb"
local vulns = require "vulns"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Checks if the target machine is running the Double Pulsar SMB backdoor.

Based on the python detection script by Luke Jennings of Countercept.
https://github.com/countercept/doublepulsar-detection-script
]]

---
-- @usage nmap -p 445 <target> --script=smb-double-pulsar-backdoor
--
-- @see smb-vuln-ms17-010.nse
--
-- @output
-- | smb-double-pulsar-backdoor:
-- |   VULNERABLE:
-- |   Double Pulsar SMB Backdoor
-- |     State: VULNERABLE
-- |     Risk factor: HIGH  CVSSv2: 10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/A:C)
-- |       The Double Pulsar SMB backdoor was detected running on the remote machine.
-- |
-- |     Disclosure date: 2017-04-14
-- |     References:
-- |       https://isc.sans.edu/forums/diary/Detecting+SMB+Covert+Channel+Double+Pulsar/22312/
-- |       https://github.com/countercept/doublepulsar-detection-script
-- |_      https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation

author = "Andrew Orr"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe", "malware"}

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

-- stolen from smb.lua as timeout needs to be modified to get a response
local function send_transaction2(smbstate, sub_command, function_parameters, function_data, overrides)
  overrides = overrides or {}
  local header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, pid, mid
  local header, parameters, data
  local parameter_offset = 0
  local parameter_size   = 0
  local data_offset      = 0
  local data_size        = 0
  local total_word_count, total_data_count, reserved1, parameter_count, parameter_displacement, data_count, data_displacement, setup_count, reserved2
  local response = {}

  -- Header is 0x20 bytes long (not counting NetBIOS header).
  header = smb.smb_encode_header(smbstate, 0x32, overrides) -- 0x32 = SMB_COM_TRANSACTION2

  if(function_parameters) then
    parameter_offset = 0x44
    parameter_size = #function_parameters
    data_offset = #function_parameters + 33 + 32
  end

  -- Parameters are 0x20 bytes long.
  parameters = string.pack("<I2 I2 I2 I2 B B I2 I4 I2 I2 I2 I2 I2 B B I2",
    parameter_size,                  -- Total parameter count.
    data_size,                       -- Total data count.
    0x000a,                          -- Max parameter count.
    0x3984,                          -- Max data count.
    0x00,                            -- Max setup count.
    0x00,                            -- Reserved.
    0x0000,                          -- Flags (0x0000 = 2-way transaction, don't disconnect TIDs).
    10803622,                        -- Timeout
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
  .. (function_data or '')

  -- Send the transaction request
  stdnse.debug2("SMB: Sending SMB_COM_TRANSACTION2")
  local result, err = smb.smb_send(smbstate, header, parameters, data, overrides)
  if(result == false) then
    return false, err
  end

  return true
end

action = function(host,port)
  local double_pulsar  = {
    title = "Double Pulsar SMB Backdoor",
--    IDS = {CVE = 'CVE-2010-2550'},
    risk_factor = "HIGH",
    scores = {
      CVSSv2 = "10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/A:C)",
    },
    description = [[
The Double Pulsar SMB backdoor was detected running on the remote machine.
]],
    references = {
      'https://github.com/countercept/doublepulsar-detection-script',
      'https://isc.sans.edu/forums/diary/Detecting+SMB+Covert+Channel+Double+Pulsar/22312/',
      'https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation'
    },
    dates = {
      disclosure = {year = '2017', month = '04', day = '14'},
    },
    exploit_results = {},
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  double_pulsar.state = vulns.STATE.NOT_VULN

  local share = "IPC$"

  local status, smbstate = smb.start_ex(host, true, true, share, nil, nil, nil)

  if not status then
    stdnse.debug1("Could not connect to IPC$ share over SMB.")
  else
    -- the multiplex ID needs to be 65
    smbstate["mid"] = 65;
    -- 12 (not 11, not 13) nulls
    local param = ("\0"):rep(12)
    -- 0x000e is SESSION_SETUP
    local status, result = send_transaction2(smbstate, 0xe, param)
    if not status then
      stdnse.debug1("Error: ", result)
    else
      local status, header, parameters, data = smb.smb_read(smbstate)
      local multiplex_id = string.unpack("<I2", header, 1 + string.packsize("BBBBB I4 B I2 I2 i8 I2 I2 I2 I2"))

      if (multiplex_id == 81) then
        double_pulsar.state = vulns.STATE.VULN
      else
        stdnse.debug1("Machine is not vulnerable")
      end
    end
  end
  return report:make_output(double_pulsar)
end
