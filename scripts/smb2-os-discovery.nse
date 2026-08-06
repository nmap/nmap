local smb = require "smb"
local smb2 = require "smb2"
local stdnse = require "stdnse"
local table = require "table"
local nmap = require "nmap"

description = [[
Attempts to determine the operating system, computer name, domain name, and current
time over the SMB2 protocol (ports 445 or 139).
]]

---
-- @usage nmap --script smb-os-discovery.nse -p445 127.0.0.1
--
-- @output
-- | Host script results:
-- | smb2-os-discovery:
-- |   OS: Windows 10 2004 (OS build 19041)
-- |   OS CPE: cpe:/o:microsoft:windows_10
-- |   NetBIOS Domain Name: Test
-- |   NetBIOS Computer Name: Test
-- |   Dns Domain Name:
-- |   Dns Computer Name: localhost
-- |_  Timestamp: 2024-02-15 13:42:29

-- @xmloutput
-- <elem key="os">Windows 10 2004 (OS build 19041)</elem>
-- <elem key="cpe">cpe:/o:microsoft:windows_10</elem>
-- <elem key="nb_domain_name">Test</elem>
-- <elem key="nb_computer_name">Test</elem>
-- <elem key="dns_domain_name"></elem>
-- <elem key="dns_computer_name">localhost</elem>
-- <elem key="timestamp">2024-02-15 13:42:29</elem>
---

author = "galycannon"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

action = function(host,port)
  local status, smbstate, overrides
  overrides = {}

  status, smbstate = smb.start(host)
  if(status == false) then
    return stdnse.format_output(false, "Connection error.")
  end
  
  local max_dialect
  status, max_dialect = smb2.negotiate_v2(smbstate)
  if not status then
    return stdnse.format_output(false, "SMB 2+ not supported")
  end
  
  response, stdnse_output = session_setup(smbstate)
  smb.stop(smbstate)
  
  return response, stdnse_output
end

function session_setup(smb)
  local overrides = {}
  overrides['CreditCharge'] = 1
  overrides['CreditR'] = 33
  overrides['MessageId'] = 1
  overrides['Signature'] = 0
  local header = smb2.smb2_encode_header_sync(smb, 0x0001, overrides)
  
  local StructureSize = 0x19
  local Flags = 0
  local SecurityMode = 1
  local Capabilities = 0
  local Channel = 0
  local Blob_Offset = 0x58
  local Blob_Length = 74
  local Pre_Session_Id = 0
  
  local data = string.pack("<I2 I1 I1 I4 I4 I2 I2 I8",
    StructureSize,  -- 2 bytes: StructureSize
    Flags,          -- 1 byte:  Flags
    SecurityMode,   -- 1 byte:  SecurityMode
    Capabilities,   -- 4 bytes: Capabilities
    Channel,        -- 4 bytes: Channel
    Blob_Offset,    -- 2 bytes: Blob Offset
    Blob_Length,    -- 2 bytes: Blob Length
    Pre_Session_Id  -- 8 bytes: Previous Session Id
  )
  local hexList = {0x60,0x48,0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02,0xa0,0x3e,0x30,0x3c,0xa0,0x0e,0x30,0x0c,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,0xa2,0x2a,0x04,0x28,0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x01,0x00,0x00,0x00,0x15,0x82,0x88,0xe0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x0f}
  local formatStr = string.rep("I1", #hexList)
  local packedString = string.pack(formatStr, table.unpack(hexList))

  data = data .. packedString
  
  status, err = smb2.smb2_send(smb, header, data)
  if not status then
    return false, err
  end
  status, header, data = smb2.smb2_read(smb)
  
  local structure_size, session_flags, blob_offset, blob_length = string.unpack("<I2 I2 I2 I2",data)
  
  neg_token_response = string.sub(data, blob_offset - #header + 1, blob_offset - #header + blob_length)
  
  local ntlm_start, ntlm_end = string.find(neg_token_response, "NTLMSSP\x00")
  local ntlm_token_response
  if ntlm_start then
    ntlm_token_response = string.sub(neg_token_response, ntlm_start)
  end
  
  local version_info = string.sub(ntlm_token_response, 48 + 1, 48 + 8)
  local major_version = string.byte(string.sub(version_info, 1, 2))
  local minor_version = string.byte(string.sub(version_info, 2, 3))
  local build_number = string.unpack("<H", string.sub(version_info, 3, 5))
  os_version = get_os(major_version, minor_version, build_number)
  cpe = make_cpe(os_version)
  
  local response = stdnse.output_table()
  local output_lines = {}
  response.os = os_version
  response.cpe = cpe
  
  if response.os then
    add_to_output(output_lines, "OS", os_version)
  else
    add_to_output(output_lines, "OS", "Unknown")
  end
  add_to_output(output_lines, "OS CPE", response.cpe)
  
  local target_length = string.unpack("<H", string.sub(ntlm_token_response, 40 + 1, 40 + 2))
  local target_offset = string.unpack("<H", string.sub(ntlm_token_response, 44 + 1, 44 + 4))
  local target_info = string.sub(ntlm_token_response, target_offset + 1, target_offset + target_length)
  local target_info_table = parse_data(target_info)
  
  local indent = 4
  for k, v in pairs(target_info_table) do
    if v.target_type == "NetBIOS Computer Name" then
      response.nb_computer_name = v.content
      add_to_output(output_lines, "NetBIOS Computer Name", v.content)
    elseif v.target_type == "NetBIOS Domain Name" then
      response.nb_domain_name = v.content
      add_to_output(output_lines, "NetBIOS Domain Name", v.content)
    elseif v.target_type == "Dns Computer Name" then
      response.dns_computer_name = v.content
      add_to_output(output_lines, "Dns Computer Name", v.content)
    elseif v.target_type == "Dns Domain Name" then
      response.dns_domain_name = v.content
      add_to_output(output_lines, "Dns Domain Name", v.content)
    elseif v.target_type == "Dns Tree Name" then
      response.dns_tree_name = v.content
      add_to_output(output_lines, "Dns Tree Name", v.content)
    elseif v.target_type == "Timestamp" then
      response.timestamp = v.content
      add_to_output(output_lines, "Timestamp", v.content)
    end
  end
  
  return response, stdnse.format_output(true, output_lines)
end


function get_os(major_version, minor_version, build_number)
  local os_version = "Unknown"
  if major_version == 10 then
    if minor_version == 0 then
      -- Windows 11 versions
      if build_number == 22000 then
        os_version = "Microsoft Windows 11 21H2 (OS build 22000)"
      elseif build_number == 22621 then
        os_version = "Microsoft Windows 11 22H2 (OS build 22621)"
      elseif build_number == 22631 then
        os_version = "Microsoft Windows 11 23H2 (OS build 22631)"
      -- Windows 10 versions
      elseif build_number == 10240 then
        os_version = "Microsoft Windows 10 1507 (OS build 10240)"
      elseif build_number == 10586 then
        os_version = "Microsoft Windows 10 1511 (OS build 10586)"
      elseif build_number == 15063 then
        os_version = "Microsoft Windows 10 1703 (OS build 15063)"
      elseif build_number == 16299 then
        os_version = "Microsoft Windows 10 1709 (OS build 16299)"
      elseif build_number == 17134 then
        os_version = "Microsoft Windows 10 1803 (OS build 17134)"
      elseif build_number == 18362 then
        os_version = "Microsoft Windows 10 1903 (OS build 18362)"
      elseif build_number == 18363 then
        os_version = "Microsoft Windows 10 1909 (OS build 18363)"
      elseif build_number == 19041 then
        os_version = "Microsoft Windows 10 2004 (OS build 19041)"
      elseif build_number == 19042 then
        os_version = "Microsoft Windows 10 20H2 (OS build 19042)"
      elseif build_number == 19043 then
        os_version = "Microsoft Windows 10 21H1 (OS build 19043)"
      elseif build_number == 19044 then
        os_version = "Microsoft Windows 10 21H2 (OS build 19044)"
      elseif build_number == 19045 then
        os_version = "Microsoft Windows 10 22H2 (OS build 19045)"
      -- Windows Server 2022
      elseif build_number == 20348 then
        os_version = "Microsoft Windows Server 2022 (OS build 20348)"
      -- Windows Server 2019
      elseif build_number == 17763 then
        os_version = "Microsoft Windows 10 1809/Microsoft Windows Server 2019 (OS build 17763)"
      elseif build_number == 14393 then
        os_version = "Microsoft Windows 10 1607/Microsoft Windows Server 2016 (OS build 14393)"
      end
    end
  end

  -- Windows 8.1
  if major_version == 6 and minor_version == 3 then
    if build_number == 9600 then
      os_version = "Microsoft Windows 8.1 (Os build 9600)"
    else
      os_version = "Microsoft Windows 8.1"
    end
  end
  
  -- Windows 8
  if major_version == 6 and minor_version == 2 then
    if build_number == 9600 then
      os_version = "Microsoft Windows 8 (Os build 9200)"
    else
      os_version = "Microsoft Windows 8"
    end
  end
  
  -- Windows 7
  if major_version == 6 and minor_version == 1 then
    if build_number == 7601 then
      os_version = "Microsoft Windows 7 (Os build 7601)"
    else
      os_version = "Microsoft Windows 7"
    end
  end
  
  return os_version
end

function add_to_output(output_table, label, value)
  if value then
    table.insert(output_table, string.format("%s: %s", label, value))
  end
end

function make_cpe(os)
  local parts = {}

  if string.match(os, "/Microsoft Windows") then
    parts = {"o", "microsoft", "-"}
  elseif string.match(os, "Windows 7") then
    parts = {"o", "microsoft", "windows_7"}
  elseif string.match(os, "Windows 8%f[^%d.]") then
    parts = {"o", "microsoft", "windows_8"}
  elseif string.match(os, "Windows 8.1") then
    parts = {"o", "microsoft", "windows_8.1"}
  elseif string.match(os, "Windows 10%f[^%d.]") then
    parts = {"o", "microsoft", "windows_10"}
  elseif string.match(os, "Windows 11") then
    parts = {"o", "microsoft", "windows_11"}
  elseif string.match(os, "Windows Server 2016") then
    parts = {"o", "microsoft", "windows_server_2016"}
  elseif string.match(os, "Windows Server 2019") then
    parts = {"o", "microsoft", "windows_server_2019"}
  elseif string.match(os, "Windows Server 2022") then
    parts = {"o", "microsoft", "windows_server_2022"}
  end

  if #parts > 0 then
    return "cpe:/" .. table.concat(parts, ":")
  end
end

-- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e
function parse_data(data)  
  local results = {}
  local i = 1
  while i <= #data do
    local target_type, new_pos = string.unpack("<I2", data, i)
    if target_type == 0 then break end
    i = new_pos

    local target_len, new_pos = string.unpack("<I2", data, i)
    i = new_pos

    local content
    if target_len > 0 then
      content, new_pos = string.unpack("c" .. target_len, data, i)
      i = new_pos
    else
      content = ""
    end

  local function hex2ascii(hexStr)
    local utf16leStr = ""
    for i = 1, #hexStr, 2 do
      local hexCode = string.unpack("<I2", hexStr, i)
      utf16leStr = utf16leStr .. utf8.char(hexCode)
    end
    return utf16leStr
  end
  
  local function hex2int(hexStr)
    local low = string.unpack("<I4", hexStr, 1)
    local high = string.unpack("<I4", hexStr, 5)
    print(low)
    return high * (2^32) + low
  end

  local function filetime2utc(ft)
    local offset = 11644473600 * 1e7
    local utcSeconds = (ft - offset) / 1e7
    utcSeconds = math.floor(utcSeconds)
    return os.date("!%Y-%m-%d %H:%M:%S", utcSeconds)
  end
  
  local tgt_type = ""
  if target_type == 1 then
    tgt_type = "NetBIOS Computer Name"
    content = hex2ascii(content)
  elseif target_type == 2 then
    tgt_type = "NetBIOS Domain Name"
    content = hex2ascii(content)
  elseif target_type == 3 then
    tgt_type = "Dns Computer Name"
    content = hex2ascii(content)
  elseif target_type == 4 then
    tgt_type = "Dns Domain Name"
    content = hex2ascii(content)
  elseif target_type == 5 then
    tgt_type = "Dns Tree Name"
    content = hex2ascii(content)
  elseif target_type == 7 then
    tgt_type = "Timestamp"
    local fileTimeInt = hex2int(content)
    local utcTimeString = filetime2utc(fileTimeInt)
    content = utcTimeString
  elseif target_type == 9 then
    tgt_type = "Target Name"
  else
    goto continue
  end

  table.insert(results, {target_type = tgt_type, content = content})
  ::continue::
  end

  return results
end
