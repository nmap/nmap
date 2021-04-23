local os = require "os"
local datetime = require "datetime"
local smb = require "smb"
local stdnse = require "stdnse"
local smb2 = require "smb2"
local smb = require "smb"
local rand = require "rand"
local string = require "string"
local smbauth = require "smbauth"

-- History:
--   2020/01/10: POC
--   2020/03/04: pull request
--   2020/03/26: NTLMSSP parsing bug
--   2020/05/25: +Windows10 2004 signature
--   2020/06/28: fix computer name
--   2020/10/31: +Windows 10 20H2

description = [[
Attempts to obtain the operating system version of a Windows SMB2 server.
]]

---
--@usage
-- nmap --script=smb2-version <host>
--
-- @output
-- Host script results:
-- | smb2-version: 
-- |   OS: Windows Server 2016, Version 1607
-- |   Server NetBIOS domain name: TEST
-- |   Server NetBIOS computer name: AD2016
-- |   DNS domain name: test.local
-- |   FQDN: AD2016.test.local
-- |   DNS forest name: test.local
-- |_  Date: 2020-03-04T19:01:44
-----------------------------------------------------------------------

author = "Yann Breut"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "default", "version"}

local SPNEGO_NEG_TOKEN_RESP = 0xa1
local ASN1_SEQUENCE = 0x30
local SMB2_NEGOTIATE_SIGNING_ENABLED = 0x0001
local SMB2_COM_SESSION_SETUP = 0x0001
local SMB_NEGOTIATE_PROTOCOL = 0x0072

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

action = function(host, port)
  local smbstate, status, overrides, message
  local output_lines = {}  
  local output = stdnse.output_table()

  -- Generate a random Client GUID
  function generate_random_ClientGuid()
    local guid = ""
    local charset = "0123456789ABCDEF"
    math.randomseed( os.time() )
    local alea = rand.random_string(32, charset)
    for i=1,#alea,2 do
      local str = string.sub(alea, i, i+1)
      guid = guid .. string.char(tonumber(str, 16))
    end
    return guid
  end

-- format: "version-build" = "operating system"
-- https://www.gaijin.at/en/infos/windows-version-numbers
-- https://docs.microsoft.com/en-us/windows/uwp/whats-new/windows-10-build-19041

  local fingerprint_values =
  {
    ["6.0-6000"] = "Windows Vista",
    ["6.0-6001"] = "Windows Vista, Service Pack 1 or Windows Server 2008",
    ["6.0-6002"] = "Windows Vista, Service Pack 2 or Windows Server 2008, Service Pack 2",
    ["6.0-6003"] = "Windows Server 2008, Service Pack 2, Rollup KB4489887",
    ["6.1-7600"] = "Windows 7 or Windows Server 2008 R2",
    ["6.1-7601"] = "Windows 7, Service Pack 1 or Windows Server 2008 R2, Service Pack 1",
    ["6.1-8400"] = "Windows Home Server 2011",
    ["6.2-9200"] = "Windows 8 or Windows Server 2012",
    ["6.3-9600"] = "Windows 8.1 or Windows Server 2012 R2",
    ["10.0-10240"] = "Windows 10, Version 1507",
    ["10.0-10586"] = "Windows 10, Version 1511",
    ["10.0-14393"] = "Windows 10, Version 1607",
    ["10.0-15063"] = "Windows 10, Version 1703",
    ["10.0-16299"] = "Windows 10, Version 1709",
    ["10.0-17134"] = "Windows 10, Version 1803",
    ["10.0-17763"] = "Windows 10, Version 1809 or Windows Server 2019, Version 1809",
    ["10.0-18362"] = "Windows 10, Version 1903",
    ["10.0-18363"] = "Windows 10, Version 1909",
    ["10.0-14393"] = "Windows Server 2016, Version 1607",
    ["10.0-16299"] = "Windows Server 2016, Version 1709",
    ["10.0-19041"] = "Windows 10, version 2004 or 20H2"
  }
  -- Get the operating system exact version from version and build data
  local function getOS(version, build)
    local bv = string.format("%s-%s", version, build);
    if fingerprint_values[bv] ~= nil then
      return fingerprint_values[bv]
    else
      return nil
    end
  end  

  -- From smb-os-discovery.nse
  local function add_to_output(output_table, label, value)
    if value then
      table.insert(output_table, string.format("%s: %s", label, value))
    end
  end

  -- Generate NTLM NEGOTIATE MESSAGE
  local function smb_generate_ntlm_negotiate_message(overrides)
    overrides = overrides or {}
    local data = string.char(
      0x60, 0x48, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x3e, 0x30, 0x3c, 0xa0, 0x0e,
      0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa2, 0x2a,
      0x04, 0x28, 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x97, 0x82,
      0x08, 0xE2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00
    )
    -- Default signature => Windows 10, Version 1803 NTLMSSP_REVISION_2K3
    data = data .. string.pack("B B >I2 B B B B",
      (overrides['ntlm_ProductMajorVersion'] or 0x0a), -- 1 byte: 10
      (overrides['ntlm_ProductMinorVersion'] or 0x00), -- 1 byte: 0
      (overrides['ntlm_ProductBuild'] or 0xee42),      -- 2 bytes: 17134
      0,                                               -- 1 byte: reserved
      0,                                               -- 1 byte: reserved
      0,                                               -- 1 byte: reserved
      (overrides['ntlm_RevisionCurrent'] or 0x0f)      -- 1 byte: version 15 (NTLMSSP_REVISION_2K3)
    )    
    local length = string.len(data)
    return length, data
  end

  -- SMB Header
  local function smb_generate_header(smb, command, overrides)
    overrides = overrides or {}
    local sig = "\xFFSMB" -- SMB packet
    -- Header structure
    local header = string.pack("<c4 B I4 B I2 I2 I8 I2 I2 I2 I2 I2",
      sig,                                -- 4 bytes: Server Component
      command,                            -- 1 bytes: Command.
      (overrides['NTStatus'] or 0),       -- 4 bytes: Status
      (overrides['Flags'] or 0),          -- 1 byte: Flags
      (overrides['Flags2'] or 0),         -- 2 byte: Flags2   
      (overrides['ProcessIdHigh'] or 0),  -- 2 bytes: Process Id High
      (overrides['Signature'] or 0),      -- 8 bytes: Signature.
      (overrides['Reserved'] or 0),       -- 2 bytes: Reserved.
      (overrides['TreeId'] or 0),         -- 2 bytes: TreeId.
      (overrides['ProcessId'] or 0),      -- 2 bytes: Process Id
      (overrides['UserId'] or 0),         -- 2 bytes: Process Id
      (overrides['MultiplexId'] or 0)     -- 2 bytes: Process Id
    )
    return header
  end
  -- SMB Negotiate Protocol Request
  local function smb_generate_negotiate_protocol_request(smb, command, overrides)
    local header = smb_generate_header(smb, command, overrides)
    local data = string.pack("B", 0)
    local bc = 0
    for _, v in pairs(overrides['StrDialects']) do
      bc = bc + 2 + string.len(v)
    end
    data = data .. string.pack("<I2", bc)
    for _, v in pairs(overrides['StrDialects']) do
      data = data .. string.pack("B", 0x02) .. v .. string.pack("B", 0x00)
    end
    return header, data
  end

  -- SMB2 Session Setup Request
  local function smb2_generate_session_setup_request(smbstate, command, overrides)
    overrides = overrides or {}
    local structureSize = 0x19
    local ntlm_negotiate_message = ""

    local header = smb2.smb2_encode_header_sync(smbstate, command, overrides)
    overrides['SecurityBlobLength'], ntlm_negotiate_message = smb_generate_ntlm_negotiate_message()
    overrides['SecurityBlobOffset'] = 0x58

    local data = string.pack("I2 B B I4 I4 I2 I2 I8",
      structureSize,                               -- 2 bytes: StructureSize
      (overrides['VcNumber'] or 0),                -- 1 byte: Flags
      (overrides['SecurityMode'] or 0),            -- 1 bytes: SecurityMode, default Signing enabled
      (overrides['Capabilities'] or 0),            -- 4 bytes: Capabilities
      (overrides['Channel'] or 0),                 -- 4 bytes: Channel
      (overrides['SecurityBlobOffset'] or 0),      -- 2 bytes: Blob Offset
      (overrides['SecurityBlobLength'] or 0),      -- 2 bytes: Blob Length
      (overrides['PreviousSessionId'] or 0)        -- 8 bytes: Previous Session Id
    )
    data = data .. ntlm_negotiate_message
    return header, data
  end

  -- Parse SMB Response Header
  local function smb2_parse_header(header_data)
    local data = {}
    local pos = 1
    data.sig, pos = string.unpack("<c4", header_data, pos)
    data.structureSize, pos = string.unpack("I2", header_data, pos)
    data.creditCharge, pos = string.unpack("I2", header_data, pos)
    data.status, pos = string.unpack("I4", header_data, pos)
    data.statusCode = data.status & 0xff
    data.command, pos = string.unpack("I2", header_data, pos)
    data.creditGranted, pos = string.unpack("I2", header_data, pos)
    data.flags, pos = string.unpack("I4", header_data, pos)
    data.chainOffset, pos = string.unpack("I4", header_data, pos)
    data.messageId, pos = string.unpack("I8", header_data, pos)
    data.processId, pos = string.unpack("I4", header_data, pos)
    data.treeId, pos = string.unpack("I4", header_data, pos)
    data.sessionId, pos = string.unpack("I8", header_data, pos)
    data.signature, pos = string.unpack("I16", header_data, pos)
    return data
  end

  local function get_asn1_length(pos, smb2_data)
    local length = 0
    local infoType, pos = string.unpack('B', smb2_data, pos)
    if infoType == 0x81 then
      length, pos = string.unpack('B', smb2_data, pos)
    elseif infoType == 0x82 then
      length, pos = string.unpack('>H', smb2_data, pos)
    elseif infoType == 0x83 then
      length, pos = string.unpack('H', smb2_data, pos)
    elseif infoType == 0x84 then
      length, pos = string.unpack('!L', smb2_data, pos)
    else
      length = infoType
    end
    return length, pos
  end
  
  local function get_asn1_data(pos, smb2_data)
    local elemType, pos = string.unpack('B', smb2_data, pos)
    local elemLength, pos = string.unpack('B', smb2_data, pos)
    local elemData = ""
    local fmt = "c" .. elemLength
    elemData, pos = string.unpack(fmt, smb2_data, pos)
    return elemType, elemLength, elemData, pos
  end
  
  -- Parse the security blob response
  local function smb2_parse_security_blob(response, pos, smb2_data)
    local length = 0
    local cpt = 0
    local sectionKey, elemType, elemLength, elemData
  
    sectionKey, pos = string.unpack('B', smb2_data, pos)
    if sectionKey == SPNEGO_NEG_TOKEN_RESP then -- 0xa1
      length, pos = get_asn1_length(pos, smb2_data)
      response.NegociationToken = {}
      sectionKey, pos = string.unpack('B', smb2_data, pos)
      if sectionKey == ASN1_SEQUENCE then -- 0x30
        length, pos = get_asn1_length(pos, smb2_data)
        sectionKey, pos = string.unpack('B', smb2_data, pos)
        if sectionKey == 0xa0 then -- Tag0
          length, pos = get_asn1_length(pos, smb2_data)
          pos = pos + length
          sectionKey, pos = string.unpack('B', smb2_data, pos)
          if sectionKey == 0xa1 then -- Tag1
            length, pos = get_asn1_length(pos, smb2_data)
            elemType, elemLength, elemData, pos = get_asn1_data(pos, smb2_data)
            sectionKey, pos = string.unpack('B', smb2_data, pos)
            if sectionKey == 0xa2 then -- Tag2
              length, pos = get_asn1_length(pos, smb2_data)
              sectionKey, pos = string.unpack('B', smb2_data, pos)
              print(sectionKey)
              if sectionKey == 0x04 then -- Tag3
                length, pos = get_asn1_length(pos, smb2_data)
                local fmt = "c" .. length
                elemData, pos = string.unpack(fmt, smb2_data, pos)
                response.NegociationToken.ntlm_challenge = smbauth.get_host_info_from_security_blob(elemData)
              end
            end
          end
        end
      end
    end
  end
  
  local function smb2_parse_session_setup_response_data(smb2_data)
    local response = {}
    local pos = 1
    response.structureSize, pos = string.unpack("<I2", smb2_data, pos)
    response.sessionFlags, pos = string.unpack("I2", smb2_data, pos)
    response.securityBufferOffset, pos = string.unpack("I2", smb2_data, pos)
    response.securityBufferLength, pos = string.unpack("I2", smb2_data, pos)
    smb2_parse_security_blob(response, pos, smb2_data)
    return response
  end

  overrides = {}
  status, smbstate = smb.start(host)
  overrides['StrDialects'] = {"SMB 2.002", "SMB 2.???"}
  overrides['Dialects'] = {0x0202, 0x0210}
  overrides["GUID"] = generate_random_ClientGuid()
  overrides["ProcessId"] = 0xfeff
  overrides['TreeId'] = 0xffff
  overrides['Flags'] = 0x18
  overrides["Flags2"] = 0xc853

  -- First, we generate a common SMB Negotiate Protocol Request
  -- It will use MessageId = 0
  local header, data = smb_generate_negotiate_protocol_request(smbstate, SMB_NEGOTIATE_PROTOCOL, overrides)
  smb2.smb2_send(smbstate, header, data)
  status, header, data = smb2.smb2_read(smbstate)

  -- In the previous message, the value of MessageId was 0. This value will be automatically incremented to 1 i the smb2.negotiate_v2 function
  overrides['Signature'] = 0x00
  smbstate["MessageId"] = 0
  overrides['Flags'] = 0x00
  overrides['TreeId'] = 0x00
  status, message = smb2.negotiate_v2(smbstate, overrides)

  if status then 
    overrides['CreditCharge'] = 0x01
    overrides['CreditR'] = 0x1f
    overrides["Capabilities"] = 0x01
    overrides["SecurityMode"] = SMB2_NEGOTIATE_SIGNING_ENABLED
    local header, data = smb2_generate_session_setup_request(smbstate,SMB2_COM_SESSION_SETUP, overrides)
    smb2.smb2_send(smbstate, header, data)
    status, header, data = smb2.smb2_read(smbstate)

    if status then
      local smb2_response_header = smb2_parse_header(header)
      if smb2_response_header.statusCode == 22 then -- STATUS_MORE_PROCESSING_REQUIRED
        smb2_response_data = smb2_parse_session_setup_response_data(data)

        local strversion = string.format("%s.%s",
          smb2_response_data.NegociationToken.ntlm_challenge.os_major_version,
          smb2_response_data.NegociationToken.ntlm_challenge.os_minor_version
        )
        local os = getOS(strversion, smb2_response_data.NegociationToken.ntlm_challenge.os_build)
        if os ~= nil then
          add_to_output(output_lines, "OS", os)
          output.os = os
        else
          local version = string.format("%s - %s", strversion, smb2_response_data.NegociationToken.ntlm_challenge.os_build)
          if smb2_response_data.NegociationToken.ntlm_challenge.os_build == 0 then
            version = version .. " (Not a windows!)"
          end
          add_to_output(output_lines, "Version", version)
          output.version = version
        end

        if smb2_response_data.NegociationToken.ntlm_challenge.netbios_domain_name then
            add_to_output(output_lines, "Server NetBIOS domain name", smb2_response_data.NegociationToken.ntlm_challenge.netbios_domain_name)
            output.domain_name = smb2_response_data.NegociationToken.ntlm_challenge.netbios_domain_name
        end
        if smb2_response_data.NegociationToken.ntlm_challenge.netbios_computer_name then
            add_to_output(output_lines, "Server NetBIOS computer name", smb2_response_data.NegociationToken.ntlm_challenge.netbios_computer_name)
            output.computer_name = smb2_response_data.NegociationToken.ntlm_challenge.netbios_computer_name
        end
        if smb2_response_data.NegociationToken.ntlm_challenge.dns_domain_name then
          add_to_output(output_lines, "DNS domain name", smb2_response_data.NegociationToken.ntlm_challenge.dns_domain_name)
          output.dns_domain_name = smb2_response_data.NegociationToken.ntlm_challenge.dns_domain_name
        end
        if smb2_response_data.NegociationToken.ntlm_challenge.fqdn then
          add_to_output(output_lines, "FQDN", smb2_response_data.NegociationToken.ntlm_challenge.fqdn)
          output.fqdn = smb2_response_data.NegociationToken.ntlm_challenge.fqdn
        end
        if smb2_response_data.NegociationToken.ntlm_challenge.dns_forest_name then
          add_to_output(output_lines, "DNS forest name", smb2_response_data.NegociationToken.ntlm_challenge.dns_forest_name)
          output.fqdn = smb2_response_data.NegociationToken.ntlm_challenge.dns_forest_name
        end
        -- From smb2.lua
        local tmp_timestamp = (smb2_response_data.NegociationToken.ntlm_challenge.timestamp // 10000000) - 11644473600
        add_to_output(output_lines, "Date", datetime.format_timestamp(tmp_timestamp))
        output.date = datetime.format_timestamp(tmp_timestamp)
      end 
      return output
      -- return output, stdnse.format_output(true, output_lines)
    end
  end
  stdnse.debug2("Negotiation failed")
  return "Protocol negotiation failed (SMB2)"
end
