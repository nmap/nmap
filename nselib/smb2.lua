---
-- Implements the Server Message Block (SMB) protocol version 2 and 3.
-- 
-- The implementation extends smb.lua to support SMB dialects 2.02, 2.10, 3.0,
--  3.02 and 3.11. This is a work in progress and not all commands are
--  implemented yet. Features/functionality will be added as the scripts
--  get updated. I tried to be consistent with the current implementation of
--  smb.lua but some fields may have changed name or don't exist anymore.
--
-- TODO:
-- * Add smb2 support for current smb scripts 
-- * MSRPC over SMB2/SMB3
-- * Implement ASYNC SMB header
-- * Implement message signing and encryption
--
-- @author Paulino Calderon <paulino@calderonpale.com>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html  
---

local string = require "string"
local stdnse = require "stdnse"
local netbios = require "netbios"
local nmap = require "nmap"
local table = require "table"
local match = require "match"
local bit = require "bit"
local nsedebug = require "nsedebug"
local math = require "math"
local os = require "os"

_ENV = stdnse.module("smb2", stdnse.seeall)

local TIMEOUT = 10000
local command_names = {}
local command_codes =
{
  SMB2_COM_NEGOTIATE              = 0x0000,
  SMB2_COM_SESSION_SETUP          = 0x0001,
  SMB2_COM_LOGOFF                 = 0x0002,
  SMB2_COM_TREE_CONNECT           = 0x0003,
  SMB2_COM_TREE_DISCONNECT        = 0x0004,
  SMB2_COM_CREATE                 = 0x0005,
  SMB2_COM_CLOSE                  = 0x0006,
  SMB2_COM_FLUSH                  = 0x0007,
  SMB2_COM_READ                   = 0x0008,
  SMB2_COM_WRITE                  = 0x0009,
  SMB2_COM_LOCK                   = 0x000A,
  SMB2_COM_IOCTL                  = 0x000B,
  SMB2_COM_CANCEL                 = 0x000C,
  SMB2_COM_ECHO                   = 0x000D,
  SMB2_COM_QUERY_DIRECTORY        = 0x000E,
  SMB2_COM_CHANGE_NOTIFY          = 0x000F,
  SMB2_COM_QUERY_INFO             = 0x0010,
  SMB2_COM_SET_INFO               = 0x0011,
  SMB2_COM_OPLOCK_BREAK           = 0x0012
}
local smb2_values_codes = {}
local smb2_values = {
  -- Security Mode
  SMB2_NEGOTIATE_SIGNING_ENABLED      = 0x0001,
  SMB2_NEGOTIATE_SIGNING_REQUIRED     = 0x0002,
  -- Capabilities
  SMB2_GLOBAL_CAP_DFS                 = 0x00000001,
  SMB2_GLOBAL_CAP_LEASING             = 0x00000002,
  SMB2_GLOBAL_CAP_LARGE_MTU           = 0x00000004,
  SMB2_GLOBAL_CAP_MULTI_CHANNEL       = 0x00000008,
  SMB2_GLOBAL_CAP_PERSISTENT_HANDLES  = 0x00000010,
  SMB2_GLOBAL_CAP_DIRECTORY_LEASING   = 0x00000020,
  SMB2_GLOBAL_CAP_ENCRYPTION          = 0x00000040,
  -- Context Types
  SMB2_ENCRYPTION_CAPABILITIES        = 0x0002,
  SMB2_PREAUTH_INTEGRITY_CAPABILITIES = 0x0001
}

for i, v in pairs(command_codes) do
  command_names[v] = i
end
for i, v in pairs(smb2_values) do
  smb2_values_codes[v] = i
end

---
-- Creates a SMB2 SYNC header packet.
--
-- SMB2 Packet Header - SYNC: 
-- * https://msdn.microsoft.com/en-us/library/cc246529.aspx
--
-- @param smb The SMB object associated with the connection.
-- @param command The SMB2 command to execute.
-- @param overrides Overrides table.
-- @return header The encoded SMB2 SYNC header.
---
function smb2_encode_header_sync(smb, command, overrides)
  overrides = overrides or {}

  local sig = "\xFESMB" -- SMB2 packet 
  local structureSize = 64 -- SYNC header structure size
  local flags = 0 -- TODO: Set flags that will work for all dialects

  -- Increase the message id
  if smb['MessageId'] then
    smb['MessageId'] = smb['MessageId'] + 1
  end

  -- Header structure
  local header = string.pack("<c4 I2 I2 I4 I2 I2 I4 I4 I8 I4 I4 I8 c16",
    sig,                                -- 4 bytes: ProtocolId
    structureSize,                      -- 2 bytes: StructureSize. Must be 64.
    (overrides['CreditCharge'] or 0),   -- 2 bytes: CreditCharge. 
    (overrides['Status'] or 0),         -- 4 bytes: (ChannelSequence/Reserved)/Status. 
    command,                            -- 2 bytes: Command.
    (overrides['CreditR'] or 0),        -- 2 bytes: CreditRequest/CreditResponse.
    (overrides['Flags'] or flags),      -- 4 bytes: Flags. TODO
    (overrides['NextCommand'] or 0),    -- 4 bytes: NextCommand.
    (overrides['MessageId'] or smb['MessageId'] or 0),  -- 8 bytes: MessageId.
    (overrides['Reserved'] or 0),              -- 4 bytes: Reserved.
    (overrides['TreeId'] or smb['TreeId'] or 0),        -- 4 bytes: TreeId.
    (overrides['SessionId'] or smb['SessionId'] or 0),  -- 8 bytes: SessionId.
    (overrides['Signature'] or '1234567890123456')     -- 16 bytes: Signature.
    )

  return header
end

---
-- Sends a SMB2 packet 
-- @param smb        The SMB object associated with the connection
-- @param header     The header encoded with <code>smb_encode_sync_header</code>.
-- @param data       The data.
-- @param overrides  Overrides table.
-- @return (result, err) If result is false, err is the error message. Otherwise, err is
--        undefined
---
function smb2_send(smb, header, data, overrides)
  overrides = overrides or {}
  local body               = header .. data
  local attempts           = 5
  local status, err

  local out = string.pack(">I<c" .. #body, #body, body)
  repeat
    attempts = attempts - 1
    stdnse.debug3("SMB: Sending SMB packet (len: %d, attempts remaining: %d)", #out, attempts)
    status, err = smb['socket']:send(out)
  until(status or (attempts == 0))

  if(attempts == 0) then
    stdnse.debug1("SMB: Sending packet failed after 5 tries! Giving up.")
  end

  return status, err
end

---
-- Reads the next SMB2 packet from the socket, and parses it into the header and data.
-- Netbios handling based taken from smb.lua.
--
-- @param smb The SMB object associated with the connection
-- @param read_data [optional] Return data section. Set to false if you only need the header. Default: true
-- @return (status, header, data) If status is true, the header,
--         and data are all the raw arrays of bytes.
--         If status is false, header contains an error message and data is undefined.
---
function smb2_read(smb, read_data)
  local status
  local pos, netbios_data, netbios_length, length, header, parameter_length, parameters, data_length, data
  local attempts = 5

  stdnse.debug3("SMB2: Receiving SMB2 packet")

  -- Receive the response -- we make sure to receive at least 4 bytes, the length of the NetBIOS length
  smb['socket']:set_timeout(TIMEOUT)

  -- perform 5 attempt to read the Netbios header
  local netbios
  repeat
    attempts = attempts - 1
    status, netbios_data = smb['socket']:receive_buf(match.numbytes(4), true);

    if ( not(status) and netbios_data == "EOF" ) then
      return false, "SMB2: ERROR: Server disconnected the connection"
    end
  until(status or (attempts == 0))

  -- Make sure the connection is still alive
  if(status ~= true) then
    return false, "SMB2: Failed to receive bytes after 5 attempts: " .. netbios_data
  end

  -- The length of the packet is 4 bytes of big endian (for our purposes).
  -- The NetBIOS header is 24 bits, big endian
  netbios_length, pos   = string.unpack(">I", netbios_data)
  if(netbios_length == nil) then
    return false, "SMB2: ERROR:Server returned less data than it was supposed to"
  end
  -- Make the length 24 bits
  netbios_length = bit.band(netbios_length, 0x00FFFFFF)

  -- The total length is the netbios_length, plus 4 (for the length itself)
  length = netbios_length + 4

  local attempts = 5
  local smb_data
  repeat
    attempts = attempts - 1
    status, smb_data = smb['socket']:receive_buf(match.numbytes(netbios_length), true)
  until(status or (attempts == 0))

  -- Make sure the connection is still alive
  if(status ~= true) then
    return false, "SMB2: Failed to receive bytes after 5 attempts: " .. smb_data
  end

  local result = netbios_data .. smb_data
  if(#result ~= length) then
    stdnse.debug1("SMB2: ERROR: Received wrong number of bytes, there will likely be issues (received %d, expected %d)", #result, length)
    return false, string.format("SMB2: ERROR: Didn't receive the expected number of bytes; received %d, expected %d. This will almost certainly cause some errors.", #result, length)
  end

  -- The header is 64 bytes.
  if (pos + 64 > #result) then
    stdnse.debug2("SMB2: SMB2 packet too small. Size needed to be at least '%d' but we got '%d' bytes", pos+64, #result)
    return false, "SMB2: ERROR: Header packet too small."
  end
  header, pos = string.unpack("<c64", result, pos)
  if(header == nil) then
    return false, "SMB2: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [3]"
  end

  -- Read the data section or skip it if read_data is false.
  if(read_data == nil or read_data == true) then
    data, pos = string.unpack("<c" .. #result - pos + 1, result, pos)
    if(data == nil) then
      return false, "SMB2: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [7]"
    end
  else
    data = nil
  end

  stdnse.debug3("SMB2: smb2_read() received %d bytes", #result)
  return true, header, data
end

---
-- Sends SMB2_COM_NEGOTIATE command for a SMB2/SMB3 connection.
-- This function works for dialects 2.02, 2.10, 3.0, 3.02 and 3.11.
-- 
-- Packet structure: https://msdn.microsoft.com/en-us/library/cc246543.aspx
--
-- @param smb The associated SMB connection object.
-- @param overrides Overrides table.
-- @return (status, dialect) If status is true, the negotiated dialect is returned as the second value.
--                            Otherwise if status is false, the error message is returned.
function negotiate_v2(smb, overrides)
  local header, parameters, data
  local StructureSize = 36 -- Must be set to 36.
  local DialectCount = #overrides['Dialects'] or 1
  -- The client MUST set SecurityMode bit to 0x01 if the SMB2_NEGOTIATE_SIGNING_REQUIRED bit is not set, 
  -- and MUST NOT set this bit if the SMB2_NEGOTIATE_SIGNING_REQUIRED bit is set. 
  -- The server MUST ignore this bit.
  local SecurityMode = overrides["SecurityMode"] or smb2_values['SMB2_NEGOTIATE_SIGNING_ENABLED'] 
  local Capabilities = overrides["Capabilities"] or 0 -- SMB 3.x dialect requires capabilities to be constructed
  local GUID = overrides["GUID"] or "1234567890123456"
  local ClientStartTime = overrides["ClientStartTime"] or 0 -- ClientStartTime only used in dialects > 3.11
  local total_data = 0  -- Data counter
  local padding_data = "" -- Padding string to align contexts
  local context_data -- Holds Context data 
  local is_0311 = false -- Flag for SMB 3.11 
  local status, err

  if not( overrides['Dialects'] ) then -- Set 2.02 as default dialect if user didn't select one
    overrides['Dialects'] = {0x0202}
  end

  header = smb2_encode_header_sync(smb, command_codes['SMB2_COM_NEGOTIATE'], overrides)

  -- We construct the first block that works for dialects 2.02 up to 3.11.
  data = string.pack("<I2 I2 I2 I2 I4 c16", 
    StructureSize,  -- 2 bytes: StructureSize
    DialectCount,   -- 2 bytes: DialectCount
    SecurityMode,   -- 2 bytes: SecurityMode
    0,              -- 2 bytes: Reserved - Must be 0
    Capabilities,   -- 4 bytes: Capabilities - 0 for dialects > 3.x
    GUID            -- 16 bytes: ClientGuid
  )

  -- The next block gets interpreted in different ways depending on the dialect
  if stdnse.contains(overrides['Dialects'], 0x0311) then
    is_0311 = true
  end

  -- If we are dealing with 3.11 we need to set the following fields:
  -- NegotiateContextOffset, NegotiateContextCount, and Reserved2
  if is_0311 then
    total_data = #header + #data + (DialectCount*2)
    while ((total_data)%8 ~= 0) do
        total_data = total_data + 1
        padding_data = padding_data .. string.pack("<c1", 0x0)
    end -- while to create 8 byte aligned padding
    data = data .. string.pack("<I4 I2 I2", 
                    total_data+8,   -- NegotiateContextOffset (4 bytes)
                    0x2,            -- NegotiateContextCount (2 bytes) 
                    0x0             -- Reserved2 (2 bytes)
                   )
  else  -- If it's not 3.11, the bytes are the ClientStartTime (8 bytes)
    data = data .. string.pack("<I8", ClientStartTime) -- If it is not 3.11, we set it to 0
  end -- if is_0311

  -- Now we build the Dialect list, 16 bit integers
  if(overrides['Dialects'] == nil) then  -- If no custom dialect is defined, used the default 2.10
    data = data .. string.pack("<I2", 0x0210)
  else  -- Dialects are set in overrides table
    for _, v in ipairs(overrides['Dialects']) do
      data = data .. string.pack("<I2", v)
    end
  end

  -- If 3.11, we now need to add some padding between the dialects and the NegotiateContextList
  -- I was only able to get this to work using both NegotiateContexts: 
  -- * SMB2_PREAUTH_INTEGRITY_CAPABILITIES
  -- * SMB2_ENCRYPTION_CAPABILITIES
  if is_0311 then
    data = data .. padding_data
    local negotiate_context_list, context_data

    -- We set SMB2_ENCRYPTION_CAPABILITIES first
    context_data = string.pack("<I2 I2 I2",
                    0x2,      -- CipherCount (2 bytes): 2 ciphers available
                    0x0002,   -- Ciphers (2 bytes each): AES-128-GCM
                    0x0001    -- Ciphers (2 bytes each): AES-128-CCM
                  )
    data = data .. string.pack("<I2 I2 I4 c" .. #context_data, 
                    smb2_values['SMB2_ENCRYPTION_CAPABILITIES'],-- ContextType (2 bytes)
                    #context_data,                              -- DataLength (2 bytes)
                    0x0,                                        -- Reserved (4 bytes)
                    context_data                                -- Data (SMB2_ENCRYPTION_CAPABILITIES)
                  )

    -- We now add SMB2_PREAUTH_INTEGRITY_CAPABILITIES
    -- We add the padding between contexts so they are 8 byte aligned
    total_data = #header+#data
    padding_data = ""
    while((total_data)%8 ~= 0) do
      padding_data = padding_data .. string.pack("<c1", 0x0)
      total_data = total_data + 1
    end
    data = data .. padding_data
    context_data = context_data .. string.pack("<I2 I2 I2 I16 I16",
                                    0x1,  -- HashAlgorithmCount (2 bytes)
                                    0x20, -- SaltLength (2 bytes)
                                    0x0001,  -- HashAlgorithms (2 bytes each): SHA-512
                                    0x0,      -- Salt
                                    0x1       -- Salt
    )
    data = data .. string.pack("<I2 I2 I4 c" .. #context_data,
                    smb2_values['SMB2_PREAUTH_INTEGRITY_CAPABILITIES'], -- ContextType (2 bytes)
                    #context_data,                                      -- DataLength (2 bytes)
                    0x0,                                                -- Reserved (4 bytes)
                    context_data                                        -- Data (variable)
    )
     
  end
  
  status, err = smb2_send(smb, header, data)
  if not status then
    return false, err
  end
  status, header, data = smb2_read(smb)

  local protocol_version, structure_size, credit_charge, status = string.unpack("<c4 I2 I2 I4", header)
  -- Get the protocol version
  if(protocol_version ~= ("\xFESMB") or structure_size ~= 64) then
    return false, "SMB: Server returned an invalid SMBv2 packet"
  end
  stdnse.debug2("SMB2_COM_NEGOTIATE returned status '%s'", status)

  if status ~= 0 then
    stdnse.debug2("SMB2_COM_NEGOTIATE command failed: Dialect not supported.")
    return false, "SMB2: Dialect is not supported. Exiting."
  end

  local data_structure_size, security_mode, negotiate_context_count
  data_structure_size, smb['security_mode'], smb['dialect'], 
    negotiate_context_count, smb['server_guid'], smb['capabilities'],
    smb['max_trans'], smb['max_read'], smb['max_write'], smb['time'], 
    smb['start_time'] = string.unpack("<I2 I2 I2 I2 c16 I4 I4 I4 I4 I8 I8", data)

  if(smb['dialect'] == nil or smb['capabilities'] == nil or smb['server_guid'] == nil or smb['security_mode'] == nil) then
    return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing)"
  end

  if(data_structure_size ~= 65) then
    return false, string.format("Server returned an unknown structure size in SMB2 NEGOTIATE response")
  end
  -- To be consistent with our current SMBv1 implementation, let's set this values if not present
  if(smb['time'] == nil) then
    smb['time'] = 0
  end
 
  if(smb['timezone'] == nil) then
    smb['timezone'] = 0
  end

  -- Convert the time and timezone to human readable values (taken from smb.lua)
  smb['time'] = (smb['time'] // 10000000) - 11644473600
  smb['date'] = os.date("%Y-%m-%d %H:%M:%S", smb['time'])
  smb['start_time'] = (smb['start_time'] // 10000000) - 11644473600
  smb['start_date'] = os.date("%Y-%m-%d %H:%M:%S", smb['start_time'])

  if status == 0 then
    return true, overrides['Dialects']
  else
    return false, string.format("Status error code:%s",status)
  end
end

function start_session(smb, log_errors, overrides)
  local header, data
    -- Make sure we have overrides
  overrides = overrides or {}
  local StructureSize = 25
  local Flags = 0x00
  local SecurityMode = 0x01
  local Capabilities = overrides["Capabilities"] or 0
  local Channel = 0
  local SecurityBufferOffset = 0x58
  local PreviousSessionId = 0

  -- Set a default status_name, in case everything fails
  local status_name = "An unknown error has occurred"

  local username, domain, password, password_hash, hash_type
  local result
  -- Get the first account, unless they overrode it
  if(overrides ~= nil and overrides['username'] ~= nil) then
    result = true
    username      = overrides['username']
    domain        = overrides['domain']
    password      = overrides['password']
    password_hash = overrides['password_hash']
    hash_type     = overrides['hash_type']
  else
    result, username, domain, password, password_hash, hash_type = smbauth.get_account(smb['host'])
    stdnse.debug1("password_hash: %s; hash_type: %s", password_hash, hash_type)
    if(not(result)) then
      return result, username
    end
  end

  -- check what kind of security blob we were given in the negotiate protocol request
  local sp_nego = false
  if ( smb['SecurityBlob'] and #smb['SecurityBlob'] > 11 ) then
    local pos, oid = bin.unpack(">A6", smb['SecurityBlob'], 5)
    sp_nego = ( oid == "\x2b\x06\x01\x05\x05\x02" ) -- check for SPNEGO OID 1.3.6.1.5.5.2
  end

  while result ~= false do
    -- These are loop variables
    local security_blob = nil
    local security_blob_length = 0

    repeat
      -- Get the new security blob, passing the old security blob as a parameter. If there was no previous security blob, then nil is passed, which creates a new one
      if ( not(security_blob) ) then
        status, security_blob, smb['mac_key'] = smbauth.get_security_blob(security_blob, smb['ip'], username, domain, password, password_hash, hash_type, (sp_nego and 0x00088215))
        if ( sp_nego ) then
          local enc = asn1.ASN1Encoder:new()
          local mechtype = enc:encode( { type = 'A0', value = enc:encode( { type = '30', value = enc:encode( { type = '06', value = bin.pack("H", "2b06010401823702020a") } ) } ) } )
          local oid = enc:encode( { type = '06', value = bin.pack("H", "2b0601050502") } )

          security_blob = enc:encode(security_blob)
          security_blob = enc:encode( { type = 'A2', value = security_blob } )
          security_blob = mechtype .. security_blob
          security_blob = enc:encode( { type = '30', value = security_blob } )
          security_blob = enc:encode( { type = 'A0', value = security_blob } )
          security_blob = oid .. security_blob
          security_blob = enc:encode( { type = '60', value = security_blob } )
        end
      else
        if ( sp_nego ) then
          if ( smb['domain'] or smb['server'] and ( not(domain) or #domain == 0 ) ) then
            domain = smb['domain'] or smb['server']
          end
          hash_type = "ntlm"
        end
        status, security_blob, smb['mac_key'] = smbauth.get_security_blob(security_blob, smb['ip'], username, domain, password, password_hash, hash_type, (sp_nego and 0x00088215))
        if ( sp_nego ) then
          local enc = asn1.ASN1Encoder:new()
          security_blob = enc:encode(security_blob)
          security_blob = enc:encode( { type = 'A2', value = security_blob } )
          security_blob = enc:encode( { type = '30', value = security_blob } )
          security_blob = enc:encode( { type = 'A1', value = security_blob } )
        end
      end

      -- There was an error processing the security blob
      if(status == false) then
        return false, string.format("SMB: ERROR: Security blob: %s", security_blob)
      end

      local data = bin.pack("<SCCIISSL", 
                            StructureSize,  --2 bytes
                            Flags,   --1 bytes
                            SecurityMode,   --1 bytes
                            Capabilities,       --4 bytes
                            Channel,   --4 bytes
                            SecurityBufferOffset,          --2 bytes
                            #security_blob,          --2 bytes
                            PreviousSessionId  --8 bytes
                            )

      header     = smb_encode_header_sync(smb, command_codes['SMB2_COM_SESSION_SETUP'], overrides)

      -- Data is a list of strings, terminated by a blank one.
      data = data .. bin.pack("<A",
        security_blob         -- Security blob
        )
      -- Send the session setup request
      stdnse.debug2("SMB: Sending SMB2_COM_SESSION_SETUP")
      result, err = smb2_send(smb, header, data, overrides)
      if(result == false) then
        return false, err
      end

      -- Read the result
      status, header, data = smb2_read(smb)
      if(status ~= true) then
        return false, header
      end

      -- Parse out the header
      pos, header1, header2, header3, header4, h_StructureSize, CreditCharge, Status, Command, CreditR, h_Flags, NextCommand, MessageId, Reserved, TreeId, smb['SessionId'], Signature1, Signature2 = bin.unpack("<CCCCSSISSIILIILLL", header)
      if(header1 == nil) then
        return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [17]"
      end

      -- Get a human readable name
      status_name = get_status_name(Status)

      -- Only parse the parameters if it's ok or if we're going to keep going
      if(status_name == "NT_STATUS_SUCCESS" or status_name == "NT_STATUS_MORE_PROCESSING_REQUIRED") then
        -- Parse the parameters
        local s_StructureSize, s_SessionFlags, s_SecurityBufferOffset, s_SecurityBufferLength
        pos, s_StructureSize, s_SessionFlags, s_SecurityBufferOffset, s_SecurityBufferLength = bin.unpack("<SSSS", data)
        if(s_SecurityBufferLength == nil) then
          return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [18]"
        end
        smb['is_guest']   = bit.band(s_SessionFlags, 1)

        -- Parse the data
        pos, security_blob = bin.unpack(string.format("<A%d", s_SecurityBufferLength), data, pos)

        if ( status_name == "NT_STATUS_MORE_PROCESSING_REQUIRED" and sp_nego ) then
          local start = security_blob:find("NTLMSSP")
          security_blob = security_blob:sub(start)
        end

        if(security_blob == nil) then
          return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [19]"
        end
        if(status_name == "NT_STATUS_MORE_PROCESSING_REQUIRED") then
          local host_info = smbauth.get_host_info_from_security_blob(security_blob)
          if ( host_info ) then
            smb['fqdn'] = host_info['fqdn']
            smb['domain_dns'] = host_info['dns_domain_name']
            smb['forest_dns'] = host_info['dns_forest_name']
            smb['server'] = host_info['netbios_computer_name']
            smb['domain'] = host_info['netbios_domain_name']
          end
        end

        -- If it's ok, do a cleanup and return true
        if(status_name == "NT_STATUS_SUCCESS") then
          -- Check if they were logged in as a guest
          if(log_errors == nil or log_errors == true) then
            if(smb['is_guest'] == 1) then
              stdnse.debug1("SMB: Extended login to %s as %s\\%s failed, but was given guest access (username may be wrong, or system may only allow guest)", smb['ip'], domain, stdnse.string_or_blank(username))
            else
              stdnse.debug2("SMB: Extended login to %s as %s\\%s succeeded", smb['ip'], domain, stdnse.string_or_blank(username))
            end
          end

          -- Set the initial sequence number
          smb['sequence'] = 1

          return true
        end -- Status is ok
      end -- Should we parse the parameters/data?
    until status_name ~= "NT_STATUS_MORE_PROCESSING_REQUIRED"

    -- Check if we got the error NT_STATUS_REQUEST_NOT_ACCEPTED
    if(status == 0xc00000d0) then
      busy_count = busy_count + 1

      if(busy_count > 9) then
        return false, "SMB: ERROR: Server has too many active connections; giving up."
      end

      local backoff = math.random() * 10
      stdnse.debug1("SMB: Server has too many active connections; pausing for %s seconds.", math.floor(backoff * 100) / 100)
      stdnse.sleep(backoff)
    else
      -- Display a message to the user, and try the next account
      if(log_errors == nil or log_errors == true) then
        stdnse.debug1("SMB: Extended login to %s as %s\\%s failed (%s)", smb['ip'], domain, stdnse.string_or_blank(username), status_name)
      end

      --Go to the next account
      if(overrides == nil or overrides['username'] == nil) then
        smbauth.next_account(smb['host'])
        result, username, domain, password, password_hash, hash_type = smbauth.get_account(smb['host'])
        if(not(result)) then
          return false, username
        end
      else
        result = false
      end
      result = false
    end

  end -- Loop over the accounts

  if(log_errors == nil or log_errors == true) then
    stdnse.debug1("SMB: ERROR: All logins failed, sorry it didn't work out!")
  end

  return false, status_name
end

return _ENV;
