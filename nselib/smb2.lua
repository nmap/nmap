---
-- Implements the SMB2/SMB3 protocol.
-- 
-- This is a work in progress and features/functionality will be added as needed by the scripts.
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

for i, v in pairs(command_codes) do
  command_names[v] = i
end


---
-- Creates a SMB2 SYNC header packet.
-- SMB2 Packet Header - SYNC: https://msdn.microsoft.com/en-us/library/cc246529.aspx
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
-- Netbios handling based on smb.lua
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
  stdnse.debug3("Pos:%s Netbios length:%s", pos, netbios_length)
  if(netbios_length == nil) then
    return false, "SMB2: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [2]"
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
-- Sends SMB2_COM_NEGOTIATE command for SMB2/SMB3 dialects
-- This function works for dialects 2.0, 2.1, 3.0.
--
-- @param smb The associated SMB connection object.
-- @param overrides Overrides table.
-- @return (status, dialect) If status is true, the negotiated dialect is returned as the second value.
--                            Otherwise if status is false, the error message is returned.
function negotiate_v2(smb, overrides)
  local header, parameters, data
  local StructureSize = 36
  local DialectCount = #overrides['Dialects']
  -- The client MUST set SecurityMode bit to 0x01 if the SMB2_NEGOTIATE_SIGNING_REQUIRED bit is not set, 
  -- and MUST NOT set this bit if the SMB2_NEGOTIATE_SIGNING_REQUIRED bit is set. 
  -- The server MUST ignore this bit.
  local SecurityMode = overrides["SecurityMode"] or 0x01
  local Capabilities = overrides["Capabilities"] or 0
  local GUID1 = overrides["GUID1"] or 1
  local GUID2 = overrides["GUID2"] or 1
  local ClientStartTime = overrides["ClientStartTime"] or 0x0
  local total_data = 0
  local padding_data = "" -- Data counter and padding string to align contexts
  local context_data -- Holds Context data 
  local is_0311 = false -- Flag for SMB 3.11 

  header = smb2_encode_header_sync(smb, command_codes['SMB2_COM_NEGOTIATE'], overrides)
   
  data = string.pack("<I2 I2 I2 I2 I4 I8 I8", 
    StructureSize,  --2 bytes
    DialectCount,   --2 bytes
    SecurityMode,   --2 bytes
    0,       -- Reserved (2 bytes)
    Capabilities,   --4 bytes
    GUID1,          --8 bytes
    GUID2          --8 bytes
    )

  for _, dialect in ipairs(overrides['Dialects']) do
    if dialect == 0x0311 then
      is_0311 = true
    end
  end

  if is_0311 then
    total_data = #header + #data + (DialectCount*2)
    while ((total_data)%8 ~= 0) do
        total_data = total_data + 1
        padding_data = padding_data .. string.pack("<c1", 0x0)
    end -- while to create 8 byte aligned padding
    data = data .. string.pack("<I4 I2 I2", total_data+8, 0x2, 0x0)
  else
    data = data .. string.pack("<I8", ClientStartTime) -- If it is not 3.11, we set it to 0
  end -- if is_0311

  if(overrides['Dialects'] == nil) then
    for _, d in ipairs(smb2_dialect) do
      data = data .. string.pack("<I2", d)
    end
  else
    for _, v in ipairs(overrides['Dialects']) do
      data = data .. string.pack("<I2", v)
    end
  end

  if is_0311 then
    data = data .. padding_data
    local negotiate_context_list, context_data
    context_data = string.pack("<I2 I2 I2", 0x2, 0x2, 0x0001)
    data = data .. string.pack("<I2 I2 I4 c" .. #context_data, 0x0002, #context_data, 0x0, context_data)

    -- We add the padding between contexts so they are 8 byte aligned
    total_data = #header+#data
    padding_data = ""
    while((total_data)%8 ~= 0) do
      padding_data = padding_data .. string.pack("<c1", 0x0)
      total_data = total_data + 1
    end
    data = data .. padding_data
    context_data = context_data .. string.pack("<I2 I2 I2 I16 I16", 0x1, 0x20, 0x0001, 0x0, 0x1)
    data = data .. string.pack("<I2 I2 I4 c" .. #context_data, 0x0001, #context_data, 0x0, context_data)
     
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
  stdnse.debug1("Status '%s'", status)

  local data_structure_size, security_mode
  data_structure_size, security_mode, smb['dialect'] = string.unpack("<I2 I2 I2", data)
  if(smb['dialect'] == nil) then
    return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [9]"
  end

  if(data_structure_size ~= 65) then
    return false, string.format("Server returned an unknown structure size in SMB2 NEGOTIATE response")
  end

  stdnse.debug2("Dialect accepted by server: %s", smb['dialect'])
  -- To be consistent with our current SMBv1 implementation, let's set this values if not present
  if(smb['time'] == nil) then
    smb['time'] = 0
  end
  if(smb['timezone'] == nil) then
    smb['timezone'] = 0
  end
  if(smb['key_length'] == nil) then


    smb['key_length'] = 0
  end
  if(smb['byte_count'] == nil) then
    smb['byte_count'] = 0
  end

  -- Convert the time and timezone to more useful values
  smb['time'] = (smb['time'] // 10000000) - 11644473600
  smb['date'] = os.date("%Y-%m-%d %H:%M:%S", smb['time'])
  smb['timezone'] = -(smb['timezone'] / 60)
  if(smb['timezone'] == 0) then
    smb['timezone_str'] = "UTC+0"
  elseif(smb['timezone'] < 0) then
    smb['timezone_str'] = "UTC-" .. math.abs(smb['timezone'])
  else
    smb['timezone_str'] = "UTC+" .. smb['timezone']
  end

  -- Let's parse the SMB data section

  if status == 0 then
    return true, overrides['Dialects']
  else
    return false, string.format("Status error code:%s",status)
  end
end

return _ENV;
