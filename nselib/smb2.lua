---
-- Implements the Server Message Block (SMB) protocol version 2 and 3.
--
-- The implementation extends smb.lua to support SMB dialects 2.0.2, 2.1, 3.0,
--  3.0.2 and 3.1.1. This is a work in progress and not all commands are
--  implemented yet. Features/functionality will be added as the scripts
--  get updated. I tried to be consistent with the current implementation of
--  smb.lua but some fields may have changed name or don't exist anymore.
--
-- @author Paulino Calderon <paulino@calderonpale.com>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
---

local datetime = require "datetime"
local string = require "string"
local stdnse = require "stdnse"
local table = require "table"
local tableaux = require "tableaux"
local match = require "match"

_ENV = stdnse.module("smb2", stdnse.seeall)

local TIMEOUT = 10000
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
local command_names = tableaux.invert(command_codes)
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
local smb2_values_codes = tableaux.invert(smb2_values)

local smb2_dialects = {0x0202, 0x0210, 0x0300, 0x0302, 0x0311}
local smb2_dialect_names = {}
for _, d in ipairs(smb2_dialects) do
  -- convert 0x0abc to "a.b.c"
  local name = stdnse.tohex(d, {separator = ".", group = 1})
  -- trim trailing ".0" at sub-minor level
  smb2_dialect_names[d] = name:find(".0", 4, true) and name:sub(1, 3) or name
end

---
-- Returns the list of supported SMB 2 dialects
-- https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fac3655a-7eb5-4337-b0ab-244bbcd014e8
-- @return list of 16-bit numerical revision codes (0x202, 0x210, ...)
---
function dialects ()
  return tableaux.tcopy(smb2_dialects)
end

---
-- Converts a supported SMB 2 dialect code to dialect name
-- https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fac3655a-7eb5-4337-b0ab-244bbcd014e8
-- @param dialect SMB 2 dialect revision code
-- @return string representing the dialect (or nil). Example: 0x202 -> "2.0.2"
---
function dialect_name (dialect)
  return smb2_dialect_names[dialect]
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
-- @return Boolean Status.
-- @return An error message if status is false.
---
function smb2_send(smb, header, data, overrides)
  overrides = overrides or {}
  local body               = header .. data
  local attempts           = 5
  local status, err

  local out = string.pack(">s4", body)
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
  stdnse.debug3("SMB2: Receiving SMB2 packet")

  -- Receive the response -- we make sure to receive at least 4 bytes, the length of the NetBIOS length
  smb['socket']:set_timeout(TIMEOUT)

  -- attempt to read the Netbios header
  local status, netbios_data = smb['socket']:receive_buf(match.numbytes(4), true);

  -- Make sure the connection is still alive
  if not status then
    return false, "SMB2: Failed to receive bytes: " .. netbios_data
  end

  -- The length of the packet is 4 bytes of big endian (for our purposes).
  -- The NetBIOS header is 24 bits, big endian
  local netbios_length, pos = string.unpack(">I4", netbios_data)
  -- Make the length 24 bits
  netbios_length = netbios_length & 0x00FFFFFF

  -- The total length is the netbios_length, plus 4 (for the length itself)
  local length = netbios_length + 4

  local status, smb_data = smb['socket']:receive_buf(match.numbytes(netbios_length), true)

  -- Make sure the connection is still alive
  if not status then
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
  local header, pos = string.unpack("<c64", result, pos)

  -- Read the data section or skip it if read_data is false.
  local data
  if(read_data == nil or read_data == true) then
    data = result:sub(pos)
  end

  stdnse.debug3("SMB2: smb2_read() received %d bytes", #result)
  return true, header, data
end

---
-- Sends SMB2_COM_NEGOTIATE command for a SMB2/SMB3 connection.
-- All supported dialects are offered. Use table overrides['Dialects']
-- to exclude some dialects or to force a specific dialect.
-- Use function smb2.dialects to obtain the list of supported dialects.
-- Use function smb2.dialect_name to check whether a given dialect is supported.
--
-- Packet structure:
-- https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5
--
-- @param smb The associated SMB connection object.
-- @param overrides Overrides table.
-- @return (status, dialect) If status is true, the negotiated dialect is returned as the second value.
--                            Otherwise if status is false, the error message is returned.
-- @see dialects
-- @see dialect_name
function negotiate_v2(smb, overrides)
  overrides = overrides or {}
  local StructureSize = 36 -- Must be set to 36.
  local Dialects = overrides['Dialects'] or smb2_dialects
  local DialectCount = #Dialects
  -- The client MUST set SecurityMode bit to 0x01 if the SMB2_NEGOTIATE_SIGNING_REQUIRED bit is not set,
  -- and MUST NOT set this bit if the SMB2_NEGOTIATE_SIGNING_REQUIRED bit is set.
  -- The server MUST ignore this bit.
  local SecurityMode = overrides["SecurityMode"] or smb2_values['SMB2_NEGOTIATE_SIGNING_ENABLED']
  local Capabilities = overrides["Capabilities"] or 0 -- SMB 3.x dialect requires capabilities to be constructed
  local GUID = overrides["GUID"] or "1234567890123456"
  local ClientStartTime = overrides["ClientStartTime"] or 0 -- ClientStartTime only used in dialects < 3.1.1
  local total_data = 0  -- Data counter
  local padding_data = "" -- Padding string to align contexts
  local context_data -- Holds Context data
  local is_0311 = tableaux.contains(Dialects, 0x0311) -- Flag for SMB 3.1.1
  local status, err

  local header = smb2_encode_header_sync(smb, command_codes['SMB2_COM_NEGOTIATE'], overrides)

  -- We construct the first block that works for dialects 2.0.2 up to 3.1.1.
  local data = string.pack("<I2 I2 I2 I2 I4 c16",
    StructureSize,  -- 2 bytes: StructureSize
    DialectCount,   -- 2 bytes: DialectCount
    SecurityMode,   -- 2 bytes: SecurityMode
    0,              -- 2 bytes: Reserved - Must be 0
    Capabilities,   -- 4 bytes: Capabilities - 0 for dialects > 3.x
    GUID            -- 16 bytes: ClientGuid
  )

  -- The next block gets interpreted in different ways depending on the dialect
  -- If we are dealing with 3.1.1 we need to set the following fields:
  -- NegotiateContextOffset, NegotiateContextCount, and Reserved2
  if is_0311 then
    total_data = #header + #data + (DialectCount*2)
    padding_data = string.rep("\0", (8 - total_data % 8) % 8)
    total_data = total_data + #padding_data
    data = data .. string.pack("<I4 I2 I2",
                    total_data+8,   -- NegotiateContextOffset (4 bytes)
                    0x2,            -- NegotiateContextCount (2 bytes)
                    0x0             -- Reserved2 (2 bytes)
                   )
  else  -- If it's not 3.1.1, the bytes are the ClientStartTime (8 bytes)
    data = data .. string.pack("<I8", ClientStartTime)
  end -- if is_0311

  -- Now we build the Dialect list, 16 bit integers
  for _, v in ipairs(Dialects) do
    data = data .. string.pack("<I2", v)
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
    data = data .. string.pack("<I2 I2 I4",
                    smb2_values['SMB2_ENCRYPTION_CAPABILITIES'],-- ContextType (2 bytes)
                    #context_data,                              -- DataLength (2 bytes)
                    0x0                                         -- Reserved (4 bytes)
                  ) .. context_data                             -- Data (SMB2_ENCRYPTION_CAPABILITIES)

    -- We now add SMB2_PREAUTH_INTEGRITY_CAPABILITIES
    -- We add the padding between contexts so they are 8 byte aligned
    total_data = #header + #data
    padding_data = string.rep("\0", (8 - total_data % 8) % 8)
    data = data .. padding_data
    context_data = context_data .. string.pack("<I2 I2 I2 I16 I16",
                                    0x1,  -- HashAlgorithmCount (2 bytes)
                                    0x20, -- SaltLength (2 bytes)
                                    0x0001,  -- HashAlgorithms (2 bytes each): SHA-512
                                    0x0,      -- Salt
                                    0x1       -- Salt
    )
    data = data .. string.pack("<I2 I2 I4",
                    smb2_values['SMB2_PREAUTH_INTEGRITY_CAPABILITIES'], -- ContextType (2 bytes)
                    #context_data,                                      -- DataLength (2 bytes)
                    0x0                                                -- Reserved (4 bytes)
    ) .. context_data

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

  local parameters_format = "<I2 I2 I2 I2 c16 I4 I4 I4 I4 I8 I8"
  if #data < string.packsize(parameters_format) then
    -- smb.lua can tolerate missing time/timezone, but it's less likely any
    -- SMB2 implementations will not have them. If this becomes a problem, we
    -- can shorten this unpack format like in smb.negotiate_v1
    return false, "SMB2: ERROR: Server returned less data than it was supposed to (one or more fields are missing)"
  end

  local data_structure_size, security_mode, negotiate_context_count
  data_structure_size, smb['security_mode'], smb['dialect'],
    negotiate_context_count, smb['server_guid'], smb['capabilities'],
    smb['max_trans'], smb['max_read'], smb['max_write'], smb['time'],
    smb['start_time'] = string.unpack(parameters_format, data)

  if(data_structure_size ~= 65) then
    return false, string.format("Server returned an unknown structure size in SMB2 NEGOTIATE response")
  end

  -- Convert the time and timezone to human readable values (taken from smb.lua)
  smb['time'] = (smb['time'] // 10000000) - 11644473600
  smb['date'] = datetime.format_timestamp(smb['time'])

  -- Samba does not report the boot time
  if smb['start_time'] ~= 0 then
    smb['start_time'] = (smb['start_time'] // 10000000) - 11644473600
    smb['start_date'] = datetime.format_timestamp(smb['start_time'])
  else
    smb['start_date'] = "N/A"
  end

  local security_buffer_offset, security_buffer_length, neg_context_offset
  security_buffer_offset, security_buffer_length, neg_context_offset = string.unpack("<I2 I2 I4", data)
  if status == 0 then
    return true, smb['dialect']
  else
    return false, string.format("Status error code:%s",status)
  end
end

return _ENV;
