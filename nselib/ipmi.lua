---
-- A module implementing IPMI protocol (the code is a porting of the Metasploit ipmi scanner:
-- https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/scanner/ipmi)
--
-- @class module
-- @name ipmi
-- @author "Claudiu Perta <claudiu.perta@gmail.com>"
local stdnse = require "stdnse"
local string = require "string"
local rand = require "rand"

_ENV = stdnse.module("ipmi", stdnse.seeall)

local HAVE_SSL, openssl = pcall(require,"openssl")

PAYLOADS = {
  ["IPMI"] = 0,
  ["PAYLOAD_SOL"]  = 1,
  ["RMCPPLUSOPEN_REQ"] = 0x10,
  ["RMCPPLUSOPEN_REP"] = 0x11,
  ["RAKP1"] = 0x12,
  ["RAKP2"] = 0x13,
  ["RAKP3"] = 0x14,
  ["RAKP4"] = 0x15,
}

RMCP_ERRORS = {
  [1] = "Insufficient resources to create new session \
         (wait for existing sessions to timeout)",

  -- Shouldn't occur.
  [2] = "Invalid Session ID",

  -- Shouldn't occur.
  [3] = "Invalid payload type",

  -- If these happen, we need to enhance our mechanism for detecting
  -- supported auth algorithms.
  [4] = "Invalid authentication algorithm",
  [5] = "Invalid integrity algorithm",

  [6] = "No matching authentication payload",
  [7] = "No matching integrity payload",

  -- This suggests the session was timed out while trying to negotiate,
  -- shouldn't happen.
  [8] = "Inactive Session ID",

  [9] = "Invalid role",
  [0xa] = "Unauthorised role or privilege level requested",
  [0xb] = "Insufficient resources to create a session at the requested role",
  [0xc] = "Invalid username length",
  [0xd] = "Unauthorized name",
  [0xe] = "Unauthorized GUID",
  [0xf] = "Invalid integrity check value",
  [0x10] = "Invalid confidentiality algorithm",
  [0x11] = "No cipher suite match with proposed security algorithms",

  -- Never observed, most likely a bug in xCAT or IPMI device.
  [0x12] = "Illegal or unrecognized parameter",
}

channel_auth_request = function()
  return (
    "\x06\x00\xff\x07" .. -- Header
    "\x00\x00\x00\x00" ..
    "\x00\x00\x00\x00\x00\x09\x20\x18" ..
    "\xc8\x81\x00\x38\x8e\x04\xb5"
    )
end

rmcpplus_header = function (payload_type)
  return (
    "\x06\x00\xff\x07" ..           -- RMCP Header
    "\x06" ..                       -- RMCP+ Authentication Type
    string.char(PAYLOADS[payload_type]) .. -- Payload Type
    "\x00\x00\x00\x00" ..           -- Session ID
    "\x00\x00\x00\x00"            -- Sequence Number
    )
end

-- Open rmcpplus_request
session_open_request = function(console_session_id)
  local data = (
    "\x00\x00" .. -- Maximum Access
    "\x00\x00" .. -- Reserved
    console_session_id ..
    "\x00\x00\x00\x08" ..
    "\x01\x00\x00\x00" ..
    "\x01\x00\x00\x08" ..
    "\x01\x00\x00\x00" .. -- HMAC-SHA1
    "\x02\x00\x00\x08" ..
    "\x01\x00\x00\x00"  -- AES Encryption
    )

  return rmcpplus_header("RMCPPLUSOPEN_REQ") .. string.pack("<s2", data)
end

-- Open rmcpplus_request
session_open_cipher_zero_request = function(console_session_id)
  console_session_id = console_session_id or rand.random_string(4)

  local data = (
    "\x00\x00" .. -- Maximum Access
    "\x00\x00" .. -- Reserved
    console_session_id ..
    "\x00\x00\x00\x08" ..
    "\x00\x00\x00\x00" .. -- Cipher-zero
    "\x01\x00\x00\x08" ..
    "\x00\x00\x00\x00" .. -- Cipher-zero
    "\x02\x00\x00\x08" ..
    "\x00\x00\x00\x00"  -- No Encryption
    )

  return rmcpplus_header("RMCPPLUSOPEN_REQ") .. string.pack("<s2", data)
end

rakp_1_request = function(bmc_session_id, console_random_id, username)
  local data = string.pack(
    "<Bxxx I c16 Bxx s1",
    0,                       -- Message Tag
    bmc_session_id,
    console_random_id,
    0x14,                       -- Privilege level
    username
    )

  return rmcpplus_header("RAKP1") .. string.pack("<s2", data)
end

rakp_hmac_sha1_salt = function(
    console_session_id,
    bmc_session_id,
    console_random_id,
    bmc_random_id,
    bmc_guid,
    authorization_level,
    username)

  local salt = string.pack(
    "c4 I c16c16c16 Bs1",
    console_session_id,
    bmc_session_id,
    console_random_id,
    bmc_random_id,
    bmc_guid,
    authorization_level,
    username
    )

  return salt

end

verify_rakp_hmac_sha1 = function(salt, hash, password)
  if not(HAVE_SSL) then
    return false
  end

  local digest = openssl.hmac('sha1', password, salt)
  return (digest == hash)
end

--[[
Multi-byte fields in RMCP/ASF fields are specified as being transmitted in
'Network Byte Order' - meaning most-significant byte first.
RMCP and ASF-specified fields are therefore transferred most-significant byte
first.
The IPMI convention is to transfer multi-byte numeric fields least-significant
Byte first. Therefore, unless otherwise specified:
Data in the IPMI Session Header and IPMI Message fields are transmitted
least-significant byte first.
--]]

parse_channel_auth_reply = function(reply)
  local data = {}
  local pos = 1
  local value

  data.rmcp_version,
  data.rmcp_padding,
  data.rmcp_sequence,
  value, pos = string.unpack("<BBBB", reply, pos)

  data.rmcp_mtype = ((value & 0x80) ~= 0)
  data.rmcp_class = (value & 0x7F)

  data.session_auth_type,
  data.session_sequence,
  data.session_id,
  data.message_length,
  data.ipmi_tgt_address,
  data.ipmi_tgt_lun,
  data.ipmi_header_checksum,
  data.ipmi_src_address,
  data.ipmi_src_lun,
  data.ipmi_command,
  data.ipmi_completion_code,
  data.ipmi_channel,
  value, pos = string.unpack("<BI4I4BBBBBBBBBB", reply, pos)

  data.ipmi_compat_20 = ((value & 0x80) ~= 0)
  data.ipmi_compat_reserved1 = ((value & 0x40) ~= 0)
  data.ipmi_compat_oem_auth = ((value & 0x20) ~= 0)
  data.ipmi_compat_password = ((value & 0x10) ~= 0)
  data.ipmi_compat_reserved2 = ((value & 0x08) ~= 0)
  data.ipmi_compat_md5 = ((value & 0x04) ~= 0)
  data.ipmi_compat_md2 = ((value & 0x02) ~= 0)
  data.ipmi_compat_none = ((value & 0x01) ~= 0)

  value, pos = string.unpack("B", reply, pos)
  data.ipmi_user_reserved1 = ((value >> 6) & 0x03)
  data.ipmi_user_kg = ((value & 0x20) ~= 0)
  data.ipmi_user_disable_message_auth = ((value & 0x10) ~= 0)
  data.ipmi_user_disable_user_auth = ((value & 0x08) ~= 0)
  data.ipmi_user_non_null = ((value & 0x04) ~= 0)
  data.ipmi_user_null = ((value & 0x02) ~= 0)
  data.ipmi_user_anonymous = ((value & 0x01) ~= 0)

  value, pos = string.unpack("B", reply, pos)
  data.ipmi_conn_reserved1 = ((value >> 2) & 0x3F)
  data.ipmi_conn_20 = ((value & 0x02) ~= 0)
  data.ipmi_conn_15 = ((value & 0x01) ~= 0)

  -- 24 bits OEMID
  data.ipmi_oem_id, pos = string.unpack("<I3", reply, pos)
  data.ipmi_oem_data = reply:sub(pos)

  return data
end

parse_open_session_reply = function(reply)
  local data = {}
  local pos = 1
  local value

  -- 4 bytes Header
  data.rmcp_version,
  data.rmcp_padding,
  data.rmcp_sequence,
  value, pos = string.unpack("BBBB", reply, pos)
  -- bit 1
  data.rmcp_mtype = ((value & 0x80) ~= 0)
  -- bit [2:8]
  data.rmcp_class = (value & 0x7F)

  data.session_auth_type,
  value, pos = string.unpack("BB", reply, pos)
  -- bit 1
  data.session_payload_encrypted = ((value & 0x80) ~= 0)
  -- bit 2
  data.session_payload_authenticated = ((value & 0x40) ~= 0)
  -- bit [3:8]
  data.session_payload_type = (value & 0x3F)

  data.session_id,
  data.session_sequence,
  data.message_length,
  data.ignored1,
  data.error_code,
  data.ignored2,
  data.console_session_id,
  data.bmc_session_id, pos = string.unpack("<I4I4I2BBI2I4I4", reply, pos)

  return data
end

parse_rakp_1_reply = function(reply)
  local data = {}
  local pos = 1
  local value

  -- 4 bytes Header
  data.rmcp_version,
  data.rmcp_padding,
  data.rmcp_sequence,
  value, pos = string.unpack("BBBB", reply, pos)
  -- bit 1
  data.rmcp_mtype = ((value & 0x80) ~= 0)
  -- bit [2:8]
  data.rmcp_class = (value & 0x7F)

  data.session_auth_type,
  value, pos = string.unpack("BB", reply, pos)
  -- bit 1
  data.session_payload_encrypted = ((value & 0x80) ~= 0)
  -- bit 2
  data.session_payload_authenticated = ((value & 0x40) ~= 0)
  -- bit [3:8]
  data.session_payload_type = (value & 0x3F)

  data.session_id,
  data.session_sequence,
  data.message_length,
  data.ignored1,
  data.error_code,
  data.ignored2,
  data.console_session_id,
  data.bmc_random_id,
  data.bmc_guid,
  data.hmac_sha1, pos = string.unpack("<I4I4I2BBI2I4c16c16c20", reply, pos)

  return data
end

return _ENV;
