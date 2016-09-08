---
-- A module implementing IPMI protocol (the code is a porting of the Metasploit ipmi scanner:
-- https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/scanner/ipmi)
--
-- @class module
-- @name ipmi
-- @author "Claudiu Perta <claudiu.perta@gmail.com>"
local bin = require "bin"
local bit = require "bit"
local math = require "math"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

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

  return bin.pack("<AP", rmcpplus_header("RMCPPLUSOPEN_REQ"), data)
end

-- Open rmcpplus_request
session_open_cipher_zero_request = function(console_session_id)
  console_session_id = console_session_id or stdnse.generate_random_string(4)

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

  return bin.pack("<AP", rmcpplus_header("RMCPPLUSOPEN_REQ"), data)
end

rakp_1_request = function(bmc_session_id, console_random_id, username)
  local data = bin.pack(
    "<AAIAAAp",
    "\x00",                       -- Message Tag
    "\x00\x00\x00",               -- Reserved
    bmc_session_id,
    console_random_id,
    "\x14",                       -- Privilege level
    "\x00\x00",                   -- Reserved
    username
    )

  return bin.pack("<AP", rmcpplus_header("RAKP1"), data)
end

rakp_hmac_sha1_salt = function(
    console_session_id,
    bmc_session_id,
    console_random_id,
    bmc_random_id,
    bmc_guid,
    authorization_level,
    username)

  local salt = bin.pack(
    "AIAAACp",
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

parse_channel_auth_reply = function(reply)
  local data = {}
  local pos = 0
  local value

  pos, data["rmcp_version"] = bin.unpack("<C", reply, pos)
  pos, data["rmcp_padding"] = bin.unpack("<C", reply, pos)
  pos, data["rmcp_sequence"] = bin.unpack("<C", reply, pos)

  pos, value = bin.unpack("C", reply, pos)
  data["rmcp_mtype"] = (bit.band(value, 0x80) ~= 0)
  data["rmcp_class"] = bit.band(value, 0x7F)

  pos, data["session_auth_type"] = bin.unpack("C", reply, pos)
  pos, data["session_sequence"] = bin.unpack("<I", reply, pos)
  pos, data["session_id"] = bin.unpack("<I", reply, pos)
  pos, data["message_length"] = bin.unpack("C", reply, pos)
  pos, data["ipmi_tgt_address"] = bin.unpack("C", reply, pos)
  pos, data["ipmi_tgt_lun"] = bin.unpack("C", reply, pos)
  pos, data["ipmi_header_checksum"] = bin.unpack("C", reply, pos)
  pos, data["ipmi_src_address"] = bin.unpack("C", reply, pos)
  pos, data["ipmi_src_lun"] = bin.unpack("C", reply, pos)
  pos, data["ipmi_command"] = bin.unpack("C", reply, pos)
  pos, data["ipmi_completion_code"] = bin.unpack("C", reply, pos)
  pos, data["ipmi_channel"] = bin.unpack("C", reply, pos)

  pos, value = bin.unpack("C", reply, pos)
  data["ipmi_compat_20"] = (bit.band(value, 0x80) ~= 0)
  data["ipmi_compat_reserved1"] = (bit.band(value, 0x40) ~= 0)
  data["ipmi_compat_oem_auth"] = (bit.band(value, 0x20) ~= 0)
  data["ipmi_compat_password"] = (bit.band(value, 0x10) ~= 0)
  data["ipmi_compat_reserved2"] = (bit.band(value, 0x08) ~= 0)
  data["ipmi_compat_md5"] = (bit.band(value, 0x04) ~= 0)
  data["ipmi_compat_md2"] = (bit.band(value, 0x02) ~= 0)
  data["ipmi_compat_none"] = (bit.band(value, 0x01) ~= 0)

  pos, value = bin.unpack("C", reply, pos)
  data["ipmi_user_reserved1"] = bit.band(bit.rshift(value, 6), 0x03)
  data["ipmi_user_kg"] = (bit.band(value, 0x20) ~= 0)
  data["ipmi_user_disable_message_auth"] = (bit.band(value, 0x10) ~= 0)
  data["ipmi_user_disable_user_auth"] = (bit.band(value, 0x08) ~= 0)
  data["ipmi_user_non_null"] = (bit.band(value, 0x04) ~= 0)
  data["ipmi_user_null"] = (bit.band(value, 0x02) ~= 0)
  data["ipmi_user_anonymous"] = (bit.band(value, 0x01) ~= 0)

  pos, value = bin.unpack("C", reply, pos)
  data["ipmi_conn_reserved1"] = bit.band(bit.rshift(value, 2), 0x3F)
  data["ipmi_conn_20"] = (bit.band(value, 0x02) ~= 0)
  data["ipmi_conn_15"] = (bit.band(value, 0x01) ~= 0)

  -- 24 bits OEMID, unpack an int and shift 1 byte to the right
  pos, value = bin.unpack("<I", reply, pos)
  data["ipmi_oem_id"] = bit.rshift(value, 8)
  -- restore one byte position
  pos = pos - 1
  pos, data["ipmi_oem_data"] = bin.unpack("A", reply, pos)

  return data
end

parse_open_session_reply = function(reply)
  local data = {}
  local pos = 0
  local value

  -- 4 bytes Header
  pos, data["rmcp_version"] = bin.unpack("C", reply, pos)
  pos, data["rmcp_padding"] = bin.unpack("C", reply, pos)
  pos, data["rmcp_sequence"] = bin.unpack("C", reply, pos)

  pos, value = bin.unpack("C", reply, pos)
  -- bit 1
  data["rmcp_mtype"] = (bit.band(value, 0x80) ~= 0)
  -- bit [2:8]
  data["rmcp_class"] = bit.band(value, 0x7F)

  pos, data["session_auth_type"] = bin.unpack("C", reply, pos)

  pos, value = bin.unpack("C", reply, pos)
  -- bit 1
  data["session_payload_encrypted"] = (bit.band(value, 0x80) ~= 0)
  -- bit 2
  data["session_payload_authenticated"] = (bit.band(value, 0x40) ~= 0)
  -- bit [3:8]
  data["session_payload_type"] = bit.band(value, 0x3F)

  pos, data["session_id"] = bin.unpack("I", reply, pos)
  pos, data["session_sequence"] = bin.unpack("I", reply, pos)
  pos, data["message_length"] = bin.unpack("<S", reply, pos)
  pos, data["ignored1"] = bin.unpack("C", reply, pos)
  pos, data["error_code"] = bin.unpack("C", reply, pos)
  pos, data["ignored2"] = bin.unpack("<S", reply, pos)
  pos, data["console_session_id"] = bin.unpack("I", reply, pos)
  pos, data["bmc_session_id"] = bin.unpack("I", reply, pos)

  return data
end

parse_rakp_1_reply = function(reply)
  local data = {}
  local pos = 0
  local value

  -- 4 bytes Header
  pos, data["rmcp_version"] = bin.unpack("C", reply, pos)
  pos, data["rmcp_padding"] = bin.unpack("C", reply, pos)
  pos, data["rmcp_sequence"] = bin.unpack("C", reply, pos)

  pos, value = bin.unpack("C", reply, pos)
  -- bit 1
  data["rmcp_mtype"] = (bit.band(value, 0x80) ~= 0)
  -- bit [2:8]
  data["rmcp_class"] = bit.band(value, 0x7F)

  pos, data["session_auth_type"] = bin.unpack("C", reply, pos)

  pos, value = bin.unpack("C", reply, pos)
  -- bit 1
  data["session_payload_encrypted"] = (bit.band(value, 0x80) ~= 0)
  -- bit 2
  data["session_payload_authenticated"] = (bit.band(value, 0x40) ~= 0)
  -- bit [3:8]
  data["session_payload_type"] = bit.band(value, 0x3F)

  pos, data["session_id"] = bin.unpack("<I", reply, pos)
  pos, data["session_sequence"] = bin.unpack("<I", reply, pos)
  pos, data["message_length"] = bin.unpack("<S", reply, pos)
  pos, data["ignored1"] = bin.unpack("C", reply, pos)
  pos, data["error_code"] = bin.unpack("C", reply, pos)
  pos, data["ignored2"] = bin.unpack("<S", reply, pos)
  pos, data["console_session_id"] = bin.unpack("<I", reply, pos)
  pos, data["bmc_random_id"] = bin.unpack("A16", reply, pos)
  pos, data["bmc_guid"] = bin.unpack("A16", reply, pos)
  pos, data["hmac_sha1"] = bin.unpack("A20", reply, pos)

  return data
end

return _ENV;
