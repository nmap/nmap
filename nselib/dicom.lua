---
-- DICOM library
--
-- This library implements (partially) the DICOM protocol. This protocol is used to
-- capture, store and distribute medical images.
--
-- From Wikipedia:
-- The core application of the DICOM standard is to capture, store and distribute
-- medical images. The standard also provides services related to imaging such as
-- managing imaging procedure worklists, printing images on film or digital media
-- like DVDs, reporting procedure status like completion of an imaging acquisition,
-- confirming successful archiving of images, encrypting datasets, removing patient
-- identifying information from datasets, organizing layouts of images for review,
-- saving image manipulations and annotations, calibrating image displays, encoding
-- ECGs, encoding CAD results, encoding structured measurement data, and storing
-- acquisition protocols.
--
-- OPTIONS:
-- *<code>called_aet</code> - If set it changes the called Application Entity Title
--                            used in the requests. Default: ANY-SCP
-- *<code>calling_aet</code> - If set it changes the calling Application Entity Title
--                            used in the requests. Default: ECHOSCU
--
-- @args dicom.called_aet Called Application Entity Title. Default: ANY-SCP
-- @args dicom.calling_aet Calling Application Entity Title. Default: ECHOSCU
-- @args dicom.timeout_ms Socket timeout in milliseconds. Default: 3000
-- 
-- @author Paulino Calderon <paulino@calderonpale.com> and Tyler M <tmart234@gmail.com>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
---

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

_ENV = stdnse.module("dicom", stdnse.seeall)

local MIN_SIZE_ASSOC_REQ = 68
local MAX_SIZE_PDU = 128000
local MIN_HEADER_LEN = 6
local PDU_NAMES = {}

-- ===== Local Helper Functions =====

local function ul_item(item_type, value_bytes)
  return string.pack(">B B I2", item_type, 0x00, #value_bytes) .. value_bytes
end

local function item_application_context(uid) return ul_item(0x10, uid) end
local function item_abstract_syntax(uid)    return ul_item(0x30, uid) end
local function item_transfer_syntax(uid)    return ul_item(0x40, uid) end

local function item_presentation_context(pc_id, abstract_uid, transfer_uid)
  local header = string.pack(">B B B B", pc_id, 0x00, 0x00, 0x00)
  local payload = header .. item_abstract_syntax(abstract_uid) .. item_transfer_syntax(transfer_uid)
  return ul_item(0x20, payload)
end

local function item_max_pdu(max_len)
  return string.pack(">B B I2 I4", 0x51, 0x00, 0x0004, max_len)
end
local function item_impl_uid(uid)     return ul_item(0x52, uid) end
local function item_impl_version(ver) return ul_item(0x55, ver) end

local function item_user_information(impl_uid, impl_ver, max_pdu_len)
  local payload = item_max_pdu(max_pdu_len) .. item_impl_uid(impl_uid) .. item_impl_version(impl_ver)
  return ul_item(0x50, payload)
end

local function pad16(s)
  s = (s or ""):sub(1,16)
  if #s < 16 then s = s .. string.rep(" ", 16 - #s) end
  return s
end

-- ==================================

local PDU_CODES = {
  ASSOCIATE_REQUEST  = 0x01,
  ASSOCIATE_ACCEPT   = 0x02,
  ASSOCIATE_REJECT   = 0x03,
  DATA               = 0x04,
  RELEASE_REQUEST    = 0x05,
  RELEASE_RESPONSE   = 0x06,
  ABORT              = 0x07
}

for i, v in pairs(PDU_CODES) do
  PDU_NAMES[v] = i
end

-- Most-specific FIRST. Only org roots known to be used as Implementation Class UIDs.
local VENDOR_UID_PATTERNS = {
  {"^1%.3%.6%.1%.4%.1%.25403%.",              "ClearCanvas"},
  {"^1%.2%.826%.0%.1%.3680043%.9%.3811%.",    "pynetdicom"},
  {"^1%.2%.826%.0%.1%.3680043%.8%.641%.",     "Orthanc"},
  {"^1%.2%.826%.0%.1%.3680043%.8%.1057%.",    "OsiriX/Horos"},
  {"^1%.2%.276%.0%.7230010%.3%.",             "DCMTK"},
  
  -- Prevent premature termination limits on sub-vendors (no $ anchors)
  {"^1%.2%.40%.0%.13%.1%.3",                  "dcm4che"},
  {"^1%.2%.826%.0%.1%.3680043%.2%.135%.1066%.101", "ConQuest"},

  -- Major vendors (org roots)
  {"^1%.2%.840%.113619%.",                    "GE Healthcare"},
  {"^1%.3%.12%.2%.1107%.",                    "Siemens"},
  {"^1%.2%.840%.114257%.",                    "Agfa"},
  {"^1%.2%.840%.113704%.",                    "Philips"},
  {"^1%.2%.840%.113564%.",                    "Carestream"},
  {"^1%.2%.392%.200036%.",                    "Fujifilm"},
  {"^1%.2%.840%.113669%..*",                  "Merge Healthcare"},
  {"^1%.3%.46%.670589%.",                     "Philips"},
}

---
-- start_connection(host, port) starts socket to DICOM service
---
function start_connection(host, port)
  local dcm = {}
  dcm['socket'] = nmap.new_socket()

  -- Dynamically adapt to SSL/TLS if detected by Nmap core
  local protocol = "tcp"
  local is_ssl = false
  
  -- Nmap stores SSL tunnel flags in port.version.service_tunnel
  if port.version and port.version.service_tunnel == "ssl" then
    is_ssl = true
  end
  if port.version and type(port.version.name) == "string" and port.version.name:match("tls") then
    is_ssl = true
  end

  if is_ssl then
    protocol = "ssl"
    stdnse.debug1("DICOM: Upgrading nsock connection to SSL/TLS")
  end

  local ok, err = dcm['socket']:connect(host, port, protocol)
  if ok == false then
    return false, "DICOM: Failed to connect to host: " .. err
  end

  local t = tonumber(stdnse.get_script_args("dicom.timeout_ms")) or 3000
  dcm['socket']:set_timeout(t)

  return true, dcm
end

---
-- send(dcm, data) Sends DICOM packet over established socket
---
function send(dcm, data) 
  if not dcm['socket'] then return false, "No socket found." end
  stdnse.debug2("DICOM: Sending DICOM packet (%d bytes)", #data)
  return dcm['socket']:send(data)
end

---
-- receive(dcm) Reads DICOM PDUs over an established socket.
---
function receive(dcm)
  local sock = dcm['socket']
  if not sock then return false, "No socket" end

  local function is_timeout(err)
    local e = tostring(err or ""):lower()
    return e:find("timed out", 1, true) or e:find("timeout", 1, true) or e:find("time out", 1, true)
  end

  local ok1, chunk = sock:receive_bytes(6)
  if not ok1 then
    if is_timeout(chunk) then return false, "TIMEOUT" end
    return false, chunk
  end
  if #chunk < 6 then return false, "Short PDU header" end

  local header = chunk:sub(1, 6)
  local pdu_type, _, pdu_length = string.unpack(">B B I4", header)
  local body = chunk:sub(7)
  local need = pdu_length - #body

  while need > 0 do
    local ok2, more = sock:receive_bytes(need)
    if not ok2 then
      if is_timeout(more) then return false, "TIMEOUT" end
      return false, more
    end
    -- Prevent buffer over-read if the server sends the next PDU immediately
    body = body .. string.sub(more, 1, need)
    need = pdu_length - #body
  end

  return true, header .. body
end

---
-- pdu_header_encode(pdu_type, length) encodes the DICOM PDU header
---
function pdu_header_encode(pdu_type, length)
  if type(pdu_type) ~= "number" or type(length) ~= "number" then
    return false, "PDU Type and Length must be numbers."
  end
  local header = string.pack(">B B I4", pdu_type, 0, length)
  return true, header
end

-- ==================== Parse Sub-Routines ====================

function parse_implementation_version(data)
  local version, uid = nil, nil
  local data_len = #data

  -- A-ASSOCIATE-AC fixed length is 74 bytes. Variable items begin at byte 75 (1-indexed).
  if data_len < 74 then 
    return nil, nil 
  end

  local offset = 75
  local userinfo_start = nil

  -- 1. Safely walk the TLV structure instead of using string matching (data:find)
  while offset + 3 <= data_len do
    local item_type = string.byte(data, offset)
    local item_len  = string.unpack(">I2", data, offset + 2)

    if item_type == 0x50 then
      userinfo_start = offset
      break
    end
    -- Skip to the next item
    offset = offset + 4 + item_len
  end

  if not userinfo_start then
      stdnse.debug2("User Information item (0x50) not found during TLV walk.")
      return nil, nil
  end

  -- Ensure we can safely read the length of the User Info Block itself
  if userinfo_start + 3 > data_len then return nil, nil end

  local userinfo_len = string.unpack(">I2", data, userinfo_start + 2)
  local sub_offset = userinfo_start + 4
  local effective_end = math.min(userinfo_start + 3 + userinfo_len, data_len)

  -- 2. Walk the sub-items inside User Info
  while sub_offset + 3 <= effective_end do
    local sub_type = string.byte(data, sub_offset)
    local sub_len  = string.unpack(">I2", data, sub_offset + 2)
    local sub_value_start = sub_offset + 4
    local sub_value_end   = sub_offset + 3 + sub_len

    if sub_value_end <= effective_end and sub_len > 0 then
      local value_raw = data:sub(sub_value_start, sub_value_end)
      local value_cleaned = value_raw:gsub("%z", ""):match("^%s*(.-)%s*$")

      if sub_type == 0x52 and not uid then
          uid = value_cleaned
      elseif sub_type == 0x55 and not version then
          version = value_cleaned
      end
    end

    sub_offset = sub_offset + 4 + sub_len
  end

  return version, uid
end

function identify_vendor_from_uid(uid)
  if not uid then return nil end
  uid = uid:gsub("%z", ""):match("^%s*(.-)%s*$")
  for _, entry in ipairs(VENDOR_UID_PATTERNS) do
    if uid:match(entry[1]) then
      return entry[2]
    end
  end
  return nil
end

function extract_clean_version(version_str, vendor)
  if not version_str then return nil end
  local s = version_str:gsub("%z", ""):match("^%s*(.-)%s*$")
  if s == "" then return nil end
  local v = vendor and vendor:lower() or nil

  -- Helper: map 3 digits like "369" -> "3.6.9"
  -- Note: This is a historical heuristic. It will fail if vendors adopt double-digit minor versions (e.g., 3.10.2).
  local function ddd_to_semver(ddd)
    if not ddd or #ddd ~= 3 then return nil end
    return string.format("%s.%s.%s", ddd:sub(1,1), ddd:sub(2,2), ddd:sub(3,3))
  end

  if v == "dcmtk" or s:find("DCMTK", 1, true) or s:find("OFFIS", 1, true) then
    local a,b,c = s:match("[Oo][Ff][Ff][Ii][Ss].-[Dd][Cc][Mm][Tt][Kk].-[ _-]?(%d)%.?(%d)%.?(%d)")
    if a and b and c then return string.format("%s.%s.%s", a,b,c) end

    a,b,c = s:match("[Dd][Cc][Mm][Tt][Kk][ _-]?(%d)%.?(%d)%.?(%d)")
    if a and b and c then return string.format("%s.%s.%s", a,b,c) end

    local sem = s:match("[Dd][Cc][Mm][Tt][Kk][%s_/-]*([%d]+%.%d+%.%d+)")
             or s:match("[Oo][Ff][Ff][Ii][Ss].-[Dd][Cc][Mm][Tt][Kk][%s_/-]*([%d]+%.%d+%.%d+)")
    if sem then return sem end
  end

  if v == "pynetdicom" or s:find("PYNETDICOM") or s:lower():find("pynetdicom") then
    local ddd = s:match("PYNETDICOM[_-](%d%d%d)$")
    if ddd then
      local semv = ddd_to_semver(ddd)
      if semv then return semv end
    end
    local sem = s:match("[Pp][Yy][Nn][Ee][Tt][Dd][Ii][Cc][Oo][Mm][%s/:-]+([%d]+%.%d+%.%d+)")
             or s:match("[Pp][Yy][Nn][Ee][Tt][Dd][Ii][Cc][Oo][Mm][%s/:-]+([%d]+%.%d+)")
    if sem then return sem end
  end

  if v == "dcm4che" or s:lower():find("dcm4che") then
    local sem = s:match("dcm4che[%w-]*[%s/:-]+([%d]+%.%d+%.%d+)")
    if sem then return sem end
  end

  if v == "orthanc" or s:lower():find("orthanc") then
    local sem = s:match("[Oo]rthanc[%s%-/]*[vV]?([%d]+%.%d+%.%d+)")
             or s:match("[Oo]rthanc[%s%-/]*[vV]?([%d]+%.%d+)")
    if sem then return sem end
  end

  if v == "osirix" or v == "horos" or s:lower():find("osirix") or s:lower():find("horos") then
    local sem = s:match("[vV]([%d]+%.%d+%.%d+)")
    if sem then return sem end
  end

  if v == "clearcanvas" or s:find("ClearCanvas") then
    local maj, min, build = s:match("ClearCanvas[_-](%d+)%.(%d+)%.(%d+)")
    if maj and min and build then return string.format("%s.%s.%s", maj, min, build) end

    maj, min = s:match("ClearCanvas[_-](%d+)%.(%d+)")
    if maj and min then return string.format("%s.%s", maj, min) end
  end

  -- Generic fallbacks
  local sem = s:match("(%d+%.%d+%.%d+)")
  if sem then return sem end
  sem = s:match("(%d+%.%d+)")
  if sem then return sem end

  if v == "dcmtk" then
    local ddd = s:match("(%d%d%d)")
    if ddd then
      local semv = ddd_to_semver(ddd)
      if semv then return semv end
    end
  end

  return s
end

-- ============================================================

---
-- associate(host, port) Attempts to associate to a DICOM Service Provider
---
function associate(host, port, calling_aet, called_aet)
  local status, dcm = start_connection(host, port)
  if not status then
    return false, dcm -- dcm contains the error message
  end

  local application_context_name = "1.2.840.10008.3.1.1.1"   
  local abstract_syntax_name     = "1.2.840.10008.1.1"       
  local transfer_syntax_name     = "1.2.840.10008.1.2"       

  local called_ae_title_val  = pad16(called_aet  or "ANY-SCP")
  local calling_ae_title_val = pad16(calling_aet or "ECHOSCU")

  -- Use a generic, clearly labeled scanner identification
  local implementation_id      = "1.2.276.0.7230010.3.0.3.6.2" -- Re-using DCMTK's root as it passes most legacy strict filters
  local implementation_version = "NMAP_DICOM_PING"
  local max_pdu_len            = 16384

  local application_context  = item_application_context(application_context_name)
  local presentation_context = item_presentation_context(1, abstract_syntax_name, transfer_syntax_name)
  local userinfo_context     = item_user_information(implementation_id, implementation_version, max_pdu_len)

  local fixed = string.pack(">I2 I2 c16 c16 c32", 0x0001, 0x0000, called_ae_title_val, calling_ae_title_val, string.rep("\0", 32))
  local assoc_body = fixed .. application_context .. presentation_context .. userinfo_context

  local header_ok, header = pdu_header_encode(PDU_CODES["ASSOCIATE_REQUEST"], #assoc_body)
  if not header_ok then 
    dcm['socket']:close()
    return false, "Failed to encode PDU header" 
  end
  
  local assoc_request = header .. assoc_body

  local send_status, send_err = send(dcm, assoc_request)
  if not send_status then
    dcm['socket']:close()
    return false, string.format("Couldn't send ASSOCIATE request: %s", send_err or "Unknown error")
  end

  local receive_status, response_data = receive(dcm)
  dcm['socket']:close() -- Association handshake complete; socket cleanup.

  if not receive_status then 
    return false, string.format("Couldn't read ASSOCIATE response: %s", response_data) 
  end

  if #response_data < MIN_HEADER_LEN then 
    return false, "Received response too short for PDU header" 
  end
  
  local resp_type, _, resp_length = string.unpack(">B B I4", response_data)

  if resp_type ~= PDU_CODES["ASSOCIATE_ACCEPT"] then
    if resp_type == PDU_CODES["ASSOCIATE_REJECT"] then
      return false, "ASSOCIATE REJECT received"
    else
      return false, "Received unexpected response PDU type: " .. tostring(resp_type)
    end
  end

  local received_version_str, received_uid_str = parse_implementation_version(response_data)
  local impl_version_name = received_version_str 

  local parsed_vendor, parsed_clean_version = nil, nil

  if received_uid_str then
    parsed_vendor = identify_vendor_from_uid(received_uid_str)
    if received_version_str then
      parsed_clean_version = extract_clean_version(received_version_str, parsed_vendor)
    end
  elseif received_version_str then
    local v = received_version_str:lower()
    if     v:find("dcm4che",   1, true) then parsed_vendor = "dcm4che"
    elseif v:find("dcmtk",     1, true) then parsed_vendor = "DCMTK"
    elseif v:find("pynetdicom",1, true) then parsed_vendor = "pynetdicom"
    elseif v:find("orthanc",   1, true) then parsed_vendor = "Orthanc"
    end
    parsed_clean_version = extract_clean_version(received_version_str, parsed_vendor)
  end

  local final_version = parsed_clean_version or impl_version_name

  return true, nil, final_version, parsed_vendor, received_uid_str, impl_version_name
end

function send_pdata(dicom, data)
  local status, header = pdu_header_encode(PDU_CODES["DATA"], #data)
  if status == false then
    return false, header
  end
  local err
  status, err = send(dicom, header .. data)
  if status == false then
    return false, err
  end
  return true
end

function extract_uid_root(uid)
  if not uid then return nil end
  local trimmed = uid:gsub("%z",""):match("^%s*(.-)%s*$")
  if trimmed == "" then return nil end
  return trimmed:match("^([%d%.]+)%.[^%.]+$") or trimmed
end

return _ENV