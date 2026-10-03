---
-- DICOM protocol library for Nmap NSE scripts.
--
-- Implements the DICOM Upper Layer protocol (PS3.8) and core DIMSE
-- services (PS3.7).  Provides connection management, A-ASSOCIATE
-- negotiation, P-DATA-TF PDU construction/parsing, and helpers for
-- C-ECHO, C-STORE, C-FIND, C-GET, and C-MOVE.
--
-- Supports both Implicit VR Little Endian and Explicit VR Little Endian
-- transfer syntaxes for dataset encoding and parsing.
--
-- Designed to be shared across multiple DICOM NSE scripts
-- (dicom-ping, dicom-store-fuzzer, dicom-cfind-ls, etc.) so that
-- protocol logic lives in one place.
--
-- INSTALLATION:
-- Copy this file to your Nmap nselib/ directory to replace the
-- built-in minimal dicom.lua:
--   cp dicom.lua /usr/share/nmap/nselib/dicom.lua
-- (or /usr/local/share/nmap/nselib/dicom.lua on macOS)
-- This library is fully backward-compatible with the original: the legacy
-- API (start_connection, send, receive, pdu_header_encode, associate,
-- send_pdata) keeps its exact signatures and behaviour, so the official
-- dicom-ping and dicom-brute scripts run unchanged.
--
-- CHANGES vs. the upstream nmap nselib/dicom.lua:
--  * Legacy API preserved verbatim (drop-in compatible).
--  * Added DIMSE service support: C-ECHO, C-STORE, C-FIND, C-GET, C-MOVE.
--  * Added A-ASSOCIATE-RQ builder with multiple presentation contexts,
--    configurable max PDU, and SCP/SCU Role Selection (PS3.7 D.3.3.4) so
--    C-GET can receive C-STORE sub-operations.
--  * Added A-ASSOCIATE-AC parser (accepted contexts, transfer syntaxes,
--    max PDU, implementation identification, accepted roles) for
--    fingerprinting and negotiation.
--  * Added P-DATA-TF fragmentation/reassembly that surfaces the PDV
--    presentation-context ID (needed to answer C-STORE sub-ops correctly).
--  * Added Implicit/Explicit VR LE element encoders/decoders and Part-10
--    (.dcm) dataset extraction.
--
-- OPTIONS:
-- *<code>called_aet</code> - Called Application Entity Title (default:
-- ANY-SCP)
-- *<code>calling_aet</code> - Calling Application Entity Title (default:
-- ECHOSCU)
--
-- @args dicom.called_aet Called Application Entity Title. Default: ANY-SCP
-- @args dicom.calling_aet Calling Application Entity Title. Default: ECHOSCU
--
-- @author Paulino Calderon <paulino@calderonpale.com>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
---

local nmap   = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table  = require "table"
local math   = require "math"
local io     = io
local os     = os

_ENV = stdnse.module("dicom", stdnse.seeall)

-----------------------------------------------------------------------
-- 1. CONSTANTS
-----------------------------------------------------------------------

--- Minimum size in bytes of a valid A-ASSOCIATE-RQ PDU.
MIN_SIZE_ASSOC_REQ = 68
--- Maximum PDU size accepted when reading from the network.
MAX_SIZE_PDU       = 128000
--- Length in bytes of a DICOM Upper Layer PDU header.
MIN_HEADER_LEN     = 6

---
-- DICOM Upper Layer PDU type codes (PS3.8 Table 9-1).
-- @class table
-- @name PDU_CODES
PDU_CODES = {
  ASSOCIATE_REQUEST  = 0x01,
  ASSOCIATE_ACCEPT   = 0x02,
  ASSOCIATE_REJECT   = 0x03,
  DATA               = 0x04,
  RELEASE_REQUEST    = 0x05,
  RELEASE_RESPONSE   = 0x06,
  ABORT              = 0x07,
}

---
-- Reverse map of PDU_CODES: numeric type code to its name.
-- @class table
-- @name PDU_NAMES
PDU_NAMES = {}
for i, v in pairs(PDU_CODES) do
  PDU_NAMES[v] = i
end

---
-- DIMSE Command Field values (PS3.7 Table E.1-1).
-- @class table
-- @name COMMAND_FIELD
COMMAND_FIELD = {
  C_STORE_RQ  = 0x0001,
  C_STORE_RSP = 0x8001,
  C_GET_RQ    = 0x0010,
  C_GET_RSP   = 0x8010,
  C_FIND_RQ   = 0x0020,
  C_FIND_RSP  = 0x8020,
  C_MOVE_RQ   = 0x0021,
  C_MOVE_RSP  = 0x8021,
  C_ECHO_RQ   = 0x0030,
  C_ECHO_RSP  = 0x8030,
}

---
-- DIMSE Status codes (PS3.7 Table C.4-1 ff.).
-- @class table
-- @name STATUS
STATUS = {
  SUCCESS              = 0x0000,
  PENDING              = 0xFF00,
  PENDING_WARN         = 0xFF01,
  CANCEL               = 0xFE00,
  WARN_COERCE          = 0xB000,
  FAIL_REFUSED_MV      = 0xA700,
  FAIL_REFUSED_SOP     = 0xA900,
  FAIL_ERROR           = 0xC000,
}

---
-- Well-known SOP Class UIDs (storage and Query/Retrieve information models).
-- @class table
-- @name SOP_CLASS
SOP_CLASS = {
  VERIFICATION          = "1.2.840.10008.1.1",
  CT_IMAGE_STORAGE      = "1.2.840.10008.5.1.4.1.1.2",
  ENHANCED_CT_STORAGE   = "1.2.840.10008.5.1.4.1.1.2.1",
  MR_IMAGE_STORAGE      = "1.2.840.10008.5.1.4.1.1.4",
  SECONDARY_CAPTURE     = "1.2.840.10008.5.1.4.1.1.7",
  PET_IMAGE_STORAGE     = "1.2.840.10008.5.1.4.1.1.128",
  RT_DOSE_STORAGE       = "1.2.840.10008.5.1.4.1.1.481.2",
  RT_PLAN_STORAGE       = "1.2.840.10008.5.1.4.1.1.481.5",
  -- Query/Retrieve Information Models
  STUDY_ROOT_QR_FIND    = "1.2.840.10008.5.1.4.1.2.2.1",
  STUDY_ROOT_QR_MOVE    = "1.2.840.10008.5.1.4.1.2.2.2",
  STUDY_ROOT_QR_GET     = "1.2.840.10008.5.1.4.1.2.2.3",
  PATIENT_ROOT_QR_FIND  = "1.2.840.10008.5.1.4.1.2.1.1",
  PATIENT_ROOT_QR_MOVE  = "1.2.840.10008.5.1.4.1.2.1.2",
  PATIENT_ROOT_QR_GET   = "1.2.840.10008.5.1.4.1.2.1.3",
}

---
-- Transfer Syntax UIDs (PS3.5).
-- @class table
-- @name TRANSFER_SYNTAX
TRANSFER_SYNTAX = {
  IMPLICIT_LE  = "1.2.840.10008.1.2",
  EXPLICIT_LE  = "1.2.840.10008.1.2.1",
  EXPLICIT_BE  = "1.2.840.10008.1.2.2",
  DEFLATED_LE  = "1.2.840.10008.1.2.1.99",
  JPEG_BASELINE = "1.2.840.10008.1.2.4.50",
  JPEG_LS       = "1.2.840.10008.1.2.4.80",
  RLE           = "1.2.840.10008.1.2.5",
}

--- DICOM Application Context Name UID (PS3.7).
APP_CTX_UID = "1.2.840.10008.3.1.1.1"

--- Implementation Class UID advertised in A-ASSOCIATE-RQ (DCMTK-compatible).
IMPL_CLASS_UID   = "1.2.276.0.7230010.3.0.3.6.7"
--- Implementation Version Name advertised in A-ASSOCIATE-RQ.
IMPL_VERSION     = "OFFIS_DCMTK_367"
--- Default maximum PDU length proposed during association.
MAX_PDU_DEFAULT  = 16384

---
-- Query/Retrieve levels (0008,0052 QueryRetrieveLevel values).
-- @class table
-- @name QR_LEVEL
QR_LEVEL = {
  PATIENT = "PATIENT",
  STUDY   = "STUDY",
  SERIES  = "SERIES",
  IMAGE   = "IMAGE",
}

---
-- VRs that use the long (12-byte) explicit encoding in Explicit VR LE
-- (PS3.5 Table 7.1-1). Membership test: LONG_VRS[vr] is true for these.
-- @class table
-- @name LONG_VRS
LONG_VRS = {
  OB = true, OD = true, OF = true, OL = true, OV = true, OW = true,
  SQ = true, UC = true, UN = true, UR = true, UT = true,
  SV = true, UV = true,
}

--- CommandDataSetType (0000,0800) sentinel: a dataset follows the command.
DATASET_PRESENT     = 0x0001
--- CommandDataSetType (0000,0800) sentinel: no dataset follows the command.
DATASET_NOT_PRESENT = 0x0101

-----------------------------------------------------------------------
-- 2. LOW-LEVEL UTILITIES
-----------------------------------------------------------------------

--- Pack a big-endian unsigned integer into n bytes.
function pack_be(val, n)
  if n == 1 then return string.pack(">B",  val) end
  if n == 2 then return string.pack(">I2", val) end
  if n == 4 then return string.pack(">I4", val) end
  return string.pack(">I" .. n, val)
end

--- Pack a little-endian unsigned integer into n bytes.
function pack_le(val, n)
  if n == 1 then return string.pack("<B",  val) end
  if n == 2 then return string.pack("<I2", val) end
  if n == 4 then return string.pack("<I4", val) end
  return string.pack("<I" .. n, val)
end

--- Pad/truncate a string to exactly n bytes (space-padded on right).
function pad_str(s, n)
  s = s or ""
  if #s >= n then return s:sub(1, n) end
  return s .. string.rep(" ", n - #s)
end

--- Build a TLV item: type(1) + reserved(1) + length(2, big-endian) + data.
function mk_item(item_type, data)
  return string.pack(">B B I2", item_type, 0x00, #data) .. data
end

--- Generate a plausible fake UID.
function generate_fake_uid()
  return string.format("1.2.3.4.5.99999.%d.%d",
    os.time(), math.random(100000, 999999))
end

--- Read a file from disk.  Returns bytes string or nil, err.
function read_file(path)
  local f, err = io.open(path, "rb")
  if not f then return nil, "Cannot open file: " .. tostring(err) end
  local data = f:read("*a")
  f:close()
  if not data then return nil, "Cannot read file: " .. path end
  return data, nil
end

--- Write binary data to a file.  Returns true or nil, err.
function write_file(path, data)
  local f, err = io.open(path, "wb")
  if not f then
    return nil, "Cannot open file for writing: " .. tostring(err)
  end
  f:write(data)
  f:close()
  return true
end

-----------------------------------------------------------------------
-- 3. PDU HEADER
-----------------------------------------------------------------------

--- Encode a DICOM PDU header (6 bytes).
-- @param pdu_type PDU type byte
-- @param length   Length of the PDU body
-- @return status (bool), header_or_err (string)
function pdu_header_encode(pdu_type, length)
  if type(pdu_type) ~= "number" then
    return false, "PDU Type must be an unsigned integer. Range:0-7"
  end
  if type(length) ~= "number" then
    return false, "Length must be an unsigned integer."
  end
  local header = string.pack(">B B I4", pdu_type, 0, length)
  if #header < MIN_HEADER_LEN then
    return false, "Header must be at least 6 bytes. Something went wrong."
  end
  return true, header
end

-----------------------------------------------------------------------
-- 4. ASSOCIATION PDU BUILDERS
-----------------------------------------------------------------------

--- Build an SCP/SCU Role Selection sub-item (PS3.7 §D.3.3.4, item type 0x54).
-- Used to request role reversal so the SCU can receive C-STORE sub-operations
-- (required for C-GET).
-- @param uid  Abstract Syntax (SOP Class) UID the role applies to
-- @param scu  SCU role byte (0 or 1)
-- @param scp  SCP role byte (0 or 1)
-- @return Encoded role selection sub-item bytes
function mk_role_item(uid, scu, scp)
  -- body: UID-length(2) + UID + SCU-role(1) + SCP-role(1)
  local body = string.pack(">I2", #uid) .. uid
             .. string.pack(">B B", scu and 1 or 0, scp and 1 or 0)
  return mk_item(0x54, body)
end

--- Build User Information sub-item for A-ASSOCIATE-RQ.
-- @param max_pdu Max PDU length to advertise
-- @param roles   (optional) list of {uid=<SOP Class UID>, scu=bool, scp=bool}
--                role-selection requests to append (for C-GET, request
-- scp=true
--                on the storage SOP classes you are willing to receive).
function mk_user_info(max_pdu, roles)
  max_pdu = max_pdu or MAX_PDU_DEFAULT
  local max_pdu_item = string.pack(">B B I2 I4", 0x51, 0x00, 0x04, max_pdu)
  local inner = max_pdu_item
  -- Role selection items must precede the implementation identification items
  -- in typical peer implementations; place them here for maximum
  -- compatibility.
  if roles then
    for _, r in ipairs(roles) do
      inner = inner .. mk_role_item(r.uid, r.scu ~= false, r.scp == true)
    end
  end
  inner = inner
        .. mk_item(0x52, IMPL_CLASS_UID)
        .. mk_item(0x55, IMPL_VERSION)
  return mk_item(0x50, inner)
end

--- Build a Presentation Context sub-item for A-ASSOCIATE-RQ.
-- @param pctx_id       Odd integer 1–255
-- @param sop_class     Abstract Syntax UID string
-- @param transfer_uids List of Transfer Syntax UIDs
--                      (default: Explicit VR LE + Implicit VR LE)
function mk_pres_ctx(pctx_id, sop_class, transfer_uids)
  transfer_uids = transfer_uids or {
    TRANSFER_SYNTAX.EXPLICIT_LE,
    TRANSFER_SYNTAX.IMPLICIT_LE,
  }
  local inner = string.pack(">B B B B", pctx_id, 0x00, 0x00, 0x00)
              .. mk_item(0x30, sop_class)
  for _, ts in ipairs(transfer_uids) do
    inner = inner .. mk_item(0x40, ts)
  end
  return mk_item(0x20, inner)
end

--- Build a complete A-ASSOCIATE-RQ PDU.
-- @param called_ae   Called AE Title (max 16 chars)
-- @param calling_ae  Calling AE Title (max 16 chars)
-- @param sop_classes List of Abstract Syntax UIDs to propose
-- @param max_pdu     Max PDU length to propose
-- @param transfer_uids  Optional list of TS UIDs for all presentation contexts
-- @param roles          Optional list of {uid=, scu=, scp=} role-selection
--                       requests (see mk_user_info). Use for C-GET to request
--                       scp=true on the storage SOP classes you will receive.
-- @return Full PDU bytes ready to send
function build_assoc_rq(called_ae, calling_ae, sop_classes, max_pdu,
    transfer_uids, roles)
  called_ae  = pad_str(called_ae  or "ANY-SCP",   16)
  calling_ae = pad_str(calling_ae or "ECHOSCU",    16)

  local reserved_32 = string.rep("\x00", 32)
  local body = string.pack(">I2 I2", 0x0001, 0x0000)
             .. called_ae .. calling_ae .. reserved_32
  body = body .. mk_item(0x10, APP_CTX_UID)

  for i, sop in ipairs(sop_classes) do
    local pctx_id = (2 * i - 1)
    if pctx_id > 255 then pctx_id = 255 end
    body = body .. mk_pres_ctx(pctx_id, sop, transfer_uids)
  end
  body = body .. mk_user_info(max_pdu, roles)

  return string.pack(">B B I4", PDU_CODES.ASSOCIATE_REQUEST, 0x00, #body)
      .. body
end

--- Parse A-ASSOCIATE-AC to extract accepted presentation contexts.
-- @param data  Raw A-ASSOCIATE-AC PDU bytes
-- @return Table { pctxs = {pctx_id -> {accepted, transfer_syntax}}, max_pdu =
-- n }
function parse_assoc_ac(data)
  local result = {
    pctxs = {},
    max_pdu = MAX_PDU_DEFAULT,
    roles = {}, -- Accepted SCP/SCU role selections {uid -> {scu,scp}}
    -- Fingerprinting fields (populated from A-ASSOCIATE-AC)
    called_ae       = "",   -- Called AE Title (from fixed header)
    calling_ae      = "",   -- Calling AE Title (from fixed header)
    impl_class_uid  = "",   -- Implementation Class UID (User Info 0x52)
    impl_version    = "",   -- Implementation Version Name (User Info 0x55)
    protocol_ver    = 0,    -- Protocol Version (should be 1)
  }
  if #data < 10 then return result end

  -- Fixed header after PDU header(6): protocol version(2) + reserved(2) +
  -- called(16) + calling(16) + reserved(32) = 68
  if #data >= 74 then
    result.protocol_ver = string.unpack(">I2", data, 7)
    -- Called AE Title: bytes 11-26 (16 bytes, space-padded)
    result.called_ae  = data:sub(11, 26):gsub("%s+$", "")
    -- Calling AE Title: bytes 27-42 (16 bytes, space-padded)
    result.calling_ae = data:sub(27, 42):gsub("%s+$", "")
  end

  local pos = 75
  if pos >= #data then return result end

  while pos <= #data - 4 do
    local item_type = string.byte(data, pos)
    local item_len  = string.unpack(">I2", data, pos + 2)
    local item_data = data:sub(pos + 4, pos + 3 + item_len)
    pos = pos + 4 + item_len

    if item_type == 0x21 then
      -- Presentation Context (AC)
      local pctx_id     = string.byte(item_data, 1)
      local result_code = string.byte(item_data, 3)
      local ts_uid = ""
      if #item_data > 4 then
        local ts_type = string.byte(item_data, 5)
        if ts_type == 0x40 then
          local ts_len = string.unpack(">I2", item_data, 7)
          ts_uid = item_data:sub(9, 8 + ts_len)
        end
      end
      result.pctxs[pctx_id] = {
        accepted        = (result_code == 0x00),
        transfer_syntax = ts_uid,
      }
    elseif item_type == 0x50 then
      -- User Information sub-items (PS3.7 Annex D.3.3)
      local upos = 1
      while upos <= #item_data - 4 do
        local u_type = string.byte(item_data, upos)
        local u_len  = string.unpack(">I2", item_data, upos + 2)
        local u_val  = item_data:sub(upos + 4, upos + 3 + u_len)
        if u_type == 0x51 and u_len == 4 then
          -- Maximum Length sub-item
          result.max_pdu = string.unpack(">I4", item_data, upos + 4)
        elseif u_type == 0x52 then
          -- Implementation Class UID
          result.impl_class_uid = u_val:gsub("%z", ""):gsub("%s+$", "")
        elseif u_type == 0x55 then
          -- Implementation Version Name
          result.impl_version = u_val:gsub("%z", ""):gsub("%s+$", "")
        elseif u_type == 0x54 then
          -- SCP/SCU Role Selection (accepted): UID-len(2)+UID+SCU(1)+SCP(1)
          if u_len >= 4 then
            local uid_len = string.unpack(">I2", u_val, 1)
            if uid_len + 2 <= #u_val then
              local uid    = u_val:sub(3, 2 + uid_len)
              local scu_b  = string.byte(u_val, 3 + uid_len) or 0
              local scp_b  = string.byte(u_val, 4 + uid_len) or 0
              result.roles[uid] = { scu = (scu_b == 1), scp = (scp_b == 1) }
            end
          end
        end
        upos = upos + 4 + u_len
      end
    end
  end
  return result
end

-----------------------------------------------------------------------
-- 5. P-DATA-TF PDU BUILDER / PARSER
-----------------------------------------------------------------------

--- Chunk data into one or more P-DATA-TF PDUs (single-stream).
-- Use build_pdata_pdus when you need separate command/dataset PDU lists.
-- Use send_dimse() for the preferred combined approach.
-- @param pctx_id    Presentation context ID
-- @param data       Raw bytes to send
-- @param is_command true for command set, false for dataset
-- @param max_pdu    Max PDU length
-- @return List of PDU byte strings
function build_pdata_pdus(pctx_id, data, is_command, max_pdu)
  max_pdu = max_pdu or MAX_PDU_DEFAULT
  -- Overhead: 6 (PDU header) + 4 (PDV length) + 1 (PC-ID) + 1 (MCH) = 12
  local frag_size = max_pdu - 12
  if frag_size < 1 then frag_size = 512 end

  local pdus = {}
  local total = #data
  local offset = 1

  while offset <= total do
    local chunk_end = math.min(offset + frag_size - 1, total)
    local chunk   = data:sub(offset, chunk_end)
    local is_last = (chunk_end >= total)

    -- PS3.8 §9.3.5.1: bit 0 = 1 → command, bit 0 = 0 → dataset; bit 1 = last
    local mch
    if is_command then
      mch = is_last and 0x03 or 0x01
    else
      mch = is_last and 0x02 or 0x00
    end

    local pdv_len = 2 + #chunk   -- PC-ID + MCH + data
    local pdv = string.pack(">I4 B B", pdv_len, pctx_id, mch) .. chunk
    local pdu = string.pack(">B B I4", PDU_CODES.DATA, 0x00, #pdv) .. pdv
    pdus[#pdus + 1] = pdu
    offset = chunk_end + 1
  end
  return pdus
end

--- Extract command bytes and dataset bytes from a single P-DATA-TF PDU.
-- @param data  Raw P-DATA-TF PDU bytes
-- @return cmd_bytes, dataset_bytes, cmd_complete, ds_complete, pctx_id
--   cmd_complete: true if the last command PDV had the "last fragment" bit set
--   ds_complete:  true if the last dataset PDV had the "last fragment" bit set
--   pctx_id:      presentation context ID of the PDV(s) (command PDV
-- preferred),
--                 needed to reply on the correct context (e.g. C-STORE-RSP
-- during
--                 C-GET sub-operations). nil if no PDV was seen.
function parse_pdata(data)
  local cmd_bytes     = ""
  local dataset_bytes = ""
  local cmd_complete  = false
  local ds_complete   = false
  local pctx_id       = nil
  if not data or #data < 6 then
    return cmd_bytes, dataset_bytes, cmd_complete, ds_complete, pctx_id
  end

  local pos = 1
  while pos <= #data - 5 do
    local pdu_type = string.byte(data, pos)
    if pdu_type ~= PDU_CODES.DATA then break end
    local pdu_len  = string.unpack(">I4", data, pos + 2)
    local pdu_end  = pos + 5 + pdu_len
    local pdu_data = data:sub(pos + 6, pdu_end)
    pos = pdu_end + 1

    -- Walk PDV items inside this PDU
    local ppos = 1
    while ppos + 5 <= #pdu_data do
      local pdv_len = string.unpack(">I4", pdu_data, ppos)
      if pdv_len < 2 then break end
      local pdv_pcid = string.byte(pdu_data, ppos + 4)
      local pdv_mch  = string.byte(pdu_data, ppos + 5)
      local pdv_frag = pdu_data:sub(ppos + 6, ppos + 3 + pdv_len)
      ppos = ppos + 4 + pdv_len

      -- PS3.8 §9.3.5.1:
      --   Bit 0 = 1 -> command, Bit 0 = 0 -> dataset
      --   Bit 1 = 1 -> last fragment
      if pdv_mch and (pdv_mch & 0x01) == 0x01 then
        cmd_bytes = cmd_bytes .. pdv_frag
        cmd_complete = (pdv_mch & 0x02) == 0x02
        pctx_id = pdv_pcid            -- command PDV context wins
      else
        dataset_bytes = dataset_bytes .. pdv_frag
        ds_complete = (pdv_mch & 0x02) == 0x02
        if pctx_id == nil then pctx_id = pdv_pcid end
      end
    end
  end
  return cmd_bytes, dataset_bytes, cmd_complete, ds_complete, pctx_id
end

-----------------------------------------------------------------------
-- 6. DATA ELEMENT ENCODING
-----------------------------------------------------------------------

--- Encode a single DICOM element in Implicit VR Little Endian (PS3.5 §7.1.2).
-- @param group  Group number (e.g. 0x0000, 0x0008, 0x0010)
-- @param elem   Element number
-- @param vr     VR string ("US", "UL", "UI", "CS", "LO", etc.)
-- @param val    Value (number for US/UL, string otherwise)
-- @return Encoded element bytes
function implicit_elem(group, elem, vr, val)
  local tag_bytes = pack_le(group, 2) .. pack_le(elem, 2)
  local val_bytes
  if vr == "US" then
    val_bytes = pack_le(val, 2)
  elseif vr == "UL" then
    val_bytes = pack_le(val, 4)
  elseif vr == "UI" then
    val_bytes = tostring(val)
    if #val_bytes % 2 ~= 0 then val_bytes = val_bytes .. "\x00" end
  else
    -- CS, LO, SH, DA, TM, PN, IS, etc.
    val_bytes = tostring(val)
    if #val_bytes % 2 ~= 0 then val_bytes = val_bytes .. " " end
  end
  return tag_bytes .. pack_le(#val_bytes, 4) .. val_bytes
end

--- Encode a single DICOM element in Explicit VR Little Endian (PS3.5 §7.1.1).
-- Uses long format for OB/OD/OF/OL/OV/OW/SQ/UC/UN/UR/UT/SV/UV,
-- short format for all other VRs.
-- @param group  Group number
-- @param elem   Element number
-- @param vr     VR string (2 characters)
-- @param val    Value (number for US/UL/SS/SL, string otherwise)
-- @return Encoded element bytes
function explicit_elem(group, elem, vr, val)
  local tag_bytes = pack_le(group, 2) .. pack_le(elem, 2)
  local val_bytes
  if vr == "US" then
    val_bytes = pack_le(val, 2)
  elseif vr == "UL" then
    val_bytes = pack_le(val, 4)
  elseif vr == "SS" then
    val_bytes = string.pack("<i2", val)
  elseif vr == "SL" then
    val_bytes = string.pack("<i4", val)
  elseif vr == "UI" then
    val_bytes = tostring(val)
    if #val_bytes % 2 ~= 0 then val_bytes = val_bytes .. "\x00" end
  else
    val_bytes = tostring(val)
    if #val_bytes % 2 ~= 0 then val_bytes = val_bytes .. " " end
  end

  if LONG_VRS[vr] then
    -- Long format: tag(4) + VR(2) + reserved(2) + length(4) + value
    return tag_bytes .. vr .. pack_le(0, 2) .. pack_le(#val_bytes, 4)
        .. val_bytes
  else
    -- Short format: tag(4) + VR(2) + length(2) + value
    return tag_bytes .. vr .. pack_le(#val_bytes, 2) .. val_bytes
  end
end

--- Encode a single element using the specified transfer syntax.
-- @param group           Group number
-- @param elem            Element number
-- @param vr              VR string
-- @param val             Value
-- @param transfer_syntax Transfer syntax UID (default: Explicit VR LE)
-- @return Encoded element bytes
function encode_element(group, elem, vr, val, transfer_syntax)
  if transfer_syntax == TRANSFER_SYNTAX.IMPLICIT_LE then
    return implicit_elem(group, elem, vr, val)
  else
    return explicit_elem(group, elem, vr, val)
  end
end

--- Encode a dataset (list of tag definitions) using the specified TS.
-- Each tag is {group=N, elem=N, vr="XX", value=...}.
-- Tags are sorted by (group, elem) automatically.
-- @param tags            List of tag tables
-- @param transfer_syntax Transfer syntax UID (default: Explicit VR LE)
-- @return Encoded dataset bytes
function encode_dataset(tags, transfer_syntax)
  transfer_syntax = transfer_syntax or TRANSFER_SYNTAX.EXPLICIT_LE

  -- Sort by (group, elem) — DICOM requires ascending order
  table.sort(tags, function(a, b)
    if a.group == b.group then return a.elem < b.elem end
    return a.group < b.group
  end)

  local ds = ""
  for _, t in ipairs(tags) do
    ds = ds .. encode_element(t.group, t.elem, t.vr, t.value, transfer_syntax)
  end
  return ds
end

-----------------------------------------------------------------------
-- 7. DATA ELEMENT PARSING
-----------------------------------------------------------------------

--- Parse Implicit VR LE command set bytes into a keyed table.
-- For group 0x0000, auto-decodes US/UL values; for others, returns raw.
-- @param cmd_bytes  Raw command set bytes
-- @return Table { "GGGG,EEEE" -> {group, elem, raw, value} }
function parse_command_set(cmd_bytes)
  local elements = {}
  local pos = 1
  while pos <= #cmd_bytes - 7 do
    local group = string.unpack("<I2", cmd_bytes, pos)
    local elem  = string.unpack("<I2", cmd_bytes, pos + 2)
    local vlen  = string.unpack("<I4", cmd_bytes, pos + 4)
    if pos + 7 + vlen > #cmd_bytes + 1 then break end
    local raw   = cmd_bytes:sub(pos + 8, pos + 7 + vlen)
    pos = pos + 8 + vlen

    local key = string.format("%04X,%04X", group, elem)
    local value = raw
    if group == 0x0000 then
      if vlen == 2 then
        value = string.unpack("<I2", raw)
      elseif vlen == 4 then
        value = string.unpack("<I4", raw)
      end
    end
    elements[key] = { group = group, elem = elem, raw = raw, value = value }
  end
  return elements
end

--- Parse Implicit VR LE dataset bytes into tag -> string table.
-- @param ds_bytes  Raw dataset bytes
-- @return Table { "GGGG,EEEE" -> cleaned_string }
function parse_dataset_implicit(ds_bytes)
  local elements = {}
  local pos = 1
  while pos <= #ds_bytes - 7 do
    local group = string.unpack("<I2", ds_bytes, pos)
    local elem  = string.unpack("<I2", ds_bytes, pos + 2)
    local vlen  = string.unpack("<I4", ds_bytes, pos + 4)

    -- Undefined-length sequences (0xFFFFFFFF): skip to delimitation
    if vlen == 0xFFFFFFFF then
      pos = pos + 8
      local depth = 1
      while pos <= #ds_bytes - 7 and depth > 0 do
        local g2 = string.unpack("<I2", ds_bytes, pos)
        local e2 = string.unpack("<I2", ds_bytes, pos + 2)
        local l2 = string.unpack("<I4", ds_bytes, pos + 4)
        if g2 == 0xFFFE and e2 == 0xE0DD then
          depth = depth - 1
          pos = pos + 8
        elseif g2 == 0xFFFE and e2 == 0xE000 then
          if l2 == 0xFFFFFFFF then depth = depth + 1
          pos = pos + 8
          else pos = pos + 8 + l2 end
        elseif g2 == 0xFFFE and e2 == 0xE00D then
          pos = pos + 8
        else
          if l2 == 0xFFFFFFFF then depth = depth + 1
          pos = pos + 8
          else pos = pos + 8 + l2 end
        end
      end
    else
      if pos + 7 + vlen > #ds_bytes + 1 then break end
      local raw = ds_bytes:sub(pos + 8, pos + 7 + vlen)
      pos = pos + 8 + vlen
      local key = string.format("%04X,%04X", group, elem)
      elements[key] = raw:gsub("%z", ""):gsub("%s+$", "")
    end
  end
  return elements
end

--- Parse Explicit VR LE dataset bytes into tag -> string table.
-- Handles both short-format and long-format VRs per PS3.5 §7.1.1.
-- @param ds_bytes  Raw dataset bytes
-- @return Table { "GGGG,EEEE" -> cleaned_string }
function parse_dataset_explicit(ds_bytes)
  local elements = {}
  local pos = 1
  while pos + 3 <= #ds_bytes do
    local group = string.unpack("<I2", ds_bytes, pos)
    local elem  = string.unpack("<I2", ds_bytes, pos + 2)

    -- Sequence/item delimiters (group FFFE)
    if group == 0xFFFE then
      if elem == 0xE0DD then pos = pos + 8
      break          -- Seq delimitation
      elseif elem == 0xE00D then pos = pos + 8             -- Item delimitation
      elseif elem == 0xE000 then                           -- Item
        local l = string.unpack("<I4", ds_bytes, pos + 4)
        if l == 0xFFFFFFFF then pos = pos + 8 else pos = pos + 8 + l end
      else pos = pos + 8 end
      goto continue
    end

    -- Need VR bytes
    if pos + 5 > #ds_bytes then break end
    local vr = ds_bytes:sub(pos + 4, pos + 5)

    local vlen, data_start
    if LONG_VRS[vr] then
      -- Long: tag(4) + VR(2) + reserved(2) + length(4) = 12
      if pos + 11 > #ds_bytes then break end
      vlen = string.unpack("<I4", ds_bytes, pos + 8)
      data_start = pos + 12
    else
      -- Short: tag(4) + VR(2) + length(2) = 8
      if pos + 7 > #ds_bytes then break end
      vlen = string.unpack("<I2", ds_bytes, pos + 6)
      data_start = pos + 8
    end

    -- Undefined-length sequences: skip to delimitation
    if vlen == 0xFFFFFFFF then
      pos = data_start
      local depth = 1
      while pos <= #ds_bytes - 7 and depth > 0 do
        local g2 = string.unpack("<I2", ds_bytes, pos)
        local e2 = string.unpack("<I2", ds_bytes, pos + 2)
        local l2 = string.unpack("<I4", ds_bytes, pos + 4)
        if g2 == 0xFFFE and e2 == 0xE0DD then
          depth = depth - 1
          pos = pos + 8
        elseif g2 == 0xFFFE and e2 == 0xE000 then
          if l2 == 0xFFFFFFFF then depth = depth + 1
          pos = pos + 8
          else pos = pos + 8 + l2 end
        elseif g2 == 0xFFFE and e2 == 0xE00D then
          pos = pos + 8
        else
          if l2 == 0xFFFFFFFF then depth = depth + 1
          pos = pos + 8
          else pos = pos + 8 + l2 end
        end
      end
    else
      if data_start + vlen - 1 > #ds_bytes then break end
      local raw = ds_bytes:sub(data_start, data_start + vlen - 1)
      pos = data_start + vlen
      local key = string.format("%04X,%04X", group, elem)
      elements[key] = raw:gsub("%z", ""):gsub("%s+$", "")
    end

    ::continue::
  end
  return elements
end

--- Parse a dataset using the appropriate decoder for the transfer syntax.
-- If the TS indicates Implicit VR LE, uses the implicit parser; otherwise
-- uses the Explicit VR parser.  Includes a heuristic fallback: if explicit
-- parsing is expected but the first element's VR bytes aren't valid ASCII
-- uppercase, falls back to implicit.
-- @param ds_bytes        Raw dataset bytes
-- @param transfer_syntax Transfer syntax UID
-- @return Table { "GGGG,EEEE" -> cleaned_string }
function parse_dataset(ds_bytes, transfer_syntax)
  if not ds_bytes or #ds_bytes == 0 then return {} end
  if transfer_syntax == TRANSFER_SYNTAX.IMPLICIT_LE then
    return parse_dataset_implicit(ds_bytes)
  end
  -- Heuristic: check if bytes 5-6 look like a valid 2-char VR
  if #ds_bytes >= 6 then
    local b5 = string.byte(ds_bytes, 5)
    local b6 = string.byte(ds_bytes, 6)
    if (b5 >= 0x41 and b5 <= 0x5A) and (b6 >= 0x41 and b6 <= 0x5A) then
      return parse_dataset_explicit(ds_bytes)
    else
      stdnse.debug1("DICOM: Expected Explicit VR but VR bytes 0x%02X%02X" ..
                    " invalid; falling back to Implicit", b5, b6)
      return parse_dataset_implicit(ds_bytes)
    end
  end
  return parse_dataset_explicit(ds_bytes)
end

-----------------------------------------------------------------------
-- 8. DIMSE COMMAND SET BUILDERS
-----------------------------------------------------------------------
-- Command sets are ALWAYS encoded in Implicit VR LE (PS3.7 §6.3.1).

--- Build a C-ECHO-RQ command set.
-- @param msg_id  Message ID
-- @return Command set bytes (Implicit VR LE)
function build_cecho_rq(msg_id)
  msg_id = msg_id or 1
  local cmd = ""
  cmd = cmd .. implicit_elem(0x0000, 0x0002, "UI", SOP_CLASS.VERIFICATION)
  cmd = cmd .. implicit_elem(0x0000, 0x0100, "US", COMMAND_FIELD.C_ECHO_RQ)
  cmd = cmd .. implicit_elem(0x0000, 0x0110, "US", msg_id)
  cmd = cmd .. implicit_elem(0x0000, 0x0800, "US", DATASET_NOT_PRESENT)
  return implicit_elem(0x0000, 0x0000, "UL", #cmd) .. cmd
end

--- Build a C-STORE-RQ command set.
-- @param msg_id           Message ID
-- @param sop_class_uid    Affected SOP Class UID
-- @param sop_instance_uid Affected SOP Instance UID
-- @param priority         Priority (default: LOW = 0x0002)
-- @return Command set bytes (Implicit VR LE)
function build_cstore_rq(msg_id, sop_class_uid, sop_instance_uid, priority)
  priority = priority or 0x0002
  local cmd = ""
  cmd = cmd .. implicit_elem(0x0000, 0x0002, "UI", sop_class_uid)
  cmd = cmd .. implicit_elem(0x0000, 0x0100, "US", COMMAND_FIELD.C_STORE_RQ)
  cmd = cmd .. implicit_elem(0x0000, 0x0110, "US", msg_id)
  cmd = cmd .. implicit_elem(0x0000, 0x0700, "US", priority)
  cmd = cmd .. implicit_elem(0x0000, 0x0800, "US", DATASET_PRESENT)
  cmd = cmd .. implicit_elem(0x0000, 0x1000, "UI", sop_instance_uid)
  return implicit_elem(0x0000, 0x0000, "UL", #cmd) .. cmd
end

--- Build a C-FIND-RQ command set.
-- @param msg_id         Message ID
-- @param sop_class_uid  Abstract Syntax UID for the Q/R information model
-- @param priority       Priority (default: LOW = 0x0002)
-- @return Command set bytes (Implicit VR LE)
function build_cfind_rq(msg_id, sop_class_uid, priority)
  priority = priority or 0x0002
  local cmd = ""
  cmd = cmd .. implicit_elem(0x0000, 0x0002, "UI", sop_class_uid)
  cmd = cmd .. implicit_elem(0x0000, 0x0100, "US", COMMAND_FIELD.C_FIND_RQ)
  cmd = cmd .. implicit_elem(0x0000, 0x0110, "US", msg_id)
  cmd = cmd .. implicit_elem(0x0000, 0x0700, "US", priority)
  cmd = cmd .. implicit_elem(0x0000, 0x0800, "US", DATASET_PRESENT)
  return implicit_elem(0x0000, 0x0000, "UL", #cmd) .. cmd
end

--- Build a C-GET-RQ command set.
-- @param msg_id         Message ID
-- @param sop_class_uid  Abstract Syntax UID for the Q/R information model
-- @param priority       Priority (default: LOW = 0x0002)
-- @return Command set bytes (Implicit VR LE)
function build_cget_rq(msg_id, sop_class_uid, priority)
  priority = priority or 0x0002
  local cmd = ""
  cmd = cmd .. implicit_elem(0x0000, 0x0002, "UI", sop_class_uid)
  cmd = cmd .. implicit_elem(0x0000, 0x0100, "US", COMMAND_FIELD.C_GET_RQ)
  cmd = cmd .. implicit_elem(0x0000, 0x0110, "US", msg_id)
  cmd = cmd .. implicit_elem(0x0000, 0x0700, "US", priority)
  cmd = cmd .. implicit_elem(0x0000, 0x0800, "US", DATASET_PRESENT)
  return implicit_elem(0x0000, 0x0000, "UL", #cmd) .. cmd
end

--- Build a C-MOVE-RQ command set.
-- @param msg_id          Message ID
-- @param sop_class_uid   Abstract Syntax UID for the Q/R information model
-- @param move_dest       Move Destination AE Title (max 16 chars,
-- space-padded)
-- @param priority        Priority (default: LOW = 0x0002)
-- @return Command set bytes (Implicit VR LE)
function build_cmove_rq(msg_id, sop_class_uid, move_dest, priority)
  priority = priority or 0x0002
  -- MoveDestination (0000,0600) is AE type: max 16 chars, space-padded, even
  -- length
  local dest = move_dest or "MOVESCP"
  if #dest > 16 then dest = dest:sub(1, 16) end
  -- Pad to even length with spaces (AE VR convention)
  if #dest % 2 ~= 0 then dest = dest .. " " end
  local cmd = ""
  cmd = cmd .. implicit_elem(0x0000, 0x0002, "UI", sop_class_uid)
  cmd = cmd .. implicit_elem(0x0000, 0x0100, "US", COMMAND_FIELD.C_MOVE_RQ)
  cmd = cmd .. implicit_elem(0x0000, 0x0110, "US", msg_id)
  cmd = cmd .. implicit_elem(0x0000, 0x0600, "AE", dest)
  cmd = cmd .. implicit_elem(0x0000, 0x0700, "US", priority)
  cmd = cmd .. implicit_elem(0x0000, 0x0800, "US", DATASET_PRESENT)
  return implicit_elem(0x0000, 0x0000, "UL", #cmd) .. cmd
end

--- Build a C-STORE-RSP command set.
-- @param msg_id_rsp     Message ID Being Responded To
-- @param sop_class_uid  Affected SOP Class UID
-- @param sop_inst_uid   Affected SOP Instance UID
-- @param status_code    Status code (default: SUCCESS = 0x0000)
-- @return Command set bytes (Implicit VR LE)
function build_cstore_rsp(msg_id_rsp, sop_class_uid, sop_inst_uid, status_code)
  status_code = status_code or STATUS.SUCCESS
  local cmd = ""
  cmd = cmd .. implicit_elem(0x0000, 0x0002, "UI", sop_class_uid)
  cmd = cmd .. implicit_elem(0x0000, 0x0100, "US", COMMAND_FIELD.C_STORE_RSP)
  cmd = cmd .. implicit_elem(0x0000, 0x0120, "US", msg_id_rsp)
  cmd = cmd .. implicit_elem(0x0000, 0x0800, "US", DATASET_NOT_PRESENT)
  cmd = cmd .. implicit_elem(0x0000, 0x0900, "US", status_code)
  cmd = cmd .. implicit_elem(0x0000, 0x1000, "UI", sop_inst_uid)
  return implicit_elem(0x0000, 0x0000, "UL", #cmd) .. cmd
end

--- Build a C-FIND query dataset for a given Q/R level.
-- @param level      QR_LEVEL value ("STUDY", "SERIES", "IMAGE")
-- @param query_tags List of {group, elem, vr, value} tag tables
-- @param transfer_syntax  Transfer syntax for encoding (default: Explicit VR
-- LE)
-- @return Dataset bytes
function build_cfind_dataset(level, query_tags, transfer_syntax)
  -- Prepend QueryRetrieveLevel
  local all_tags = {{group=0x0008, elem=0x0052, vr="CS", value=level}}
  for _, t in ipairs(query_tags) do
    if not (t.group == 0x0008 and t.elem == 0x0052) then
      all_tags[#all_tags + 1] = t
    end
  end
  return encode_dataset(all_tags, transfer_syntax)
end

--- Build a C-GET query dataset.
-- @param level      QR_LEVEL value
-- @param query_tags List of {group, elem, vr, value} tag tables
-- @param transfer_syntax  Transfer syntax for encoding
-- @return Dataset bytes
function build_cget_dataset(level, query_tags, transfer_syntax)
  return build_cfind_dataset(level, query_tags, transfer_syntax)
end

-----------------------------------------------------------------------
-- 9. DIMSE RESPONSE PARSERS
-----------------------------------------------------------------------

--- Parse a C-STORE-RSP from P-DATA-TF PDU bytes.
-- @param data  Raw PDU bytes
-- @return status_code (int), error_comment (string)
function parse_cstore_rsp(data)
  local cmd_bytes = parse_pdata(data)
  local elems = parse_command_set(cmd_bytes)
  local status = 0xFFFF
  local error_comment = ""
  if elems["0000,0900"] then status = elems["0000,0900"].value end
  if elems["0000,0902"] then
    error_comment = tostring(elems["0000,0902"].value):gsub("%z",
        ""):gsub("%s+$", "")
  end
  return status, error_comment
end

--- Parse a C-FIND-RSP from P-DATA-TF PDU bytes.
-- @param data             Raw PDU bytes
-- @param transfer_syntax  Transfer syntax for dataset decoding (default:
-- Explicit VR LE)
-- @return status (int), dataset_elements (table or nil), cmd_elements (table)
function parse_cfind_rsp(data, transfer_syntax)
  transfer_syntax = transfer_syntax or TRANSFER_SYNTAX.EXPLICIT_LE
  local cmd_bytes, dataset_bytes = parse_pdata(data)
  local cmd_elems = parse_command_set(cmd_bytes)

  local status = 0xFFFF
  if cmd_elems["0000,0900"] then
    status = cmd_elems["0000,0900"].value
  end

  -- CommandDataSetType: 0x0101 = no dataset
  local has_dataset = true
  if cmd_elems["0000,0800"] then
    has_dataset = (cmd_elems["0000,0800"].value ~= DATASET_NOT_PRESENT)
  end

  local ds_elems = nil
  if has_dataset and #dataset_bytes > 0 then
    ds_elems = parse_dataset(dataset_bytes, transfer_syntax)
  end

  return status, ds_elems, cmd_elems
end

-----------------------------------------------------------------------
-- 10. NETWORK LAYER
-----------------------------------------------------------------------

--- Create a new Nmap socket with timeout.
function new_sock(timeout_s)
  local s = nmap.new_socket()
  s:set_timeout((timeout_s or 10) * 1000)
  return s
end

--- Whether DICOM-over-TLS is requested via the global "dicom.tls" script-arg.
-- @return true if dicom.tls=true was supplied on the command line
function tls_enabled()
  return stdnse.get_script_args("dicom.tls") == "true"
end

--- Connect a socket.  Returns ok, err.
-- @param sock Nmap socket
-- @param host Host object
-- @param port Port object (or number)
-- @param tls  true = TLS, false = plain TCP, nil = honor the dicom.tls arg
function tcp_connect(sock, host, port, tls)
  if tls == nil then tls = tls_enabled() end
  return sock:connect(host, port, tls and "ssl" or "tcp")
end

--- Fetch the peer's TLS certificate from a connected TLS socket, if any.
-- @param sock Connected Nmap socket (TLS)
-- @return certificate table (see nmap sslcert), or nil
function get_cert(sock)
  local ok, cert = pcall(function() return sock:get_ssl_certificate() end)
  if ok then return cert end
  return nil
end

--- Send all bytes on a socket.  Returns ok, err.
function tcp_send(sock, data)
  if not data or #data == 0 then return true end
  return sock:send(data)
end

--- Receive bytes until one complete PDU is assembled.
-- Accepts an optional carry buffer containing leftover bytes from a
-- previous call (when multiple PDUs arrive in a single TCP segment).
-- Returns the extracted PDU **and** any remaining bytes so the caller
-- can feed them back into the next call.
--
-- @param sock      Nmap socket
-- @param timeout_s Timeout in seconds (used for error classification)
-- @param carry     (optional) leftover bytes from a previous recv_pdu call
-- @return ok (bool), data_or_err (string), remaining (string – leftover bytes,
-- empty on error)
function recv_pdu(sock, timeout_s, carry)
  local buf = carry or ""
  -- If carry already contains a full PDU, extract it without reading the
  -- socket
  if #buf >= 6 then
    local pdu_len = string.unpack(">I4", buf, 3)
    if #buf >= 6 + pdu_len then
      local pdu_data  = buf:sub(1, 6 + pdu_len)
      local remaining = buf:sub(6 + pdu_len + 1)
      return true, pdu_data, remaining
    end
  end
  local ok, chunk
  for _ = 1, 30 do
    ok, chunk = sock:receive()
    if not ok then
      if chunk and chunk:find("TIMEOUT") then
        return false, "TIMEOUT", ""
      end
      return false, "CONNECTION_RESET", ""
    end
    buf = buf .. chunk
    if #buf >= 6 then
      local pdu_len = string.unpack(">I4", buf, 3)
      if #buf >= 6 + pdu_len then
        local pdu_data  = buf:sub(1, 6 + pdu_len)
        local remaining = buf:sub(6 + pdu_len + 1)
        return true, pdu_data, remaining
      end
    end
  end
  if #buf > 0 then return true, buf, "" end
  return false, "NO_DATA", ""
end

-----------------------------------------------------------------------
-- 11. DIMSE MESSAGE I/O
-----------------------------------------------------------------------

--- Send a DIMSE message (command set + optional dataset) as P-DATA-TF PDU(s).
--
-- When both the command and dataset fit within a single PDU, they are
-- combined into one P-DATA-TF PDU with two PDV items (matching the
-- behaviour of DCMTK and pynetdicom).  For larger payloads, the dataset
-- is fragmented across multiple PDUs.
--
-- Command sets are always Implicit VR LE.  The dataset must already be
-- encoded in the negotiated transfer syntax before calling this function.
--
-- @param sock      Nmap socket
-- @param pctx_id   Accepted presentation context ID
-- @param cmd_bytes Command set bytes (Implicit VR LE)
-- @param ds_bytes  Dataset bytes (already encoded in negotiated TS), or nil
-- @param max_pdu   Max PDU size (use server's negotiated value)
-- @return ok (bool), err (string or nil)
function send_dimse(sock, pctx_id, cmd_bytes, ds_bytes, max_pdu)
  max_pdu = max_pdu or MAX_PDU_DEFAULT
  local max_frag = max_pdu - 12
  if max_frag < 1 then max_frag = 512 end

  -- Build command PDV: MCH 0x03 = command + last fragment
  -- PS3.8 §9.3.5.1: Bit 0 = 1 → command, Bit 1 = 1 → last fragment
  local cmd_pdv = string.pack(">I4 B B", 2 + #cmd_bytes, pctx_id, 0x03)
      .. cmd_bytes

  -- Always send command in its own P-DATA-TF PDU.
  -- Some DICOM implementations (including certain Orthanc/DCMTK builds)
  -- do not correctly handle multi-PDV P-DATA-TF PDUs where both the
  -- command and dataset PDV items are combined into one PDU.  Sending
  -- them in separate PDUs is the most compatible approach and is
  -- explicitly allowed by PS3.8 §9.3.5.
  local pdu1 = string.pack(">B B I4", PDU_CODES.DATA, 0x00, #cmd_pdv)
      .. cmd_pdv
  local ok, err = tcp_send(sock, pdu1)
  if not ok then return false, err end

  if not ds_bytes or #ds_bytes == 0 then
    return true  -- Command-only (e.g., C-ECHO-RQ)
  end

  -- Fragment dataset across P-DATA-TF PDU(s)
  local offset = 1
  while offset <= #ds_bytes do
    local chunk_end = math.min(offset + max_frag - 1, #ds_bytes)
    local chunk   = ds_bytes:sub(offset, chunk_end)
    local is_last = (chunk_end >= #ds_bytes)
    local mch = is_last and 0x02
        or 0x00 -- PS3.8: bit 0=0 → dataset, bit 1=1 → last
    local ds_pdv  = string.pack(">I4 B B", 2 + #chunk, pctx_id, mch) .. chunk
    local pdu = string.pack(">B B I4", PDU_CODES.DATA, 0x00, #ds_pdv) .. ds_pdv
    ok, err = tcp_send(sock, pdu)
    if not ok then return false, err end
    offset = chunk_end + 1
  end
  return true
end

--- Receive a single DIMSE response (command + optional dataset).
--
-- The server may send the command and dataset in a single P-DATA-TF PDU
-- (with two PDV items) or in separate P-DATA-TF PDUs.  This function
-- handles both cases by checking CommandDataSetType (0000,0800) in the
-- command set: if a dataset is expected but not yet received, it reads
-- the next PDU to obtain it.
--
-- Accepts and returns a carry buffer so the caller can chain calls
-- without losing bytes when multiple PDUs arrive in one TCP segment.
--
-- @param sock      Nmap socket
-- @param timeout_s Timeout in seconds
-- @param carry     (optional) leftover bytes from previous recv_pdu
-- @return pdu_type (int or nil), cmd_elems (table), ds_bytes (string),
--         raw_pdu (string), remaining (string – leftover bytes for next call),
--         pctx_id (int or nil – presentation context the message arrived on;
--         needed to reply on the correct context during C-GET sub-operations)
function recv_dimse(sock, timeout_s, carry)
  local remaining = carry or ""

  -- Read first PDU (should contain at least the command set)
  local ok, data
  ok, data, remaining = recv_pdu(sock, timeout_s, remaining)
  if not ok then return nil, nil, "", data, remaining, nil end

  local pdu_type = string.byte(data, 1)
  if pdu_type ~= PDU_CODES.DATA then
    return pdu_type, nil, "", data, remaining, nil
  end

  local cmd_bytes, ds_bytes, cmd_complete, ds_complete,
      pctx_id = parse_pdata(data)
  local cmd_elems = {}
  if #cmd_bytes > 0 then
    cmd_elems = parse_command_set(cmd_bytes)
  end

  -- Check if command indicates a dataset is present
  -- CommandDataSetType (0000,0800): 0x0101 = no dataset, anything else =
  -- dataset present
  local has_dataset = false
  if cmd_elems["0000,0800"] then
    has_dataset = (cmd_elems["0000,0800"].value ~= DATASET_NOT_PRESENT)
  end

  if has_dataset then
    -- Read additional PDUs until we have the complete dataset.
    -- The dataset may span many P-DATA-TF PDUs (common for images).
    -- We stop when the last dataset PDV has MCH bit 1 set (last fragment).
    local max_reads = 2000  -- safety limit for very large datasets
    local reads = 0
    while not ds_complete and reads < max_reads do
      reads = reads + 1
      local ok2, data2
      ok2, data2, remaining = recv_pdu(sock, timeout_s, remaining)
      if not ok2 then
        stdnse.debug2("recv_dimse: dataset reassembly read error: %s",
            tostring(data2))
        break
      end
      local pdu_type2 = string.byte(data2, 1)
      if pdu_type2 ~= PDU_CODES.DATA then
        -- Non-DATA PDU arrived mid-dataset (e.g. A-ABORT).
        -- Return what we have; caller gets the unexpected PDU next time via
        -- carry.
        -- Push data2 back into remaining so the next recv_pdu finds it.
        remaining = data2 .. remaining
        break
      end
      local extra_cmd, extra_ds, _, extra_ds_complete = parse_pdata(data2)
      if #extra_cmd > 0 then
        cmd_bytes = cmd_bytes .. extra_cmd
      end
      ds_bytes = ds_bytes .. extra_ds
      ds_complete = extra_ds_complete
    end
  end

  return pdu_type, cmd_elems, ds_bytes, data, remaining, pctx_id
end

-----------------------------------------------------------------------
-- 12. CONNECTION / ASSOCIATION MANAGEMENT
-----------------------------------------------------------------------

-- ── Legacy API (backward-compatible with built-in dicom.lua) ───────

--- Legacy: start_connection(host, port) — opens TCP socket.
function start_connection(host, port)
  local dcm = {}
  local status, err
  dcm['socket'] = nmap.new_socket()
  local proto = tls_enabled() and "ssl" or "tcp"
  status, err = dcm['socket']:connect(host, port, proto)
  if status == false then
    return false, "DICOM: Failed to connect to host: " .. err
  end
  return true, dcm
end

--- Legacy: send(dcm, data)
function send(dcm, data)
  stdnse.debug2("DICOM: Sending DICOM packet (%d)", #data)
  if dcm['socket'] then
    local status, err = dcm['socket']:send(data)
    if status == false then return false, err end
  else
    return false, "No socket found. Check your DICOM object"
  end
  return true
end

--- Legacy: receive(dcm)
function receive(dcm)
  local status, data = dcm['socket']:receive()
  if status == false then return false, data end
  stdnse.debug1("DICOM: receive() read %d bytes", #data)
  return true, data
end

--- Legacy: associate(host, port, calling_aet, called_aet)
function associate(host, port, calling_aet, called_aet)
  local application_context = ""
  local presentation_context = ""
  local userinfo_context = ""

  local status, dcm = start_connection(host, port)
  if status == false then return false, dcm end

  local application_context_name = "1.2.840.10008.3.1.1.1"
  application_context = string.pack(">B B s2", 0x10, 0x0,
      application_context_name)

  local abstract_syntax_name = "1.2.840.10008.1.1"
  local transfer_syntax_name = "1.2.840.10008.1.2"
  presentation_context = string.pack(">B B I2 B B B B B B s2 B B s2",
    0x20, 0x0, 0x2e,
    0x1, 0x0, 0x0, 0x0,
    0x30, 0x0, abstract_syntax_name,
    0x40, 0x0, transfer_syntax_name)

  local implementation_id = IMPL_CLASS_UID
  local implementation_version = IMPL_VERSION
  userinfo_context = string.pack(">B B I2 B B I2 I4 B B s2 B B s2",
    0x50, 0x0, 0x3a,
    0x51, 0x0, 0x04, 0x4000,
    0x52, 0x0, implementation_id,
    0x55, 0x0, implementation_version)

  local called_ae_title = called_aet
      or stdnse.get_script_args("dicom.called_aet") or "ANY-SCP"
  local calling_ae_title = calling_aet
      or stdnse.get_script_args("dicom.calling_aet") or "ECHOSCU"
  if #called_ae_title > 16 or #calling_ae_title > 16 then
    return false,
        "Calling/Called Application Entity Title must be less than 16 bytes"
  end
  called_ae_title  = ("%-16s"):format(called_ae_title)
  calling_ae_title = ("%-16s"):format(calling_ae_title)

  local assoc_request = string.pack(">I2 I2 c16 c16 c32",
    0x1, 0x0, called_ae_title, calling_ae_title, "")
    .. application_context
    .. presentation_context
    .. userinfo_context

  local status, header = pdu_header_encode(PDU_CODES["ASSOCIATE_REQUEST"],
      #assoc_request)
  if status == false then return false, header end

  assoc_request = header .. assoc_request

  if #assoc_request < MIN_SIZE_ASSOC_REQ then
    return false, string.format(
      "ASSOCIATE request PDU must be at least %d bytes and we tried to send" ..
      " %d.",
      MIN_SIZE_ASSOC_REQ, #assoc_request)
  end
  local status, err = send(dcm, assoc_request)
  if status == false then
    return false, string.format("Couldn't send ASSOCIATE request:%s", err)
  end
  status, err = receive(dcm)
  if status == false then
    return false, string.format("Couldn't read ASSOCIATE response:%s", err)
  end

  local resp_type, _, resp_length = string.unpack(">B B I4", err)
  stdnse.debug1("PDU Type:%d Length:%d", resp_type, resp_length)
  if resp_type == PDU_CODES["ASSOCIATE_ACCEPT"] then
    stdnse.debug1("ASSOCIATE ACCEPT message found!")
    return true, dcm
  elseif resp_type == PDU_CODES["ASSOCIATE_REJECT"] then
    stdnse.debug1("ASSOCIATE REJECT message found!")
    return false, "ASSOCIATE REJECT received"
  else
    return false, "Received unknown response"
  end
end

--- Legacy: send_pdata(dicom, data)
function send_pdata(dicom, data)
  local status, header = pdu_header_encode(PDU_CODES["DATA"], #data)
  if status == false then return false, header end
  local err
  status, err = send(dicom, header .. data)
  if status == false then return false, err end
end

-- ── New API ────────────────────────────────────────────────────────

--- Perform A-ASSOCIATE-RQ and parse A-ASSOCIATE-AC.
-- @param host           Nmap host object
-- @param port           Nmap port object
-- @param called_ae      Called AE Title
-- @param calling_ae     Calling AE Title
-- @param sop_classes    List of SOP Class UIDs to propose
-- @param max_pdu        Max PDU length
-- @param timeout_s      Socket timeout in seconds
-- @param transfer_uids  Optional list of TS UIDs for presentation contexts
-- @param roles          Optional list of {uid=,scu=,scp=} SCP/SCU role
--                       selection requests (request scp=true on storage SOP
--                       classes for C-GET). Accepted roles are returned in
--                       the ac_info table (6th return value) as .roles.
-- @param tls            If true, wrap the association in TLS (DICOM-over-TLS);
--                       the peer certificate is returned in ac_info.cert.
-- @return ok, sock_or_err, pctx_map, server_max_pdu, elapsed_ms, ac_info
function do_associate(host, port, called_ae, calling_ae, sop_classes, max_pdu,
    timeout_s, transfer_uids, roles, tls)
  if tls == nil then tls = tls_enabled() end
  local sock = new_sock(timeout_s)
  local t0 = nmap.clock_ms()
  local ok, err = tcp_connect(sock, host, port, tls)
  if not ok then
    sock:close()
    return false, "CONN_REFUSED", nil, nil, nmap.clock_ms() - t0
  end

  local assoc_rq = build_assoc_rq(called_ae, calling_ae, sop_classes, max_pdu,
      transfer_uids, roles)
  ok, err = tcp_send(sock, assoc_rq)
  if not ok then
    sock:close()
    return false, "SEND_FAILED", nil, nil, nmap.clock_ms() - t0
  end

  local resp
  ok, resp = recv_pdu(sock, timeout_s)
  local elapsed = nmap.clock_ms() - t0
  if not ok then
    sock:close()
    return false, resp, nil, nil, elapsed
  end

  local pdu_type = string.byte(resp, 1)
  if pdu_type == PDU_CODES.ASSOCIATE_ACCEPT then
    local ac_info = parse_assoc_ac(resp)
    if tls then ac_info.cert = get_cert(sock) end
    return true, sock, ac_info.pctxs, ac_info.max_pdu, elapsed, ac_info
  elseif pdu_type == PDU_CODES.ASSOCIATE_REJECT then
    sock:close()
    local result_v, source, reason = 0, 0, 0
    if #resp >= 10 then
      result_v = string.byte(resp, 8)
      source   = string.byte(resp, 9)
      reason   = string.byte(resp, 10)
    end
    return false,
      string.format("REJECT(result=%d,source=%d,reason=%d)", result_v, source,
          reason),
      nil, nil, elapsed
  elseif pdu_type == PDU_CODES.ABORT then
    sock:close()
    return false, "A-ABORT", nil, nil, elapsed
  else
    sock:close()
    return false,
      string.format("UNEXPECTED_PDU(0x%02X)", pdu_type),
      nil, nil, elapsed
  end
end

--- Send A-RELEASE-RQ and wait for A-RELEASE-RP (best-effort).
function do_release(sock, timeout_s)
  local rel_rq = string.pack(">B B I4 I4",
    PDU_CODES.RELEASE_REQUEST, 0x00, 0x04, 0x00000000)
  sock:set_timeout((timeout_s or 3) * 1000)
  tcp_send(sock, rel_rq)
  pcall(function() sock:receive() end)
  sock:close()
end

--- Find the first accepted presentation context ID from a pctx map.
-- @param pctxs  Table from parse_assoc_ac {pctx_id -> {accepted,
-- transfer_syntax}}
-- @return pctx_id (int) or nil
function pick_accepted_pctx(pctxs)
  local sorted = {}
  for pid, _ in pairs(pctxs) do sorted[#sorted + 1] = pid end
  table.sort(sorted)
  for _, pid in ipairs(sorted) do
    if pctxs[pid].accepted then return pid end
  end
  return nil
end

--- Get the negotiated transfer syntax for an accepted presentation context.
-- @param pctxs    Table from parse_assoc_ac
-- @param pctx_id  Presentation context ID
-- @return Transfer syntax UID string, or nil
function get_accepted_ts(pctxs, pctx_id)
  if pctxs and pctx_id and pctxs[pctx_id] and pctxs[pctx_id].accepted then
    return pctxs[pctx_id].transfer_syntax
  end
  return nil
end

-----------------------------------------------------------------------
-- 13. FILE META / DATASET EXTRACTION
-----------------------------------------------------------------------

--- Extract the DICOM dataset from a raw .dcm file.
-- Strips 128-byte preamble + "DICM" prefix and File Meta Information.
-- @param filepath Path to .dcm file
-- @return dataset_bytes, sop_class_uid, sop_instance_uid, transfer_syntax_uid,
-- err
function read_dcm_dataset(filepath)
  local data, err = read_file(filepath)
  if not data then
    return nil, nil, nil, nil, err
  end

  if #data >= 132 and data:sub(129, 132) == "DICM" then
    local pos = 133
    local sop_class    = ""
    local sop_instance = ""
    local ts_uid       = TRANSFER_SYNTAX.EXPLICIT_LE

    -- Parse File Meta Information (always Explicit VR LE, group 0002)
    while pos <= #data - 8 do
      local grp  = string.unpack("<I2", data, pos)
      if grp ~= 0x0002 then
        return data:sub(pos), sop_class, sop_instance, ts_uid
      end
      local elem = string.unpack("<I2", data, pos + 2)
      local vr   = data:sub(pos + 4, pos + 5)
      local vlen, next_pos
      if LONG_VRS[vr] then
        vlen     = string.unpack("<I4", data, pos + 8)
        next_pos = pos + 12 + vlen
      else
        vlen     = string.unpack("<I2", data, pos + 6)
        next_pos = pos + 8 + vlen
      end
      local val_start = next_pos - vlen
      local val = data:sub(val_start, next_pos - 1)

      if grp == 0x0002 and elem == 0x0002 then
        sop_class = val:gsub("%z", ""):gsub("%s+$", "")
      elseif grp == 0x0002 and elem == 0x0003 then
        sop_instance = val:gsub("%z", ""):gsub("%s+$", "")
      elseif grp == 0x0002 and elem == 0x0010 then
        ts_uid = val:gsub("%z", ""):gsub("%s+$", "")
      end
      pos = next_pos
    end
    return data:sub(pos), sop_class, sop_instance, ts_uid
  else
    stdnse.debug2("No DICM magic in %s — sending raw file as dataset",
        filepath)
    return data, SOP_CLASS.CT_IMAGE_STORAGE, generate_fake_uid(),
        TRANSFER_SYNTAX.EXPLICIT_LE
  end
end

return _ENV
