description = [[
Lists DICOM objects stored on a PACS server using C-FIND queries at the
STUDY, SERIES, and IMAGE levels.  Results are displayed hierarchically
showing patients, studies, series and (optionally) individual instances.

The script negotiates an A-ASSOCIATE with the Study Root Query/Retrieve
Information Model — FIND SOP Class and issues C-FIND-RQ at each level.
It can also retrieve (download) individual DICOM instances using C-GET
when the --script-args save option is set.

This is a read-only, non-intrusive reconnaissance script suitable for
auditing what data is accessible on a DICOM endpoint without proper
access controls.

NOTE: Many PACS servers accept C-FIND from any associated SCU with no
authentication.  If the server returns results, it means patient data
is exposed to any host that can reach the DICOM port — a critical
finding for security assessments.

INSTALLATION:
  This script requires the enhanced dicom.lua library.
  Copy dicom.lua to your Nmap nselib/ directory:
    cp dicom.lua /usr/share/nmap/nselib/dicom.lua
]]

---
-- @usage
-- nmap -p 4242 --script dicom-cfind-ls <target>
--
-- @usage
-- nmap -p 4242 --script dicom-cfind-ls \
--   --script-args 'dicom-cfind-ls.called_ae=ORTHANC,dicom-cfind-ls.calling_ae=LAUNCHER' <target>
--
-- @usage
-- nmap -p 4242 --script dicom-cfind-ls \
--   --script-args 'dicom-cfind-ls.level=SERIES,dicom-cfind-ls.max_results=50' <target>
--
-- @usage  (download all matching instances to disk)
-- nmap -p 4242 --script dicom-cfind-ls \
--   --script-args 'dicom-cfind-ls.save=/tmp/dicom-dump' <target>
--
-- @args dicom-cfind-ls.called_ae   Target AE Title (default: "ANY-SCP")
-- @args dicom-cfind-ls.calling_ae  Our AE Title (default: "FINDSCU")
-- @args dicom-cfind-ls.level       Deepest query level: PATIENT, STUDY,
-- SERIES, IMAGE (default: "IMAGE")
-- @args dicom-cfind-ls.max_results Maximum results per level (default: 100)
-- @args dicom-cfind-ls.timeout     Response timeout in seconds (default: 10)
-- @args dicom-cfind-ls.max_pdu     Max PDU Length in bytes (default: 16384)
-- @args dicom-cfind-ls.patient_name  Filter by PatientName (wildcard *
-- allowed, default: "*")
-- @args dicom-cfind-ls.patient_id    Filter by PatientID (default: all)
-- @args dicom-cfind-ls.study_date    Filter by StudyDate (YYYYMMDD or range,
-- default: all)
-- @args dicom-cfind-ls.modality      Filter by Modality (CT, MR, etc.,
-- default: all)
-- @args dicom-cfind-ls.save         Directory to save DICOM files via C-GET
-- (default: disabled)
-- @args dicom-cfind-ls.info_model   Q/R Information Model: "study" or
-- "patient" (default: "study")
-- @args dicom-cfind-ls.full         Include extended return-key tags in
-- queries (StudyDate,
--                                   AccessionNumber, ModalitiesInStudy, etc.).
-- Some PACS servers
--                                   abort on unsupported tags; when set the
-- script auto-retries
--                                   with minimal tags on A-ABORT.  Default:
-- off (lean query).
--
-- @output
-- PORT     STATE SERVICE
-- 4242/tcp open  dicom
-- | dicom-cfind-ls:
-- |   DICOM Q/R Results (Study Root, FIND):
-- |   Patients: 3  Studies: 5  Series: 12  Instances: 47
-- |
-- |   [Patient] John Doe (ID: PATIENT001)
-- |     [Study] 2025-01-15 - CT Abdomen (1.2.3.4.5.1)
-- |       [Series] CT - 128 images (1.2.3.4.5.1.1)
-- |       [Series] CT - 64 images (1.2.3.4.5.1.2)
-- |     [Study] 2025-03-20 - MR Brain (1.2.3.4.5.2)
-- |       [Series] MR - 256 images (1.2.3.4.5.2.1)
-- |   [Patient] Jane Smith (ID: PATIENT002)
-- |     [Study] 2025-02-10 - CR Chest (1.2.3.4.5.3)
-- |       [Series] CR - 2 images (1.2.3.4.5.3.1)
-- |
-- |   WARNING: Patient data accessible without authentication
-- |_  Saved 47 instances to /tmp/dicom-dump/
---

author   = "Paulino Calderon <paulino@calderonpale.com>"
license  = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local shortport = require "shortport"
local stdnse    = require "stdnse"
local nmap      = require "nmap"
local string    = require "string"
local table     = require "table"
local math      = require "math"
local dicom     = require "dicom"

-- Verify we have the enhanced library (not Nmap's built-in minimal version)
assert(dicom.explicit_elem,
  "\n\n  dicom-cfind-ls requires the enhanced dicom.lua library.\n" ..
  "  Copy dicom.lua to your Nmap nselib/ directory:\n" ..
  "    cp dicom.lua /usr/share/nmap/nselib/dicom.lua\n")

portrule = shortport.port_or_service(
  {104, 2345, 2761, 2762, 4242, 11112}, "dicom", "tcp", "open")

-----------------------------------------------------------------------
-- HELPERS
-----------------------------------------------------------------------

local function get_arg(key, default)
  return stdnse.get_script_args("dicom-cfind-ls." .. key) or default
end

-----------------------------------------------------------------------
-- C-FIND QUERY
-----------------------------------------------------------------------

--- Hex-dump helper for debug level >= 2.
local function hexdump(label, data)
  if not data or #data == 0 then return end
  local parts = {}
  for i = 1, #data do
    parts[#parts + 1] = string.format("%02X", string.byte(data, i))
    if i % 32 == 0 then parts[#parts + 1] = "\n  " end
  end
  stdnse.debug2("%s (%d bytes):\n  %s", label, #data, table.concat(parts, " "))
end

--- Perform a single C-FIND association + query cycle.
-- Opens an association, sends C-FIND-RQ + dataset, collects PENDING
-- responses until SUCCESS or error, then releases.
--
-- @param host         Nmap host object
-- @param port         Nmap port object
-- @param called_ae    Called AE Title
-- @param calling_ae   Calling AE Title
-- @param find_sop     SOP Class UID for the Q/R FIND model
-- @param query_tags   List of {group, elem, vr, value} for the query dataset
-- @param level        Q/R level string ("STUDY", "SERIES", "IMAGE")
-- @param max_pdu      Max PDU length
-- @param timeout_s    DIMSE timeout in seconds
-- @param max_results  Max results to collect
-- @return ok (bool), results_or_err (list of tag tables, or error string)
local function do_cfind_once(host, port, called_ae, calling_ae, find_sop,
                             query_tags, level, max_pdu, timeout_s,
                                 max_results)
  -- Associate
  local ok, sock, pctxs, server_max_pdu, elapsed =
    dicom.do_associate(host, port, called_ae, calling_ae, {find_sop}, max_pdu,
        timeout_s)
  if not ok then
    return false, sock
  end

  local pctx_id = dicom.pick_accepted_pctx(pctxs)
  if not pctx_id then
    dicom.do_release(sock, 3)
    return false, "No accepted presentation context for C-FIND"
  end

  -- Determine the negotiated transfer syntax for dataset encoding
  local ts = dicom.get_accepted_ts(pctxs, pctx_id)
      or dicom.TRANSFER_SYNTAX.EXPLICIT_LE
  local eff_max = math.min(server_max_pdu or max_pdu, max_pdu)

  stdnse.debug1("C-FIND: pctx_id=%d  TS=%s  max_pdu=%d  tags=%d",
    pctx_id, ts, eff_max, #query_tags)

  -- Build command set (always Implicit VR LE) and dataset (negotiated TS)
  local cmd_bytes = dicom.build_cfind_rq(1, find_sop)
  local ds_bytes  = dicom.build_cfind_dataset(level, query_tags, ts)

  hexdump("C-FIND command set", cmd_bytes)
  hexdump("C-FIND dataset", ds_bytes)

  -- Send command + dataset via send_dimse (combines into single P-DATA-TF PDU)
  ok = dicom.send_dimse(sock, pctx_id, cmd_bytes, ds_bytes, eff_max)
  if not ok then
    sock:close()
    return false, "Failed to send C-FIND DIMSE message"
  end

  -- Collect responses
  local results = {}
  local count = 0
  local carry = ""  -- carry buffer for leftover bytes between recv_dimse calls

  while true do
    local pdu_type, cmd_elems, resp_ds_bytes, raw
    pdu_type, cmd_elems, resp_ds_bytes, raw, carry =
      dicom.recv_dimse(sock, timeout_s, carry)

    if not pdu_type then
      stdnse.debug1("C-FIND recv error: %s", tostring(raw))
      break
    end

    if pdu_type == dicom.PDU_CODES.ABORT then
      stdnse.debug1("C-FIND: received A-ABORT (sent %d tags at level %s)",
          #query_tags, level)
      hexdump("A-ABORT PDU", raw)
      sock:close()
      if #results > 0 then return true, results end
      return false, "A-ABORT"
    end

    if pdu_type ~= dicom.PDU_CODES.DATA then
      stdnse.debug1("C-FIND: unexpected PDU type 0x%02X", pdu_type)
      break
    end

    -- Parse response status
    local cfind_status = 0xFFFF
    if cmd_elems and cmd_elems["0000,0900"] then
      cfind_status = cmd_elems["0000,0900"].value
    end

    if cfind_status == dicom.STATUS.PENDING
       or cfind_status == dicom.STATUS.PENDING_WARN then
      -- Parse dataset with negotiated transfer syntax
      if #resp_ds_bytes > 0 then
        local ds_elems = dicom.parse_dataset(resp_ds_bytes, ts)
        if ds_elems then
          results[#results + 1] = ds_elems
          count = count + 1
          if count >= max_results then
            stdnse.debug1("C-FIND: max_results (%d) reached", max_results)
            break
          end
        end
      end
    elseif cfind_status == dicom.STATUS.SUCCESS then
      stdnse.debug1("C-FIND: SUCCESS — %d results", #results)
      break
    else
      stdnse.debug1("C-FIND: status 0x%04X — stopping", cfind_status)
      break
    end
  end

  dicom.do_release(sock, 3)
  return true, results
end

--- Perform a C-FIND query with automatic fallback to minimal tags.
-- If the full query gets A-ABORT, retries with just QueryRetrieveLevel +
-- PatientName (the same minimal set that DCMTK findscu uses by default).
-- This handles servers that abort on unsupported return-key tags.
--
-- @param host         Nmap host object
-- @param port         Nmap port object
-- @param called_ae    Called AE Title
-- @param calling_ae   Calling AE Title
-- @param find_sop     SOP Class UID for the Q/R FIND model
-- @param query_tags   List of {group, elem, vr, value} for the query dataset
-- @param level        Q/R level string ("STUDY", "SERIES", "IMAGE")
-- @param max_pdu      Max PDU length
-- @param timeout_s    DIMSE timeout in seconds
-- @param max_results  Max results to collect
-- @param minimal_tags Optional fallback tag list (nil = auto-generate from
-- query_tags)
-- @return ok (bool), results_or_err (list of tag tables, or error string),
-- used_fallback (bool)
local function do_cfind(host, port, called_ae, calling_ae, find_sop,
                        query_tags, level, max_pdu, timeout_s, max_results,
                        minimal_tags)
  local ok, results = do_cfind_once(host, port, called_ae, calling_ae,
    find_sop, query_tags, level, max_pdu, timeout_s, max_results)

  if ok then
    return true, results, false
  end

  -- If we got A-ABORT and have more than 2 tags, retry with minimal set
  if results == "A-ABORT" and #query_tags > 2 then
    if not minimal_tags then
      -- Build minimal: keep only tags that have a non-empty filter value,
      -- plus PatientName=* as a universal wildcard match key
      minimal_tags = {}
      for _, t in ipairs(query_tags) do
        if t.value and t.value ~= "" then
          minimal_tags[#minimal_tags + 1] = t
        end
      end
      -- Ensure at least PatientName is present
      local has_pn = false
      for _, t in ipairs(minimal_tags) do
        if t.group == 0x0010 and t.elem == 0x0010 then has_pn = true
        break end
      end
      if not has_pn then
        minimal_tags[#minimal_tags + 1] = {group=0x0010, elem=0x0010, vr="PN",
            value="*"}
      end
    end

    stdnse.debug1("C-FIND: A-ABORT with %d tags; retrying with %d minimal" ..
                  " tags",
      #query_tags, #minimal_tags)

    ok, results = do_cfind_once(host, port, called_ae, calling_ae,
      find_sop, minimal_tags, level, max_pdu, timeout_s, max_results)
    if ok then
      return true, results, true
    end
  end

  return false, results, false
end

-----------------------------------------------------------------------
-- C-GET RETRIEVAL
-----------------------------------------------------------------------

--- Download DICOM instances via C-GET.
-- Handles incoming C-STORE sub-operations from the SCP and saves files.
local function do_cget(host, port, called_ae, calling_ae, get_sop,
                       storage_sops, query_tags, level, max_pdu,
                       timeout_s, save_dir)
  local all_sops = {get_sop}
  for _, sop in ipairs(storage_sops) do
    all_sops[#all_sops + 1] = sop
  end

  local ok, sock, pctxs, server_max_pdu, elapsed =
    dicom.do_associate(host, port, called_ae, calling_ae, all_sops, max_pdu,
        timeout_s)
  if not ok then
    return 0, 0, sock
  end

  local pctx_id = dicom.pick_accepted_pctx(pctxs)
  if not pctx_id then
    dicom.do_release(sock, 3)
    return 0, 0, "No accepted presentation context for C-GET"
  end

  local ts = dicom.get_accepted_ts(pctxs, pctx_id)
      or dicom.TRANSFER_SYNTAX.EXPLICIT_LE
  local eff_max = math.min(server_max_pdu or max_pdu, max_pdu)

  -- Build and send C-GET-RQ
  local cmd_bytes = dicom.build_cget_rq(1, get_sop)
  local ds_bytes  = dicom.build_cfind_dataset(level, query_tags, ts)

  dicom.send_dimse(sock, pctx_id, cmd_bytes, ds_bytes, eff_max)

  local saved, errors = 0, 0
  local carry = ""  -- carry buffer for leftover bytes between recv_dimse calls

  while true do
    local pdu_type, cmd_elems, resp_ds, raw
    pdu_type, cmd_elems, resp_ds, raw, carry =
      dicom.recv_dimse(sock, timeout_s, carry)

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
      -- Incoming C-STORE sub-operation: save file to disk
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

      local filename = sop_instance:gsub("[^%w%.]", "_") .. ".dcm"
      local filepath = save_dir:gsub("[/\\]+$", "") .. "/" .. filename
      local wok, werr = dicom.write_file(filepath, resp_ds)
      if wok then
        saved = saved + 1
        stdnse.debug1("C-GET: saved %s (%d bytes)", filename, #resp_ds)
      else
        errors = errors + 1
        stdnse.debug1("C-GET: save failed: %s", tostring(werr))
      end

      -- Send C-STORE-RSP
      local rsp_cmd = dicom.build_cstore_rsp(msg_id_rsp, sop_class,
          sop_instance)
      dicom.send_dimse(sock, pctx_id, rsp_cmd, nil, eff_max)

    elseif cmd_field == dicom.COMMAND_FIELD.C_GET_RSP then
      local cget_status = 0xFFFF
      if cmd_elems["0000,0900"] then
        cget_status = cmd_elems["0000,0900"].value
      end
      if cget_status ~= dicom.STATUS.PENDING
         and cget_status ~= dicom.STATUS.PENDING_WARN then
        stdnse.debug1("C-GET: final RSP status 0x%04X", cget_status)
        break
      end
    else
      stdnse.debug1("C-GET: unknown command field 0x%04X", cmd_field)
    end
  end

  dicom.do_release(sock, 3)
  return saved, errors
end

-----------------------------------------------------------------------
-- MAIN ACTION
-----------------------------------------------------------------------
action = function(host, port)
  local called_ae   = get_arg("called_ae",    "ANY-SCP")
  local calling_ae  = get_arg("calling_ae",   "FINDSCU")
  local max_level   = get_arg("level",        "IMAGE"):upper()
  local max_results = tonumber(get_arg("max_results", "100"))
  local timeout_s   = tonumber(get_arg("timeout",     "10"))
  local max_pdu     = tonumber(get_arg("max_pdu",     "16384"))
  local pat_name    = get_arg("patient_name", "*")
  local pat_id      = get_arg("patient_id",   "")
  local study_date  = get_arg("study_date",   "")
  local modality    = get_arg("modality",     "")
  local save_dir    = get_arg("save",         nil)
  local info_model  = get_arg("info_model",   "study"):lower()

  -- Select Q/R SOP Classes based on information model
  local find_sop, get_sop
  if info_model == "patient" then
    find_sop = dicom.SOP_CLASS.PATIENT_ROOT_QR_FIND
    get_sop  = dicom.SOP_CLASS.PATIENT_ROOT_QR_GET
  else
    find_sop = dicom.SOP_CLASS.STUDY_ROOT_QR_FIND
    get_sop  = dicom.SOP_CLASS.STUDY_ROOT_QR_GET
  end

  local out = stdnse.output_table()

  -- ── C-ECHO probe ─────────────────────────────────────────────────
  -- Quick DIMSE connectivity check.  If C-ECHO fails, C-FIND will too.
  -- This distinguishes encoding/framing problems from access-control
  -- restrictions (server may accept association but disallow FIND).
  do
    local echo_ok, echo_sock, echo_pctxs =
      dicom.do_associate(host, port, called_ae, calling_ae,
        {dicom.SOP_CLASS.VERIFICATION}, max_pdu, timeout_s)
    if echo_ok then
      local echo_pctx_id = dicom.pick_accepted_pctx(echo_pctxs)
      if echo_pctx_id then
        local echo_cmd = dicom.build_cecho_rq(1)
        dicom.send_dimse(echo_sock, echo_pctx_id, echo_cmd, nil, max_pdu)
        local pdu_type, cmd_elems = dicom.recv_dimse(echo_sock, timeout_s)
        if pdu_type == dicom.PDU_CODES.DATA then
          local echo_status = 0xFFFF
          if cmd_elems and cmd_elems["0000,0900"] then
            echo_status = cmd_elems["0000,0900"].value
          end
          if echo_status == dicom.STATUS.SUCCESS then
            stdnse.debug1("C-ECHO: SUCCESS — DIMSE connectivity verified")
          else
            stdnse.debug1("C-ECHO: unexpected status 0x%04X", echo_status)
          end
        elseif pdu_type == dicom.PDU_CODES.ABORT then
          stdnse.debug1("C-ECHO: A-ABORT — server rejects DIMSE from %s",
              calling_ae)
          out["Error"] = string.format(
            "C-ECHO aborted — server rejects DIMSE from calling AE '%s'. " ..
            "Check server's modality configuration (AllowEcho, AllowFind).",
            calling_ae)
          dicom.do_release(echo_sock, 3)
          return out
        end
      end
      dicom.do_release(echo_sock, 3)
    else
      stdnse.debug1("C-ECHO: association failed: %s", tostring(echo_sock))
    end
  end

  -- ── STUDY-level C-FIND ───────────────────────────────────────────
  -- Core tags: always sent (match keys + essential return keys).
  -- These mirror what DCMTK findscu sends and work universally.
  local study_tags = {
    {group=0x0010, elem=0x0010, vr="PN", value=pat_name},
        -- PatientName (match)
    {group=0x0010, elem=0x0020, vr="LO", value=pat_id},
        -- PatientID (match/return)
    {group=0x0020, elem=0x000D, vr="UI", value=""},
        -- StudyInstanceUID (return)
  }

  -- Additional return keys: requested when user sets level or uses filters.
  -- Some PACS (e.g. certain Orthanc configs) abort on unsupported tags,
  -- so these are added only with the "full" flag or specific filter args,
  -- and we fall back to core-only if the server aborts.
  local want_extra = (get_arg("full", nil) ~= nil)
                     or study_date ~= ""
                     or modality ~= ""

  if want_extra then
    -- Insert before PatientName to keep ascending (group,elem) order.
    -- encode_dataset sorts anyway, but helps readability.
    study_tags[#study_tags + 1] = {group=0x0008, elem=0x0020, vr="DA",
        value=study_date} -- StudyDate
    study_tags[#study_tags + 1] = {group=0x0008, elem=0x0030, vr="TM",
        value=""} -- StudyTime
    study_tags[#study_tags + 1] = {group=0x0008, elem=0x0050, vr="SH",
        value=""} -- AccessionNumber
    study_tags[#study_tags + 1] = {group=0x0008, elem=0x0061, vr="CS",
        value=modality} -- ModalitiesInStudy (0008,0061 not 0008,0060)
    study_tags[#study_tags + 1] = {group=0x0008, elem=0x1030, vr="LO",
        value=""} -- StudyDescription
    study_tags[#study_tags + 1] = {group=0x0010, elem=0x0030, vr="DA",
        value=""} -- PatientBirthDate
    study_tags[#study_tags + 1] = {group=0x0010, elem=0x0040, vr="CS",
        value=""} -- PatientSex
    study_tags[#study_tags + 1] = {group=0x0020, elem=0x0010, vr="SH",
        value=""} -- StudyID
  end

  local ok, studies, used_fallback = do_cfind(host, port, called_ae,
      calling_ae,
    find_sop, study_tags, "STUDY", max_pdu, timeout_s, max_results)
  if not ok then
    if studies == "A-ABORT" then
      out["Error"] = string.format(
        "C-FIND aborted by server (A-ABORT source=0). " ..
        "C-ECHO may succeed while C-FIND is denied. " ..
        "If using Orthanc, check that calling AE '%s' has AllowFind=true " ..
        "in /etc/orthanc/orthanc.json DicomModalities section. " ..
        "Try: calling_ae=ORTHANC or calling_ae=FINDSCU",
        calling_ae)
    else
      out["Error"] = "C-FIND STUDY failed: " .. tostring(studies)
    end
    return out
  end
  if used_fallback then
    stdnse.verbose1("C-FIND: server aborted with extended tags; used" ..
                    " minimal query")
  end

  if #studies == 0 then
    out["Result"] = "No studies found (server may require specific AE title" ..
                    " or filter)"
    return out
  end

  -- ── Build patient/study tree ─────────────────────────────────────
  local patients = {}
  local patient_order = {}
  local study_count = 0
  local series_count = 0
  local instance_count = 0

  for _, s in ipairs(studies) do
    local pid   = s["0010,0020"] or "UNKNOWN"
    local pname = s["0010,0010"] or "UNKNOWN"
    local psex  = s["0010,0040"] or ""
    local pdob  = s["0010,0030"] or ""
    local suid  = s["0020,000D"] or ""
    local sdate = s["0008,0020"] or ""
    local stime = s["0008,0030"] or ""
    local sdesc = s["0008,1030"] or ""
    local smod  = s["0008,0060"] or ""
    local sid   = s["0020,0010"] or ""
    local accno = s["0008,0050"] or ""

    if not patients[pid] then
      patients[pid] = { name=pname, sex=psex, dob=pdob, studies={} }
      patient_order[#patient_order + 1] = pid
    end

    patients[pid].studies[#patients[pid].studies + 1] = {
      uid         = suid,
      date        = sdate,
      time        = stime,
      description = sdesc,
      modality    = smod,
      study_id    = sid,
      accession   = accno,
      series      = {},
    }
    study_count = study_count + 1
  end

  -- ── SERIES-level C-FIND (if requested) ───────────────────────────
  if max_level == "SERIES" or max_level == "IMAGE" then
    for _, pid in ipairs(patient_order) do
      for _, study in ipairs(patients[pid].studies) do
        if study.uid == "" then goto next_study end

        local series_tags = {
          {group=0x0008, elem=0x0060, vr="CS", value=""},          -- Modality
          {group=0x0008, elem=0x103E, vr="LO", value=""}, -- SeriesDescription
          {group=0x0020, elem=0x000D, vr="UI", value=study.uid},
              -- StudyInstanceUID
          {group=0x0020, elem=0x000E, vr="UI", value=""}, -- SeriesInstanceUID
          {group=0x0020, elem=0x0011, vr="IS", value=""}, -- SeriesNumber
        }

        local sok, series_list = do_cfind(host, port, called_ae, calling_ae,
                                          find_sop, series_tags, "SERIES",
                                          max_pdu, timeout_s, max_results)
        if sok and series_list then
          for _, sr in ipairs(series_list) do
            study.series[#study.series + 1] = {
              uid         = sr["0020,000E"] or "",
              modality    = sr["0008,0060"] or "",
              description = sr["0008,103E"] or "",
              number      = sr["0020,0011"] or "",
              instances   = {},
              num_images  = 0,
            }
            series_count = series_count + 1
          end
        end
        ::next_study::
      end
    end
  end

  -- ── IMAGE-level C-FIND (if requested) ────────────────────────────
  if max_level == "IMAGE" then
    for _, pid in ipairs(patient_order) do
      for _, study in ipairs(patients[pid].studies) do
        for _, series in ipairs(study.series) do
          if series.uid == "" then goto next_series end

          local img_tags = {
            {group=0x0008, elem=0x0016, vr="UI", value=""}, -- SOPClassUID
            {group=0x0008, elem=0x0018, vr="UI", value=""}, -- SOPInstanceUID
            {group=0x0020, elem=0x000D, vr="UI", value=study.uid},
                -- StudyInstanceUID
            {group=0x0020, elem=0x000E, vr="UI", value=series.uid},
                -- SeriesInstanceUID
            {group=0x0020, elem=0x0013, vr="IS", value=""}, -- InstanceNumber
          }

          local iok, imgs = do_cfind(host, port, called_ae, calling_ae,
                                     find_sop, img_tags, "IMAGE",
                                     max_pdu, timeout_s, max_results)
          if iok and imgs then
            for _, img in ipairs(imgs) do
              series.instances[#series.instances + 1] = {
                sop_class    = img["0008,0016"] or "",
                sop_instance = img["0008,0018"] or "",
                number       = img["0020,0013"] or "",
              }
              instance_count = instance_count + 1
            end
            series.num_images = #series.instances
          end
          ::next_series::
        end
      end
    end
  end

  -- ── C-GET DOWNLOAD (if --save) ───────────────────────────────────
  local saved_total = 0
  if save_dir and max_level == "IMAGE" and instance_count > 0 then
    os.execute("mkdir -p " .. save_dir .. " 2>/dev/null")
    os.execute("mkdir " .. save_dir .. " 2>nul")

    -- Collect unique storage SOP classes
    local sop_set = {}
    local storage_sops = {}
    for _, pid in ipairs(patient_order) do
      for _, study in ipairs(patients[pid].studies) do
        for _, series in ipairs(study.series) do
          for _, inst in ipairs(series.instances) do
            if inst.sop_class ~= "" and not sop_set[inst.sop_class] then
              sop_set[inst.sop_class] = true
              storage_sops[#storage_sops + 1] = inst.sop_class
            end
          end
        end
      end
    end

    -- Retrieve per-study via C-GET
    for _, pid in ipairs(patient_order) do
      for _, study in ipairs(patients[pid].studies) do
        if study.uid == "" then goto next_dl_study end

        local get_tags = {
          {group=0x0020, elem=0x000D, vr="UI", value=study.uid},
        }
        local nsaved, nerrors = do_cget(host, port, called_ae, calling_ae,
                                        get_sop, storage_sops, get_tags,
                                        "STUDY", max_pdu, timeout_s, save_dir)
        saved_total = saved_total + nsaved
        if nsaved > 0 then
          stdnse.verbose1("C-GET: saved %d instances for study %s", nsaved,
              study.uid)
        end
        ::next_dl_study::
      end
    end
  end

  -- ── FORMAT OUTPUT ────────────────────────────────────────────────
  local model_name = info_model == "patient" and "Patient Root" or "Study Root"
  out["DICOM Q/R Results"] = string.format("(%s, FIND)", model_name)
  out["Patients"] = #patient_order
  out["Studies"]  = study_count
  if series_count > 0 then out["Series"]    = series_count end
  if instance_count > 0 then out["Instances"] = instance_count end

  local lines = {}
  for _, pid in ipairs(patient_order) do
    local p = patients[pid]
    local pline = string.format("[Patient] %s (ID: %s)", p.name, pid)
    if p.sex ~= "" then pline = pline .. " " .. p.sex end
    if p.dob ~= "" then pline = pline .. " DOB:" .. p.dob end
    lines[#lines + 1] = pline

    for _, study in ipairs(p.studies) do
      local sline = string.format("  [Study] %s",
        study.date ~= "" and study.date or "no-date")
      if study.description ~= "" then
        sline = sline .. " - " .. study.description
      end
      if study.modality ~= "" then
        sline = sline .. " (" .. study.modality .. ")"
      end
      if study.uid ~= "" then sline = sline .. " " .. study.uid end
      lines[#lines + 1] = sline

      for _, series in ipairs(study.series) do
        local srline = string.format("    [Series] #%s %s",
          series.number ~= "" and series.number or "?",
          series.modality)
        if series.description ~= "" then
          srline = srline .. " - " .. series.description
        end
        if series.num_images > 0 then
          srline = srline .. string.format(" (%d images)", series.num_images)
        end
        if series.uid ~= "" then srline = srline .. " " .. series.uid end
        lines[#lines + 1] = srline

        for ii, inst in ipairs(series.instances) do
          if ii <= 5 then
            stdnse.debug1("      [Instance] #%s %s (%s)",
              tostring(inst.number), tostring(inst.sop_instance),
                  tostring(inst.sop_class))
          elseif ii == 6 then
            stdnse.debug1("      ... and %d more instances",
                #series.instances - 5)
          end
        end
      end
    end
  end

  out["Listing"] = lines

  if #patient_order > 0 then
    out["WARNING"] = "Patient data accessible without authentication"
  end

  if saved_total > 0 then
    out["Saved"] = string.format("%d instances to %s", saved_total, save_dir)
  elseif save_dir and instance_count == 0 then
    out["Save"] = "No instances found to download"
  elseif save_dir and max_level ~= "IMAGE" then
    out["Save"] = "Set level=IMAGE to enable C-GET download"
  end

  nmap.set_port_state(host, port, "open")
  port.version.name = "dicom"
  port.version.product = "DICOM SCP"
  nmap.set_port_version(host, port, "hardmatched")

  return out
end
