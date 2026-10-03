local shortport = require "shortport"
local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
local math = require "math"
local os = require "os"
local dicom = require "dicom"

description = [[
Tests whether a DICOM archive accepts an unauthenticated C-STORE -- i.e.
whether any client that can associate can write a new image (SOP Instance)
into the PACS/VNA.

Most DICOM Storage SCPs authorise storage by AE Title alone, or not at all, so
an attacker who can reach the DIMSE port can often inject arbitrary instances:
a decoy study attached to a real patient, a tampered image, or a payload that
exercises a downstream viewer. This is the native-protocol counterpart to
dicomweb-enum's STOW-RS surface and the DICOM analogue of hl7-inject.

The script negotiates a Storage presentation context (as an SCU), builds one
clearly-synthetic Secondary Capture image -- an obviously fake patient
(ZZZTEST), a "SAFE TO DELETE" study description, a tiny 4x4 black frame, and
UIDs under a rootless 2.25 arc -- and issues a single C-STORE. It reports
whether the archive accepted the store (C-STORE-RSP 0x0000 / a warning status),
refused it, or refused the association outright, and prints the UIDs of the
stored instance so an operator can locate and delete it.

This is a HIGHLY INTRUSIVE, WRITING test: on success it creates a real (though
clearly-marked) object in the target archive. Run it only against systems you
are explicitly authorised to test, and clean up the injected instance
afterwards using the UIDs it reports.
]]

---
-- @usage
-- nmap -p104,4242,11112 --script dicom-store-inject <target>
--
-- @usage
-- nmap -p4242 --script dicom-store-inject \
--   --script-args 'dicom-store-inject.called_ae=ORTHANC' <target>
--
-- @usage
-- nmap -p2762 --script dicom-store-inject \
--   --script-args 'dicom.tls=true' <target>
--
-- @args dicom-store-inject.called_ae    Called AE Title. Default: "ANY-SCP"
-- @args dicom-store-inject.calling_ae   Calling AE Title. Default: "NMAP-STORE"
-- @args dicom-store-inject.patient_id   PatientID (0010,0020) to write.
--                                       Default: "NMAP-STOREINJECT"
-- @args dicom-store-inject.patient_name PatientName (0010,0010) to write.
--                                       Default: "ZZZTEST^NMAP^STORE^INJECT"
-- @args dicom-store-inject.sop_class    Storage SOP Class UID to propose.
--                                       Default: Secondary Capture
-- @args dicom-store-inject.uid_root     Root for generated UIDs.
--                                       Default: "2.25" (rootless UUID arc)
-- @args dicom-store-inject.timeout      Association/response timeout (seconds).
--                                       Default: 10
-- @args dicom-store-inject.max_pdu      Max PDU length. Default: 16384
-- @args dicom.tls                       Force transport for the DICOM suite:
--                                       "true" (TLS), "false" (plaintext),
--                                       unset = plaintext.
--
-- @output
-- PORT     STATE SERVICE
-- 4242/tcp open  dicom
-- | dicom-store-inject:
-- |   Association: accepted
-- |   Transfer syntax: 1.2.840.10008.1.2.1 (Explicit VR Little Endian)
-- |   C-STORE status: 0x0000 (Success)
-- |   Result: ACCEPTED - the archive stored the injected instance
-- |   Injected instance (delete these to clean up):
-- |     SOP Instance UID:   2.25.184467...3.1.1.1
-- |     Study Instance UID: 2.25.184467...3.1
-- |     PatientID:          NMAP-STOREINJECT
-- |     PatientName:        ZZZTEST^NMAP^STORE^INJECT
-- |   VULNERABILITY: Unauthenticated DICOM C-STORE accepted
-- |_    An attacker who can associate can write arbitrary images
--
-- @xmloutput
-- <elem key="association">accepted</elem>
-- <elem key="cstore_status">0x0000</elem>
-- <elem key="result">ACCEPTED</elem>
-- <elem key="sop_instance_uid">2.25.184467...3.1.1.1</elem>
---

author = "Paulino Calderon <paulino@calderonpale.com>"
license = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive"}

portrule = shortport.port_or_service({104, 2762, 11112, 4242}, "dicom", "tcp",
  "open")

local function arg(name, default)
  return stdnse.get_script_args("dicom-store-inject." .. name) or default
end

--- Generate a set of related, clearly-synthetic UIDs under one random base.
-- @param root string UID root (e.g. "2.25")
-- @return study_uid, series_uid, instance_uid
local function make_uids(root)
  math.randomseed(os.time() + nmap.clock_ms())
  -- A large pseudo-random component keeps collisions with real UIDs unlikely
  -- while staying obviously machine-generated.
  local base = string.format("%s.%d%04d%04d", root,
    os.time() % 100000000, math.random(0, 9999), math.random(0, 9999))
  return base .. ".1", base .. ".1.1", base .. ".1.1.1"
end

--- Build the synthetic Secondary Capture dataset.
-- @return list of {group, elem, vr, value} for dicom.encode_dataset
local function build_sc_dataset(o, sop_instance_uid, study_uid, series_uid)
  local date = os.date("%Y%m%d")
  local time = os.date("%H%M%S")
  local marker = "NMAP DICOM-STORE-INJECT TEST - SAFE TO DELETE"
  -- 4x4, 8-bit MONOCHROME2, single black frame (16 bytes of pixel data).
  local pixels = string.rep("\0", 16)
  return {
    {group = 0x0008, elem = 0x0016, vr = "UI",
      value = dicom.SOP_CLASS.SECONDARY_CAPTURE},
    {group = 0x0008, elem = 0x0018, vr = "UI", value = sop_instance_uid},
    {group = 0x0008, elem = 0x0020, vr = "DA", value = date},
    {group = 0x0008, elem = 0x0030, vr = "TM", value = time},
    {group = 0x0008, elem = 0x0060, vr = "CS", value = "OT"},
    {group = 0x0008, elem = 0x0064, vr = "CS", value = "WSD"},
    {group = 0x0008, elem = 0x0070, vr = "LO", value = "NMAP"},
    {group = 0x0008, elem = 0x1030, vr = "LO", value = marker},
    {group = 0x0008, elem = 0x103E, vr = "LO", value = marker},
    {group = 0x0010, elem = 0x0010, vr = "PN", value = o.patient_name},
    {group = 0x0010, elem = 0x0020, vr = "LO", value = o.patient_id},
    {group = 0x0020, elem = 0x000D, vr = "UI", value = study_uid},
    {group = 0x0020, elem = 0x000E, vr = "UI", value = series_uid},
    {group = 0x0020, elem = 0x0011, vr = "IS", value = "1"},
    {group = 0x0020, elem = 0x0013, vr = "IS", value = "1"},
    {group = 0x0028, elem = 0x0002, vr = "US", value = 1},
    {group = 0x0028, elem = 0x0004, vr = "CS", value = "MONOCHROME2"},
    {group = 0x0028, elem = 0x0010, vr = "US", value = 4},
    {group = 0x0028, elem = 0x0011, vr = "US", value = 4},
    {group = 0x0028, elem = 0x0100, vr = "US", value = 8},
    {group = 0x0028, elem = 0x0101, vr = "US", value = 8},
    {group = 0x0028, elem = 0x0102, vr = "US", value = 7},
    {group = 0x0028, elem = 0x0103, vr = "US", value = 0},
    {group = 0x7FE0, elem = 0x0010, vr = "OB", value = pixels},
  }
end

local TS_NAMES = {
  ["1.2.840.10008.1.2"]   = "Implicit VR Little Endian",
  ["1.2.840.10008.1.2.1"] = "Explicit VR Little Endian",
}

--- Classify a C-STORE-RSP status code.
-- @return "accepted", "refused" or "failed", and a human label
local function classify_status(code)
  if code == 0x0000 then
    return "accepted", "Success"
  end
  local hi = code & 0xF000
  if hi == 0xB000 then
    -- Warning: coercion / elements discarded / data set mismatch. The instance
    -- is still stored.
    return "accepted", string.format("Warning 0x%04X (stored with warning)",
      code)
  end
  if (code & 0xFF00) == 0xA700 then
    return "refused", "Refused: Out of Resources"
  end
  if (code & 0xFF00) == 0xA900 then
    return "refused", "Error: Data Set does not match SOP Class"
  end
  if hi == 0xC000 then
    return "failed", "Error: Cannot understand / Processing failure"
  end
  return "failed", string.format("Unknown status 0x%04X", code)
end

action = function(host, port)
  local o = {
    called_ae   = arg("called_ae", "ANY-SCP"),
    calling_ae  = arg("calling_ae", "NMAP-STORE"),
    patient_id  = arg("patient_id", "NMAP-STOREINJECT"),
    patient_name = arg("patient_name", "ZZZTEST^NMAP^STORE^INJECT"),
  }
  local timeout_s = tonumber(arg("timeout", "10")) or 10
  local max_pdu = tonumber(arg("max_pdu", "16384")) or 16384
  local uid_root = arg("uid_root", "2.25")
  local sop_class = arg("sop_class", dicom.SOP_CLASS.SECONDARY_CAPTURE)

  local out = stdnse.output_table()

  -- Propose the chosen storage class (plus Secondary Capture as a fallback) on
  -- the standard uncompressed transfer syntaxes.
  local sop_list = {sop_class}
  if sop_class ~= dicom.SOP_CLASS.SECONDARY_CAPTURE then
    sop_list[#sop_list + 1] = dicom.SOP_CLASS.SECONDARY_CAPTURE
  end
  local transfer_uids = {
    dicom.TRANSFER_SYNTAX.EXPLICIT_LE,
    dicom.TRANSFER_SYNTAX.IMPLICIT_LE,
  }

  local ok, sock, pctxs = dicom.do_associate(host, port, o.called_ae,
    o.calling_ae, sop_list, max_pdu, timeout_s, transfer_uids)
  if not ok then
    out["Association"] = "refused (" .. tostring(sock) .. ")"
    out["Result"] =
      "Association refused - archive enforces association-level access control"
    out["Note"] =
      "The target rejected the association before any C-STORE was attempted"
    return out
  end
  out["Association"] = "accepted"

  local pctx_id = dicom.pick_accepted_pctx(pctxs)
  if not pctx_id then
    dicom.do_release(sock, timeout_s)
    out["Result"] =
      "No storage presentation context accepted - archive would not negotiate"
      .. " a Storage SCP role for the proposed SOP class"
    return out
  end
  local ts = pctxs[pctx_id].transfer_syntax or dicom.TRANSFER_SYNTAX.EXPLICIT_LE
  out["Transfer syntax"] = string.format("%s (%s)", ts,
    TS_NAMES[ts] or "unknown")

  -- Build and send the synthetic instance.
  local study_uid, series_uid, instance_uid = make_uids(uid_root)
  local tags = build_sc_dataset(o, instance_uid, study_uid, series_uid)
  local ds_bytes = dicom.encode_dataset(tags, ts)

  local cmd_bytes = dicom.build_cstore_rq(1, sop_class, instance_uid)
  local sent = dicom.send_dimse(sock, pctx_id, cmd_bytes, ds_bytes, max_pdu)
  if not sent then
    dicom.do_release(sock, timeout_s)
    out["Result"] = "C-STORE send failed (connection error)"
    return out
  end

  sock:set_timeout(timeout_s * 1000)
  local pdu_type, cmd_elems, _, raw_or_err = dicom.recv_dimse(sock, timeout_s)
  if not pdu_type then
    dicom.do_release(sock, timeout_s)
    out["Result"] = "No C-STORE-RSP received (" .. tostring(raw_or_err) .. ")"
    return out
  end
  if pdu_type == dicom.PDU_CODES.ABORT then
    out["Result"] = "Server sent A-ABORT in response to the C-STORE"
    return out
  end

  local status_code = 0xFFFF
  if cmd_elems and cmd_elems["0000,0900"] then
    status_code = cmd_elems["0000,0900"].value
  end
  dicom.do_release(sock, timeout_s)

  local verdict, label = classify_status(status_code)
  out["C-STORE status"] = string.format("0x%04X (%s)", status_code, label)

  if verdict == "accepted" then
    out["Result"] = "ACCEPTED - the archive stored the injected instance"
    out["Injected instance (delete these to clean up)"] = {
      "SOP Instance UID:   " .. instance_uid,
      "Study Instance UID: " .. study_uid,
      "Series Instance UID:" .. series_uid,
      "PatientID:          " .. o.patient_id,
      "PatientName:        " .. o.patient_name,
    }
    out["VULNERABILITY"] = "Unauthenticated DICOM C-STORE accepted"
    out["Impact"] =
      "An attacker who can associate can write arbitrary images to the archive"
    nmap.set_port_version(host, port, "hardmatched")
  elseif verdict == "refused" then
    out["Result"] = "REFUSED - the archive declined to store the instance"
  else
    out["Result"] = "FAILED - " .. label
  end

  return out
end
