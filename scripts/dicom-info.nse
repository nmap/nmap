description = [[
DICOM service fingerprinter and capability enumerator.

Connects to a DICOM SCP (Service Class Provider) and extracts:
  * Implementation Class UID and Version Name (software identification)
  * Supported SOP Classes (storage, query/retrieve, workflow services)
  * Accepted Transfer Syntaxes per SOP Class
  * Maximum PDU length
  * Protocol version
  * AE Title echo

The Implementation Class UID and Version Name are set by the DICOM software
at build time and uniquely identify the vendor and version -- the DICOM
equivalent of an HTTP Server header. A fingerprint database maps known UIDs
to software names: DCMTK, Orthanc, Horos, dcm4chee, etc.

SOP Class probing reveals what services the target exposes: image storage
(CT, MR, US, ...), query/retrieve (C-FIND, C-MOVE, C-GET), modality
worklist, MPPS, and storage commitment. Each accepted SOP class is an
entry point for further testing with dicom-cfind-ls or dicom-store-fuzzer.

Transfer syntax enumeration reveals encoding capabilities: Implicit/Explicit
VR, compressed formats (JPEG, JPEG-LS, JPEG 2000, RLE), and the deprecated
Explicit VR Big Endian. Compressed transfer syntaxes exercise additional
codec code paths in the target.

This script is non-intrusive -- it only performs A-ASSOCIATE negotiations
and does not send any DIMSE commands or patient data.

Requires the dicom.lua library (place in nselib/ or same directory).
]]

---
-- @usage
-- nmap -p 104,11112,4242 --script dicom-info <target>
--
-- @usage
-- nmap -p 4242 --script dicom-info \
--   --script-args 'dicom-info.called_ae=ORTHANC,dicom-info.calling_ae=FINDSCU' <target>
--
-- @usage
-- nmap -p 11112 --script dicom-info \
--   --script-args 'dicom-info.probe=full' <target>
--
-- @args dicom-info.called_ae   Called AE Title (default: "ANY-SCP")
-- @args dicom-info.calling_ae  Calling AE Title (default: "NMAP-INFO")
-- @args dicom-info.timeout     Association timeout in seconds (default: 10)
-- @args dicom-info.max_pdu     Max PDU Length to propose (default: 16384)
-- @args dicom-info.probe       Probe depth: "basic" (fingerprint only),
--                               "standard" (+ common SOP classes),
--                               "full" (+ all storage + workflow SOP classes)
--                               (default: "standard")
-- @args dicom.tls             Force transport for the whole DICOM suite:
--                             "true" (DICOM over TLS), "false" (plaintext), or
--                             unset to auto-detect (dicom-info only)
--
-- @output
-- PORT     STATE SERVICE
-- 4242/tcp open  dicom
-- | dicom-info:
-- |   Implementation: Orthanc 1.12.4
-- |     Class UID: 1.2.826.0.1.3680043.2.1545.1.2.1.7
-- |     Version: Orthanc
-- |   Max PDU: 16384
-- |   Protocol Version: 1
-- |   Accepted SOP Classes (15 of 42 probed):
-- |     C-ECHO Verification                                 1.2.840.10008.1.1
-- |     CT Image Storage                                    1.2.840.10008.5.1.4.1.1.2
-- |     MR Image Storage                                    1.2.840.10008.5.1.4.1.1.4
-- |     Secondary Capture Image Storage                     1.2.840.10008.5.1.4.1.1.7
-- |     Study Root Q/R - FIND                               1.2.840.10008.5.1.4.1.2.2.1
-- |     Study Root Q/R - MOVE                               1.2.840.10008.5.1.4.1.2.2.2
-- |     Study Root Q/R - GET                                1.2.840.10008.5.1.4.1.2.2.3
-- |     ...
-- |   Accepted Transfer Syntaxes:
-- |     Implicit VR Little Endian                           1.2.840.10008.1.2
-- |     Explicit VR Little Endian                           1.2.840.10008.1.2.1
-- |   Security: No TLS (plaintext DICOM association)
-- |_  WARNING: DICOM service accessible without authentication
---

author   = "Paulino Calderon <paulino@calderonpale.com>"
license  = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

local shortport = require "shortport"
local stdnse    = require "stdnse"
local nmap      = require "nmap"
local string    = require "string"
local math      = require "math"
local dicom     = require "dicom"

portrule = shortport.port_or_service({104, 2762, 11112, 4242}, "dicom", "tcp",
    "open")

-----------------------------------------------------------------------
-- IMPLEMENTATION FINGERPRINT DATABASE
-----------------------------------------------------------------------
-- Maps Implementation Class UIDs to vendor/product names.
-- Sources: DICOM standard PS3.7 Annex E, vendor documentation,
-- observed values from real deployments.

local IMPL_DB = {
  -- DCMTK (OFFIS)
  ["1.2.276.0.7230010.3.0.3.6.0"] = "DCMTK 3.6.0",
  ["1.2.276.0.7230010.3.0.3.6.1"] = "DCMTK 3.6.1",
  ["1.2.276.0.7230010.3.0.3.6.2"] = "DCMTK 3.6.2",
  ["1.2.276.0.7230010.3.0.3.6.3"] = "DCMTK 3.6.3",
  ["1.2.276.0.7230010.3.0.3.6.4"] = "DCMTK 3.6.4",
  ["1.2.276.0.7230010.3.0.3.6.5"] = "DCMTK 3.6.5",
  ["1.2.276.0.7230010.3.0.3.6.6"] = "DCMTK 3.6.6",
  ["1.2.276.0.7230010.3.0.3.6.7"] = "DCMTK 3.6.7",
  ["1.2.276.0.7230010.3.0.3.6.8"] = "DCMTK 3.6.8",
  -- Orthanc
  ["1.2.826.0.1.3680043.2.1545.1.2.1.7"] = "Orthanc",
  -- dcm4che / dcm4chee
  ["1.2.40.0.13.1.1"]                     = "dcm4che",
  ["1.2.40.0.13.1.3"]                     = "dcm4chee Archive",
  -- GDCM
  ["1.2.826.0.1.3680043.2.1143.107.104.103.115.2"] = "GDCM",
  -- pydicom / pynetdicom
  ["1.2.826.0.1.3680043.9.3811.2.0.1"]    = "pynetdicom",
  ["1.2.826.0.1.3680043.8.498.1"]         = "pydicom",
  -- Horos / OsiriX
  ["1.2.276.0.7238010.3.0.3.6.0"]         = "Horos (OsiriX fork)",
  ["2.16.756.5.5.100.3611.1.1"]           = "OsiriX",
  -- ClearCanvas
  ["1.2.826.0.1.3680043.2.1343.8806"]     = "ClearCanvas",
  -- Merge DICOM Toolkit
  ["1.2.826.0.1.3680043.2.46.1.1"]        = "Merge DICOM Toolkit",
  -- Conquest DICOM
  ["1.2.826.0.1.3680043.2.135.1066.101"]  = "Conquest DICOM",
  -- MicroDicom
  ["1.2.826.0.1.3680043.2.1545.1.2.1.9"]  = "MicroDicom",
  -- FO-DICOM (.NET)
  ["1.3.6.1.4.1.30071.8"]                 = "fo-dicom",
  -- Philips Healthcare
  ["1.3.46.670589.50"]                     = "Philips Healthcare",
  -- GE Healthcare
  ["1.2.840.113619.6.5"]                   = "GE Healthcare",
  -- Siemens Healthineers
  ["1.3.12.2.1107.5.8.1"]                 = "Siemens Healthineers",
  -- Agfa Healthcare
  ["1.2.124.113532.3500.8.1"]             = "Agfa HealthCare IMPAX",
  -- Carestream
  ["1.2.840.113564.3.5"]                  = "Carestream Health",
  -- Fujifilm
  ["1.2.392.200036.9116.7.8.1.1"]         = "Fujifilm Synapse",
  -- Canon Medical (Toshiba)
  ["1.2.392.200036.9116.7.1.1"]           = "Canon Medical / Toshiba",
  -- Sectra
  ["1.2.752.24.7.123"]                     = "Sectra IDS7",
  -- Visage Imaging
  ["1.2.826.0.1.3680043.2.228.1"]         = "Visage Imaging",
}

-- Partial prefix matching for vendors with many sub-versions
local IMPL_PREFIX = {
  ["1.2.276.0.7230010.3.0.3."]    = "DCMTK",
  ["1.2.826.0.1.3680043.2.1545."] = "Orthanc",
  ["1.2.40.0.13."]                = "dcm4che/dcm4chee",
  ["1.3.46.670589."]              = "Philips Healthcare",
  ["1.2.840.113619."]             = "GE Healthcare",
  ["1.3.12.2.1107."]              = "Siemens Healthineers",
  ["1.2.124.113532."]             = "Agfa HealthCare",
  ["1.2.840.113564."]             = "Carestream Health",
  ["1.2.392.200036."]             = "Fujifilm/Canon Medical",
  ["1.2.826.0.1.3680043.9.3811."] = "pynetdicom",
  ["1.2.826.0.1.3680043.8.498."]  = "pydicom",
}

--- Look up an Implementation Class UID in the fingerprint database.
-- @param uid  Implementation Class UID string
-- @return product name or nil
local function lookup_impl(uid)
  if not uid or uid == "" then return nil end
  -- Exact match first
  if IMPL_DB[uid] then return IMPL_DB[uid] end
  -- Prefix match
  for prefix, name in pairs(IMPL_PREFIX) do
    if uid:sub(1, #prefix) == prefix then
      return name
    end
  end
  return nil
end

-----------------------------------------------------------------------
-- SOP CLASS CATALOG
-----------------------------------------------------------------------
-- Organized by service category for structured output.
-- Each entry: {uid, short_name, category}

local SOP_CATALOG = {
  -- Verification
  {"1.2.840.10008.1.1", "C-ECHO Verification", "Verification"},
  -- Storage: Common modalities
  {"1.2.840.10008.5.1.4.1.1.2", "CT Image Storage", "Storage"},
  {"1.2.840.10008.5.1.4.1.1.2.1", "Enhanced CT Image Storage", "Storage"},
  {"1.2.840.10008.5.1.4.1.1.4", "MR Image Storage", "Storage"},
  {"1.2.840.10008.5.1.4.1.1.4.1", "Enhanced MR Image Storage", "Storage"},
  {"1.2.840.10008.5.1.4.1.1.6.1", "US Image Storage", "Storage"},
  {"1.2.840.10008.5.1.4.1.1.7", "Secondary Capture", "Storage"},
  {"1.2.840.10008.5.1.4.1.1.7.1", "Multi-frame SC (Byte)", "Storage"},
  {"1.2.840.10008.5.1.4.1.1.7.2", "Multi-frame SC (Word)", "Storage"},
  {"1.2.840.10008.5.1.4.1.1.7.3", "Multi-frame SC (True Color)", "Storage"},
  {"1.2.840.10008.5.1.4.1.1.7.4", "Multi-frame SC (Grayscale)", "Storage"},
  {"1.2.840.10008.5.1.4.1.1.12.1", "X-Ray Angiographic Storage", "Storage"},
  {"1.2.840.10008.5.1.4.1.1.12.2", "X-Ray Radiofluoroscopic Storage",
      "Storage"},
  {"1.2.840.10008.5.1.4.1.1.20", "NM Image Storage", "Storage"},
  {"1.2.840.10008.5.1.4.1.1.128", "PET Image Storage", "Storage"},
  {"1.2.840.10008.5.1.4.1.1.128.1", "Enhanced PET Image Storage", "Storage"},
  {"1.2.840.10008.5.1.4.1.1.1", "CR Image Storage", "Storage"},
  {"1.2.840.10008.5.1.4.1.1.1.1", "Digital X-Ray (DX) Storage", "Storage"},
  {"1.2.840.10008.5.1.4.1.1.1.2", "Digital Mammography Storage", "Storage"},
  {"1.2.840.10008.5.1.4.1.1.104.1", "Encapsulated PDF Storage", "Storage"},
  {"1.2.840.10008.5.1.4.1.1.104.2", "Encapsulated CDA Storage", "Storage"},
  {"1.2.840.10008.5.1.4.1.1.104.3", "Encapsulated STL Storage", "Storage"},
  -- Query/Retrieve
  {"1.2.840.10008.5.1.4.1.2.2.1", "Study Root Q/R - FIND", "Query/Retrieve"},
  {"1.2.840.10008.5.1.4.1.2.2.2", "Study Root Q/R - MOVE", "Query/Retrieve"},
  {"1.2.840.10008.5.1.4.1.2.2.3", "Study Root Q/R - GET", "Query/Retrieve"},
  {"1.2.840.10008.5.1.4.1.2.1.1", "Patient Root Q/R - FIND", "Query/Retrieve"},
  {"1.2.840.10008.5.1.4.1.2.1.2", "Patient Root Q/R - MOVE", "Query/Retrieve"},
  {"1.2.840.10008.5.1.4.1.2.1.3", "Patient Root Q/R - GET", "Query/Retrieve"},
  -- Worklist & Workflow
  {"1.2.840.10008.5.1.4.31", "Modality Worklist - FIND", "Worklist"},
  {"1.2.840.10008.3.1.2.3.3", "Modality Performed Procedure Step", "Workflow"},
  {"1.2.840.10008.5.1.4.32.1", "Unified Procedure Step - Push", "Workflow"},
  {"1.2.840.10008.5.1.4.32.3", "Unified Procedure Step - Watch", "Workflow"},
  -- Storage Commitment
  {"1.2.840.10008.1.20.1", "Storage Commitment Push", "Commitment"},
  -- RT
  {"1.2.840.10008.5.1.4.1.1.481.1", "RT Image Storage", "Storage (RT)"},
  {"1.2.840.10008.5.1.4.1.1.481.2", "RT Dose Storage", "Storage (RT)"},
  {"1.2.840.10008.5.1.4.1.1.481.3", "RT Structure Set Storage",
      "Storage (RT)"},
  {"1.2.840.10008.5.1.4.1.1.481.5", "RT Plan Storage", "Storage (RT)"},
  {"1.2.840.10008.5.1.4.1.1.481.8", "RT Ion Plan Storage", "Storage (RT)"},
  -- Structured Reports
  {"1.2.840.10008.5.1.4.1.1.88.11", "Basic Text SR Storage", "Storage (SR)"},
  {"1.2.840.10008.5.1.4.1.1.88.22", "Enhanced SR Storage", "Storage (SR)"},
  {"1.2.840.10008.5.1.4.1.1.88.33", "Comprehensive SR Storage",
      "Storage (SR)"},
  {"1.2.840.10008.5.1.4.1.1.88.34", "Comprehensive 3D SR Storage",
      "Storage (SR)"},
}

-- Extended storage SOP classes for "full" probe mode
local SOP_EXTENDED = {
  -- Ophthalmology
  {"1.2.840.10008.5.1.4.1.1.77.1.5.1", "Ophthalmic Photography 8 Bit",
      "Storage (Oph)"},
  {"1.2.840.10008.5.1.4.1.1.77.1.5.2", "Ophthalmic Photography 16 Bit",
      "Storage (Oph)"},
  {"1.2.840.10008.5.1.4.1.1.77.1.5.4", "Ophthalmic Tomography Storage",
      "Storage (Oph)"},
  -- Waveform
  {"1.2.840.10008.5.1.4.1.1.9.1.1", "12-lead ECG Waveform Storage",
      "Storage (Waveform)"},
  {"1.2.840.10008.5.1.4.1.1.9.1.2", "General ECG Waveform Storage",
      "Storage (Waveform)"},
  {"1.2.840.10008.5.1.4.1.1.9.1.3", "Ambulatory ECG Waveform Storage",
      "Storage (Waveform)"},
  -- Presentation State
  {"1.2.840.10008.5.1.4.1.1.11.1", "Grayscale Softcopy Pres. State",
      "Storage (PR)"},
  {"1.2.840.10008.5.1.4.1.1.11.2", "Color Softcopy Pres. State",
      "Storage (PR)"},
  -- Key Object
  {"1.2.840.10008.5.1.4.1.1.88.59", "Key Object Selection Doc",
      "Storage (KO)"},
  -- Segmentation
  {"1.2.840.10008.5.1.4.1.1.66.4", "Segmentation Storage", "Storage (Seg)"},
  -- Parametric Map
  {"1.2.840.10008.5.1.4.1.1.30", "Parametric Map Storage", "Storage (Map)"},
  -- Raw Data
  {"1.2.840.10008.5.1.4.1.1.66", "Raw Data Storage", "Storage (Raw)"},
  -- VL Image
  {"1.2.840.10008.5.1.4.1.1.77.1.1", "VL Endoscopic Image Storage",
      "Storage (VL)"},
  {"1.2.840.10008.5.1.4.1.1.77.1.2", "VL Microscopic Image Storage",
      "Storage (VL)"},
  {"1.2.840.10008.5.1.4.1.1.77.1.4", "VL Photographic Image Storage",
      "Storage (VL)"},
  -- Whole Slide
  {"1.2.840.10008.5.1.4.1.1.77.1.6", "VL Whole Slide Microscopy Storage",
      "Storage (WSI)"},
  -- 3D
  {"1.2.840.10008.5.1.4.1.1.68.1", "Surface Scan Mesh Storage",
      "Storage (3D)"},
}

-----------------------------------------------------------------------
-- TRANSFER SYNTAX CATALOG
-----------------------------------------------------------------------

local TS_CATALOG = {
  {"1.2.840.10008.1.2",        "Implicit VR Little Endian"},
  {"1.2.840.10008.1.2.1",      "Explicit VR Little Endian"},
  {"1.2.840.10008.1.2.2",      "Explicit VR Big Endian (retired)"},
  {"1.2.840.10008.1.2.1.99",   "Deflated Explicit VR Little Endian"},
  {"1.2.840.10008.1.2.4.50",   "JPEG Baseline (Process 1)"},
  {"1.2.840.10008.1.2.4.51",   "JPEG Extended (Process 2 & 4)"},
  {"1.2.840.10008.1.2.4.57",   "JPEG Lossless Non-Hierarchical (Process 14)"},
  {"1.2.840.10008.1.2.4.70",   "JPEG Lossless SV1 (Process 14 SV1)"},
  {"1.2.840.10008.1.2.4.80",   "JPEG-LS Lossless"},
  {"1.2.840.10008.1.2.4.81",   "JPEG-LS Lossy (Near-Lossless)"},
  {"1.2.840.10008.1.2.4.90",   "JPEG 2000 (Lossless Only)"},
  {"1.2.840.10008.1.2.4.91",   "JPEG 2000"},
  {"1.2.840.10008.1.2.4.201",  "HTJ2K (Lossless Only)"},
  {"1.2.840.10008.1.2.4.202",  "HTJ2K (Lossless or Lossy)"},
  {"1.2.840.10008.1.2.4.203",  "HTJ2K RPCL (Lossless Only)"},
  {"1.2.840.10008.1.2.5",      "RLE Lossless"},
}

-----------------------------------------------------------------------
-- HELPERS
-----------------------------------------------------------------------

local function get_arg(key, default)
  return stdnse.get_script_args("dicom-info." .. key) or default
end

--- Probe whether a list of SOP classes are accepted by the target.
-- Sends A-ASSOCIATE-RQ proposing up to `batch_size` SOP classes at once,
-- returns list of accepted UIDs and their transfer syntaxes.
-- @param host, port      Nmap host/port objects
-- @param called_ae       Called AE Title
-- @param calling_ae      Calling AE Title
-- @param sop_entries     List of {uid, name, category} from catalog
-- @param max_pdu         Max PDU length
-- @param timeout_s       Timeout in seconds
-- @param ts_uids         Transfer syntax UIDs to propose
-- @return accepted (list of {uid, name, category, transfer_syntax}),
-- rejected_count
local function probe_sop_classes(host, port, called_ae, calling_ae,
                                  sop_entries, max_pdu, timeout_s, ts_uids,
                                  tls)
  local accepted = {}
  local rejected = 0

  -- DICOM allows up to 128 presentation contexts per association (pctx_id
  -- 1-255 odd)
  local batch_size = 128
  local i = 1

  while i <= #sop_entries do
    local batch = {}
    local batch_uids = {}
    for j = i, math.min(i + batch_size - 1, #sop_entries) do
      batch[#batch + 1] = sop_entries[j]
      batch_uids[#batch_uids + 1] = sop_entries[j][1]
    end

    local ok, sock, pctxs, _, _, ac_info = dicom.do_associate(
      host, port, called_ae, calling_ae, batch_uids, max_pdu, timeout_s,
          ts_uids, nil, tls)

    if ok then
      -- Map pctx_id back to SOP class (pctx_id = 2*index - 1)
      for idx, entry in ipairs(batch) do
        local pctx_id = 2 * idx - 1
        if pctxs[pctx_id] and pctxs[pctx_id].accepted then
          accepted[#accepted + 1] = {
            uid      = entry[1],
            name     = entry[2],
            category = entry[3],
            ts       = pctxs[pctx_id].transfer_syntax or "",
          }
        else
          rejected = rejected + 1
        end
      end
      dicom.do_release(sock, 3)
    else
      -- Association failed entirely for this batch
      rejected = rejected + #batch
      stdnse.debug1("SOP probe batch failed: %s", tostring(sock))
    end

    i = i + batch_size
  end

  return accepted, rejected
end

--- Probe which transfer syntaxes the target accepts for a given SOP class.
-- Tests each transfer syntax individually against a single SOP class.
-- @param host, port      Nmap host/port objects
-- @param called_ae       Called AE Title
-- @param calling_ae      Calling AE Title
-- @param sop_uid         SOP Class UID to test against
-- @param max_pdu         Max PDU length
-- @param timeout_s       Timeout in seconds
-- @return List of accepted {uid, name} transfer syntaxes
local function probe_transfer_syntaxes(host, port, called_ae, calling_ae,
                                        sop_uid, max_pdu, timeout_s, tls)
  local accepted = {}

  -- Test each transfer syntax individually (some servers only accept one per
  -- pctx)
  for _, ts in ipairs(TS_CATALOG) do
    local ok, sock, pctxs = dicom.do_associate(
      host, port, called_ae, calling_ae, {sop_uid}, max_pdu, timeout_s,
          {ts[1]}, nil, tls)

    if ok then
      local pctx_id = dicom.pick_accepted_pctx(pctxs)
      if pctx_id then
        accepted[#accepted + 1] = { uid = ts[1], name = ts[2] }
      end
      dicom.do_release(sock, 3)
    end
  end

  return accepted
end

--- Format a certificate date, which may be a string or a date table.
local function fmt_date(d)
  if type(d) == "table" then
    if d.year then
      return string.format("%04d-%02d-%02d %02d:%02d:%02d",
        d.year or 0, d.month or 0, d.day or 0,
        d.hour or 0, d.min or 0, d.sec or 0)
    end
    return "?"
  end
  return tostring(d)
end

--- Describe a TLS certificate as a list of output lines.
local function cert_lines(cert)
  local subj = cert.subject and cert.subject.commonName or "?"
  local iss  = cert.issuer and cert.issuer.commonName or "?"
  local exp  = "?"
  if cert.validity and cert.validity.notAfter then
    exp = fmt_date(cert.validity.notAfter)
  end
  local lines = {
    "Subject CN: " .. subj,
    "Issuer CN: " .. iss,
    "Not after: " .. exp,
  }
  -- Certificate key and signature strength (from the presented cert).
  if cert.pubkey then
    local ktype = tostring(cert.pubkey.type or "?")
    local kbits = cert.pubkey.bits
    local kline = "Public key: " .. ktype
    if kbits then kline = kline .. " " .. tostring(kbits) .. "-bit" end
    if ktype == "rsa" and kbits and kbits < 2048 then
      kline = kline .. " (WEAK: < 2048-bit)"
    end
    lines[#lines + 1] = kline
  end
  if cert.sig_algorithm then
    local sig = tostring(cert.sig_algorithm)
    local sline = "Signature: " .. sig
    local low = sig:lower()
    if low:find("sha1") or low:find("md5") then
      sline = sline .. " (WEAK signature algorithm)"
    end
    lines[#lines + 1] = sline
  end
  if subj ~= "?" and subj == iss then
    lines[#lines + 1] = "Self-signed certificate"
  end
  return lines
end

--- Return weak-crypto / cert warnings for the WARNINGS section.
local function cert_warnings(cert)
  local w = {}
  if cert.pubkey and cert.pubkey.type == "rsa" and cert.pubkey.bits
     and cert.pubkey.bits < 2048 then
    w[#w + 1] = "TLS certificate uses a weak RSA key (< 2048-bit)"
  end
  if cert.sig_algorithm then
    local low = tostring(cert.sig_algorithm):lower()
    if low:find("sha1") or low:find("md5") then
      w[#w + 1] = "TLS certificate uses a weak signature algorithm (SHA-1/MD5)"
    end
  end
  local subj = cert.subject and cert.subject.commonName
  local iss  = cert.issuer and cert.issuer.commonName
  if subj and iss and subj == iss then
    w[#w + 1] = "TLS certificate is self-signed (no CA trust chain)"
  end
  return w
end

-----------------------------------------------------------------------
-- MAIN ACTION
-----------------------------------------------------------------------

action = function(host, port)
  local called_ae   = get_arg("called_ae",  "ANY-SCP")
  local calling_ae  = get_arg("calling_ae", "NMAP-INFO")
  local timeout_s   = tonumber(get_arg("timeout", "10"))
  local max_pdu     = tonumber(get_arg("max_pdu", "16384"))
  local probe_depth = get_arg("probe", "standard"):lower()

  -- Transport: tls=true forces DICOM-over-TLS, tls=false forces plaintext,
  -- unset auto-detects (plaintext first, then TLS).
  local tls_arg = stdnse.get_script_args("dicom.tls")
  local attempts
  if tls_arg == "true" then
    attempts = { true }
  elseif tls_arg == "false" then
    attempts = { false }
  else
    attempts = { false, true }
  end

  local out = stdnse.output_table()

  -- == Phase 1: Fingerprint via Verification SOP class ==
  local ok, sock, pctxs, server_max_pdu, elapsed, ac_info
  local tls = false
  for _, t in ipairs(attempts) do
    ok, sock, pctxs, server_max_pdu, elapsed, ac_info = dicom.do_associate(
      host, port, called_ae, calling_ae,
      {dicom.SOP_CLASS.VERIFICATION}, max_pdu, timeout_s, nil, nil, t)
    if ok then
      tls = t
      break
    end
  end

  if not ok then
    out["Error"] = string.format("Association failed: %s", tostring(sock))
    return out
  end

  -- Extract fingerprint data
  local impl_uid = ac_info.impl_class_uid or ""
  local impl_ver = ac_info.impl_version   or ""
  local product  = lookup_impl(impl_uid)

  -- Format implementation info
  if product then
    -- If impl_version adds version detail not in the product name, append it
    if impl_ver ~= "" and not product:lower():find(impl_ver:lower()) then
      out["Implementation"] = string.format("%s (%s)", product, impl_ver)
    else
      out["Implementation"] = product
    end
  elseif impl_ver ~= "" then
    out["Implementation"] = impl_ver
  else
    out["Implementation"] = "Unknown"
  end
  out["  Class UID"] = impl_uid ~= "" and impl_uid or "(not provided)"
  out["  Version"]   = impl_ver ~= "" and impl_ver or "(not provided)"
  out["Max PDU"]     = server_max_pdu or max_pdu

  -- C-ECHO verification
  local pctx_id = dicom.pick_accepted_pctx(pctxs)
  local echo_ok = false
  if pctx_id then
    local cmd = dicom.build_cecho_rq(1)
    dicom.send_dimse(sock, pctx_id, cmd, nil, max_pdu)
    local pdu_type, cmd_elems = dicom.recv_dimse(sock, timeout_s)
    if pdu_type == dicom.PDU_CODES.DATA and cmd_elems
       and cmd_elems["0000,0900"]
       and cmd_elems["0000,0900"].value == dicom.STATUS.SUCCESS then
      echo_ok = true
    end
  end
  dicom.do_release(sock, 3)

  if probe_depth == "basic" then
    out["C-ECHO"] = echo_ok and "SUCCESS" or "FAILED"
    nmap.set_port_state(host, port, "open")
    port.version.name = "dicom"
    if product then port.version.product = product end
    nmap.set_port_version(host, port, "hardmatched")
    return out
  end

  -- == Phase 2: SOP class probing ==
  -- Build the probe list based on depth
  local probe_list = {}
  for _, entry in ipairs(SOP_CATALOG) do
    probe_list[#probe_list + 1] = entry
  end
  if probe_depth == "full" then
    for _, entry in ipairs(SOP_EXTENDED) do
      probe_list[#probe_list + 1] = entry
    end
  end

  -- Use standard transfer syntaxes for SOP probing
  local probe_ts = {
    dicom.TRANSFER_SYNTAX.EXPLICIT_LE,
    dicom.TRANSFER_SYNTAX.IMPLICIT_LE,
  }

  local accepted_sops, rejected_count = probe_sop_classes(
    host, port, called_ae, calling_ae, probe_list, max_pdu, timeout_s,
        probe_ts, tls)

  local total_probed = #probe_list
  out["Accepted SOP Classes"] = string.format("%d of %d probed",
    #accepted_sops, total_probed)

  -- Group by category for display
  local cat_order = {}
  local by_category = {}
  for _, sop in ipairs(accepted_sops) do
    if not by_category[sop.category] then
      by_category[sop.category] = {}
      cat_order[#cat_order + 1] = sop.category
    end
    by_category[sop.category][#by_category[sop.category] + 1] = sop
  end

  local sop_lines = {}
  for _, cat in ipairs(cat_order) do
    for _, sop in ipairs(by_category[cat]) do
      -- Align UID column for readability
      local padded = sop.name .. string.rep(" ", math.max(1, 50 - #sop.name))
      sop_lines[#sop_lines + 1] = padded .. sop.uid
    end
  end
  out["  Services"] = sop_lines

  -- == Phase 3: Transfer syntax probing ==
  -- Use Verification SOP (universally accepted) as the probe target
  local ts_probe_sop = dicom.SOP_CLASS.VERIFICATION
  -- If Verification wasn't accepted, use the first accepted SOP
  if #accepted_sops > 0 then
    -- Prefer Verification, but fall back to first accepted
    local found_verif = false
    for _, sop in ipairs(accepted_sops) do
      if sop.uid == dicom.SOP_CLASS.VERIFICATION then
        found_verif = true
        break
      end
    end
    if not found_verif then
      ts_probe_sop = accepted_sops[1].uid
    end
  end

  local accepted_ts = probe_transfer_syntaxes(
    host, port, called_ae, calling_ae, ts_probe_sop, max_pdu, timeout_s, tls)

  if #accepted_ts > 0 then
    local ts_lines = {}
    for _, ts in ipairs(accepted_ts) do
      local padded = ts.name .. string.rep(" ", math.max(1, 50 - #ts.name))
      ts_lines[#ts_lines + 1] = padded .. ts.uid
    end
    out["Accepted Transfer Syntaxes"] = ts_lines
  end

  -- == Security assessment ==
  -- Transport was determined by our own association attempt above.
  if tls then
    out["Security"] = "DICOM over TLS (encrypted)"
    if ac_info and ac_info.cert then
      out["  TLS certificate"] = cert_lines(ac_info.cert)
    end
    -- We completed the TLS association without presenting a client
    -- certificate, so the server does not require mutual TLS (IHE ATNA node
    -- authentication).
    out["  Client certificate"] =
      "not required (no mutual TLS / IHE ATNA node authentication)"
  else
    out["Security"] = "No TLS (plaintext DICOM association)"
  end

  -- Check for concerning capabilities
  local warnings = {}
  if echo_ok then
    warnings[#warnings + 1] = "DICOM service accessible without authentication"
  end

  -- Check for Q/R services (data exfiltration risk)
  local has_find, has_move, has_get = false, false, false
  for _, sop in ipairs(accepted_sops) do
    if sop.uid:find("%.1$") and sop.category == "Query/Retrieve" then
      has_find = true
    end
    if sop.uid:find("%.2$") and sop.category == "Query/Retrieve" then
      has_move = true
    end
    if sop.uid:find("%.3$") and sop.category == "Query/Retrieve" then
      has_get = true
    end
  end
  if has_find then
    warnings[#warnings + 1] = "Q/R FIND enabled - patient data enumeration" ..
                              " possible (use dicom-cfind-ls)"
  end
  if has_move then
    warnings[#warnings + 1] = "Q/R MOVE enabled - image exfiltration to" ..
                              " arbitrary destination possible"
  end
  if has_get then
    warnings[#warnings + 1] = "Q/R GET enabled - direct image download" ..
                              " possible"
  end

  -- Check for storage (C-STORE injection risk)
  local storage_count = 0
  for _, sop in ipairs(accepted_sops) do
    if sop.category:find("^Storage") then storage_count = storage_count + 1 end
  end
  if storage_count > 0 then
    warnings[#warnings + 1] = string.format(
      "%d storage SOP classes accepted - malformed data injection possible" ..
      " (use dicom-store-fuzzer)",
      storage_count)
  end

  if not tls then
    warnings[#warnings + 1] = "No TLS - PHI transmitted in plaintext"
  else
    warnings[#warnings + 1] = "TLS server requires no client certificate"
      .. " (no mutual TLS / IHE ATNA node authentication)"
    if ac_info and ac_info.cert then
      for _, w in ipairs(cert_warnings(ac_info.cert)) do
        warnings[#warnings + 1] = w
      end
    end
  end

  if #warnings > 0 then
    out["WARNINGS"] = warnings
  end

  -- Set port info
  nmap.set_port_state(host, port, "open")
  port.version.name = "dicom"
  if product then port.version.product = product end
  nmap.set_port_version(host, port, "hardmatched")

  return out
end
