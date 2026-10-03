local http = require "http"
local json = require "json"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local math = require "math"

description = [[
Discovers and enumerates DICOMweb services -- the HTTP/REST face of DICOM
(PS3.18): QIDO-RS (query), WADO-RS (retrieve) and STOW-RS (store).

Modern PACS, VNAs and cloud imaging archives (Orthanc, dcm4chee-arc, and the
cloud healthcare APIs) expose imaging over HTTP alongside, or instead of, the
classic DIMSE port. Nmap has rich DIMSE coverage (dicom-info, dicom-cfind-ls,
...) but nothing for the web tier, which is often where exposure actually
lives -- a QIDO-RS "/studies" endpoint reachable without authentication leaks
the same study- and patient-level metadata as an unauthenticated C-FIND, and
a STOW-RS "/studies" endpoint reachable without authentication is an
image-injection surface.

The script:
  * probes a list of common DICOMweb roots (or a caller-supplied one) for a
    QIDO-RS "/studies" endpoint;
  * classifies the endpoint as open (returns application/dicom+json),
    authentication-required (401/403) or absent (404);
  * on an open endpoint, reports the study count and a sample of the
    study-level metadata returned (patient name/ID, study date, description,
    modalities) -- i.e. the PHI an unauthenticated client can read;
  * checks WADO-RS retrieval (study metadata) and STOW-RS store-endpoint
    presence, the latter via OPTIONS / an empty multipart probe that does NOT
    create any object;
  * flags unauthenticated QIDO/STOW access and PHI carried over plaintext
    HTTP.

It is read-only: it issues GET, OPTIONS and (for STOW detection only) an empty
POST that cannot store an instance. It does not upload images or modify data.

The three DICOMweb transactions tested, and the resources they expose:
  * QIDO-RS (Query based on ID for DICOM Objects, PS3.18 Section 10.6) -- the
    "/studies", "/series" and "/instances" search resources. The study-level
    reply is a DICOM+JSON array (PS3.18 Annex F) of attribute objects keyed by
    8-hex-digit tag; it carries PatientName (0010,0010), PatientID (0010,0020),
    StudyDate (0008,0020), StudyDescription (0008,1030), ModalitiesInStudy
    (0008,0061) and the study UID (0020,000D).
  * WADO-RS (Web Access to DICOM Objects by RESTful services, PS3.18 Section
    10.4) -- "/studies/{uid}/metadata" and the bulk instance/frame retrieval
    resources. Metadata retrievability without auth means the full images are
    retrievable too.
  * STOW-RS (Store Over the Web, PS3.18 Section 10.5) -- the "/studies" POST
    resource, the HTTP equivalent of a C-STORE. An open STOW endpoint is an
    unauthenticated image-write surface (see dicom-store-inject for the DIMSE
    equivalent).

References:
  * DICOM PS3.18, Web Services:
    https://dicom.nema.org/medical/dicom/current/output/html/part18.html
  * QIDO-RS (Search transaction): PS3.18 Section 10.6
  * WADO-RS (Retrieve transaction): PS3.18 Section 10.4
  * STOW-RS (Store transaction): PS3.18 Section 10.5
  * DICOM JSON Model: PS3.18 Annex F
  * Orthanc DICOMweb plugin:
    https://orthanc.uclouvain.be/book/plugins/dicomweb.html
  * dcm4chee-arc-light (DICOMweb archive):
    https://github.com/dcm4che/dcm4chee-arc-light
]]

---
-- @usage
-- nmap -p 8042 --script dicom-web-enum <target>
--
-- @usage
-- nmap -p 443 --script dicom-web-enum \
--   --script-args 'dicom-web-enum.root=/dicom-web,dicom-web-enum.scheme=https'\
--   <target>
--
-- @usage
-- nmap -p 8042 --script dicom-web-enum \
--   --script-args 'dicom-web-enum.samples=5' <target>
--
-- @args dicom-web-enum.root     DICOMweb base path to test (e.g. "/dicom-web").
--                               If unset, a built-in candidate list is probed.
-- @args dicom-web-enum.scheme   "http" or "https". Default: inferred from the
--                               port (https for ssl/443/8443, else http, with a
--                               fallback to the other scheme).
-- @args dicom-web-enum.samples  Number of studies to sample from QIDO-RS for
--                               metadata reporting. Default: 3. 0 disables
--                               metadata sampling (endpoint detection only).
-- @args dicom-web-enum.timeout  HTTP timeout in seconds. Default: 10.
--
-- @output
-- PORT     STATE SERVICE
-- 8042/tcp open  http
-- | dicom-web-enum:
-- |   Base URL: http://10.0.0.5:8042/dicom-web
-- |   Server: Orthanc 1.12.4
-- |   Transport: HTTP (plaintext)
-- |   QIDO-RS (query): OPEN - no authentication required
-- |     Studies visible: 128
-- |     Sample studies:
-- |       DOE^JOHN | ID=PAT001 | 20240115 | CT CHEST | CT | series=4
-- |       ROE^JANE | ID=PAT002 | 20240116 | MR BRAIN | MR | series=6
-- |   WADO-RS (retrieve): OPEN - study metadata retrievable
-- |   STOW-RS (store): OPEN - store endpoint accepts unauthenticated POST
-- |   VULNERABILITY: Unauthenticated DICOMweb access exposes PHI and an
-- |     image-injection (STOW-RS) surface
-- |_    PHI is served over plaintext HTTP (no TLS)
--
-- @xmloutput
-- <elem key="base_url">http://10.0.0.5:8042/dicom-web</elem>
-- <elem key="qido">OPEN</elem>
-- <elem key="wado">OPEN</elem>
-- <elem key="stow">OPEN</elem>
--
-- @see dicom-info.nse
-- @see dicom-cfind-ls.nse
-- @see dicom-store-inject.nse
---

author = "Paulino Calderon <paulino@calderonpale.com>"
license = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- DICOMweb services are commonly co-located with the target's HTTP(S) service
-- (Orthanc's REST API defaults to 8042); fire on any HTTP service plus the
-- ports operators most often bind DICOMweb to.
portrule = function(host, port)
  if shortport.http(host, port) then
    return true
  end
  return shortport.port_or_service(
    {8042, 8080, 8443, 4242}, {"http", "https"}, "tcp", "open")(host, port)
end

-- Candidate DICOMweb roots, ordered by how often each is seen in the wild.
local DEFAULT_ROOTS = {
  "/dicom-web",
  "/dicomweb",
  "/wado-rs",
  "/rs",
  "/qido-rs",
  "/dcm4chee-arc/aets/DCM4CHEE/rs",
  "/pacs/rs",
  "/api/dicomweb",
  "",
}

-- Study-level DICOM tags reported for each sampled study.
local TAGS = {
  patient_name = "00100010",
  patient_id   = "00100020",
  study_date   = "00080020",
  study_desc   = "00081030",
  modalities   = "00080061",
  n_series     = "00201206",
  study_uid    = "0020000D",
}

local function arg(name, default)
  return stdnse.get_script_args("dicom-web-enum." .. name) or default
end

--- Extract the first Value of a DICOM+JSON attribute.
-- Handles PN attributes, whose value is an object with an Alphabetic key.
-- @param study table  one QIDO-RS study object (tag -> attribute)
-- @param tag   string 8-hex-digit tag key
-- @return string or nil
local function tag_value(study, tag)
  local attr = study[tag]
  if type(attr) ~= "table" then
    return nil
  end
  local values = attr.Value
  if type(values) ~= "table" or #values == 0 then
    return nil
  end
  local v = values[1]
  if type(v) == "table" then
    -- Person Name: {Alphabetic="DOE^JOHN", Ideographic=..., Phonetic=...}
    v = v.Alphabetic or v.Ideographic or v.Phonetic
  end
  if v == nil then
    return nil
  end
  -- ModalitiesInStudy (CS) may carry several values.
  if tag == TAGS.modalities and #values > 1 then
    local mods = {}
    for _, m in ipairs(values) do
      mods[#mods + 1] = tostring(m)
    end
    return table.concat(mods, "/")
  end
  return tostring(v)
end

--- One-line summary of a sampled study.
local function study_line(study)
  local parts = {
    tag_value(study, TAGS.patient_name) or "(no name)",
    "ID=" .. (tag_value(study, TAGS.patient_id) or "?"),
    tag_value(study, TAGS.study_date) or "(no date)",
    tag_value(study, TAGS.study_desc) or "(no description)",
    tag_value(study, TAGS.modalities) or "?",
  }
  local n = tag_value(study, TAGS.n_series)
  if n then
    parts[#parts + 1] = "series=" .. n
  end
  return table.concat(parts, " | ")
end

--- Build option table for an HTTP request with the given Accept header.
local function opts(scheme, timeout_s, accept, extra)
  local header = {}
  if accept then
    header["Accept"] = accept
  end
  if extra then
    for k, v in pairs(extra) do
      header[k] = v
    end
  end
  return {
    scheme = scheme,
    header = header,
    timeout = timeout_s * 1000,
    no_cache = true,
    redirect_ok = false,
  }
end

--- Try QIDO-RS "/studies" under one root.
-- @return status one of "open", "auth", "absent", "error"
-- @return studies parsed JSON array (only for "open"), or a detail string
local function probe_qido(host, port, scheme, root, timeout_s, limit)
  local path = root .. "/studies?limit=" .. tostring(math.max(limit, 1))
  local o = opts(scheme, timeout_s, "application/dicom+json")
  local r = http.get(host, port, path, o)
  if not r or not r.status then
    return "error", "no HTTP response"
  end
  if r.status == 401 or r.status == 403 then
    return "auth", tostring(r.status)
  end
  if r.status == 200 and r.body then
    local ct = (r.header and r.header["content-type"]) or ""
    if ct:find("json", 1, true) or r.body:match("^%s*%[") then
      local ok, parsed = json.parse(r.body)
      if ok and type(parsed) == "table" then
        return "open", parsed
      end
    end
    return "absent", "200 but not DICOM+JSON"
  end
  return "absent", tostring(r.status)
end

--- Ask QIDO-RS for a study count (a bare /studies, no limit).
local function count_studies(host, port, scheme, root, timeout_s)
  local o = opts(scheme, timeout_s, "application/dicom+json")
  local r = http.get(host, port, root .. "/studies", o)
  if r and r.status == 200 and r.body then
    local ok, parsed = json.parse(r.body)
    if ok and type(parsed) == "table" then
      return #parsed
    end
  end
  return nil
end

--- WADO-RS: is study metadata retrievable?
-- @return "open", "auth" or "absent"
local function probe_wado(host, port, scheme, root, study_uid, timeout_s)
  if not study_uid then
    return "unknown"
  end
  local path = root .. "/studies/" .. study_uid .. "/metadata"
  local o = opts(scheme, timeout_s, "application/dicom+json")
  local r = http.get(host, port, path, o)
  if not r or not r.status then
    return "absent"
  end
  if r.status == 401 or r.status == 403 then
    return "auth"
  end
  if r.status == 200 then
    return "open"
  end
  return "absent"
end

--- STOW-RS: does a store endpoint exist, and is it reachable without auth?
-- Uses OPTIONS first; falls back to an empty multipart POST that cannot
-- create an instance (a server that implements STOW rejects the empty body
-- with 400/409/415/500; a server without it answers 404/405).
-- @return "open", "auth", "present" (exists, auth state unknown) or "absent"
local function probe_stow(host, port, scheme, root, timeout_s)
  local path = root .. "/studies"

  -- OPTIONS is a cheap existence signal (often an unauthenticated CORS
  -- preflight), but it does not reveal whether POST itself needs auth.
  local advertised = false
  local ro = http.generic_request(host, port, "OPTIONS", path,
    opts(scheme, timeout_s, nil))
  if ro and ro.status then
    local allow = (ro.header and (ro.header["allow"]
      or ro.header["access-control-allow-methods"])) or ""
    advertised = allow:upper():find("POST", 1, true) ~= nil
  end

  -- Empty multipart/related body: understood-but-rejected proves the endpoint
  -- exists and reveals its auth posture; it carries no DICOM part so nothing
  -- can be stored. This verdict is authoritative over OPTIONS.
  local boundary = "nmapDICOMWEBprobe"
  local po = opts(scheme, timeout_s, "application/dicom+json", {
    ["Content-Type"] =
      'multipart/related; type="application/dicom"; boundary=' .. boundary,
  })
  po.content = "--" .. boundary .. "--\r\n"
  local rp = http.generic_request(host, port, "POST", path, po)
  if rp and rp.status then
    local s = rp.status
    if s == 401 or s == 403 then
      return "auth"
    end
    -- 2xx (lenient accept of an empty body) or an understood-but-rejected
    -- payload (400/409/415/500) both mean the store endpoint is reachable
    -- without authentication.
    if s == 200 or s == 202 or s == 400 or s == 409 or s == 415
        or s == 500 then
      return "open"
    end
    -- 404/405: no store endpoint here (unless OPTIONS said otherwise).
  end

  return advertised and "present" or "absent"
end

--- Best-effort server identification (HTTP Server header + Orthanc /system).
local function identify_server(host, port, scheme, timeout_s, base_header)
  local server = base_header
  local o = opts(scheme, timeout_s, "application/json")
  local r = http.get(host, port, "/system", o)
  if r and r.status == 200 and r.body then
    local ok, sys = json.parse(r.body)
    if ok and type(sys) == "table" and sys.Name then
      local ver = sys.Version and (" " .. tostring(sys.Version)) or ""
      return tostring(sys.Name) .. ver
    end
  end
  return server
end

--- Decide the scheme(s) to try for this port.
local function scheme_order(port)
  local forced = arg("scheme", nil)
  if forced then
    return {forced}
  end
  local svc = port.service or ""
  local tunnel = (port.version and port.version.service_tunnel) or ""
  if tunnel == "ssl" or svc == "https" or port.number == 443
      or port.number == 8443 then
    return {"https", "http"}
  end
  return {"http", "https"}
end

--- Find a working QIDO root across the candidate roots for one scheme.
-- @return root, status, studies-or-detail, scheme
local function discover(host, port, scheme, roots, timeout_s, limit)
  local best
  for _, root in ipairs(roots) do
    local status, data = probe_qido(host, port, scheme, root, timeout_s, limit)
    if status == "open" then
      return root, status, data
    end
    if status == "auth" and not best then
      best = {root = root, status = status, data = data}
    end
  end
  if best then
    return best.root, best.status, best.data
  end
  return nil
end

action = function(host, port)
  local timeout_s = tonumber(arg("timeout", "10")) or 10
  local samples = tonumber(arg("samples", "3")) or 3
  local user_root = arg("root", nil)
  local roots = user_root and {user_root} or DEFAULT_ROOTS
  local limit = math.max(samples, 1)

  local root, status, data, scheme
  for _, sch in ipairs(scheme_order(port)) do
    root, status, data = discover(host, port, sch, roots, timeout_s, limit)
    if root then
      scheme = sch
      break
    end
  end

  if not root then
    return nil
  end

  local out = stdnse.output_table()
  local base = string.format("%s://%s:%d%s", scheme, host.ip, port.number, root)
  out["Base URL"] = base

  -- Server identification (Server header, then Orthanc /system).
  local server_hdr
  do
    local r = http.get(host, port, root .. "/studies?limit=1",
      opts(scheme, timeout_s, "application/dicom+json"))
    server_hdr = r and r.header and r.header["server"]
  end
  local server = identify_server(host, port, scheme, timeout_s, server_hdr)
  if server then
    out["Server"] = server
  end

  local plaintext = (scheme == "http")
  out["Transport"] = plaintext and "HTTP (plaintext)" or "HTTPS (TLS)"

  local phi_exposed = false
  local sample_study_uid

  if status == "auth" then
    out["QIDO-RS (query)"] =
      "AUTH REQUIRED - endpoint present, returned " .. tostring(data)
  elseif status == "open" then
    out["QIDO-RS (query)"] = "OPEN - no authentication required"
    local total = count_studies(host, port, scheme, root, timeout_s)
    out["Studies visible"] = total or (#data .. " (sample)")
    if #data > 0 then
      sample_study_uid = tag_value(data[1], TAGS.study_uid)
      if samples > 0 then
        local lines = {}
        for i = 1, math.min(samples, #data) do
          lines[#lines + 1] = study_line(data[i])
          if tag_value(data[i], TAGS.patient_name)
              or tag_value(data[i], TAGS.patient_id) then
            phi_exposed = true
          end
        end
        out["Sample studies"] = lines
      end
    end
  end

  -- WADO-RS retrieval.
  local wado = probe_wado(host, port, scheme, root, sample_study_uid, timeout_s)
  if wado == "open" then
    out["WADO-RS (retrieve)"] = "OPEN - study metadata retrievable"
  elseif wado == "auth" then
    out["WADO-RS (retrieve)"] = "AUTH REQUIRED"
  elseif wado == "absent" then
    out["WADO-RS (retrieve)"] = "not detected"
  end

  -- STOW-RS store surface.
  local stow = probe_stow(host, port, scheme, root, timeout_s)
  local stow_open = false
  if stow == "open" then
    out["STOW-RS (store)"] =
      "OPEN - store endpoint accepts unauthenticated POST"
    stow_open = true
  elseif stow == "present" then
    out["STOW-RS (store)"] = "present (POST advertised)"
  elseif stow == "auth" then
    out["STOW-RS (store)"] = "AUTH REQUIRED"
  else
    out["STOW-RS (store)"] = "not detected"
  end

  -- Findings.
  local warnings = {}
  if status == "open" and (phi_exposed or wado == "open") then
    out["VULNERABILITY"] =
      "Unauthenticated DICOMweb access exposes PHI"
      .. (stow_open and " and an image-injection (STOW-RS) surface" or "")
  elseif stow_open then
    out["VULNERABILITY"] =
      "Unauthenticated STOW-RS store endpoint (image-injection surface)"
  end
  if plaintext and (phi_exposed or status == "open" or status == "auth") then
    warnings[#warnings + 1] =
      "DICOMweb (PHI) is served over plaintext HTTP (no TLS)"
  end
  if #warnings > 0 then
    out["WARNINGS"] = warnings
  end

  return out
end
