local dns       = require "dns"
local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"
local table     = require "table"

description = [[
Identifies Matter smart-home devices via mDNS service discovery.

Matter (formerly Project CHIP) is the unified IP-based smart-home protocol
maintained by the Connectivity Standards Alliance. The script sends three
DNS PTR queries to port 5353/udp on the target and decodes the responses:

  _matter._tcp.local   commissioned (operational) nodes
  _matterc._udp.local  nodes currently in commissioning / pairing mode
  _meshcop._udp.local  Thread network border routers

Per-instance attributes are extracted from DNS-SD TXT records, including
Vendor ID (looked up against the partial CSA registry shipped in the Matter
SDK), Product ID, device type, fabric/node identifiers, discriminator,
commissioning mode, TCP support, session intervals, and pairing hints.

If port 5540 (Matter operational TCP/UDP port) is also reported open, the
script flags it; mDNS on 5353/udp provides the richer device information.

References:
* https://csa-iot.org/all-solutions/matter/
* https://github.com/project-chip/connectedhomeip
* Matter Core Specification, section 4 ("Discovery") and section 5.4
]]

---
-- @usage nmap -sU -p 5353 --script matter-identify <target>
-- @usage nmap -sU -p 5353 --script matter-identify 192.168.0.0/24
-- @usage nmap -p T:5540,U:5353 --script matter-identify <target>
--
-- @output
-- PORT     STATE SERVICE
-- 5353/udp open  mdns
-- | matter-identify:
-- |   Commissioned Matter device (_matter._tcp) #1:
-- |     Instance: 92E5DE45A4357164-0000000000000019
-- |     Fabric ID: 0x92E5DE45A4357164
-- |     Node ID: 0x0000000000000019
-- |     Session Idle Interval: 2000 ms
-- |     Session Active Interval: 2000 ms
-- |     Session Active Threshold: 4000 ms
-- |     Port: 5540
-- |     Host: DAA69B29F9D12EEE.local
-- |   Commissioning Matter device (_matterc._udp):
-- |     Instance: 9BB722E74A9CAEBB
-- |     Vendor ID: 0x130A
-- |     Product ID: 0x0050
-- |     Device type: 0x010A (On/Off Plug-in Unit)
-- |     Device name: Eve Energy
-- |     Discriminator: 408
-- |     Commissioning mode: 2 (enhanced commissioning mode)
-- |     Rotating device ID: 0C00A65A406F5F8689445667357195EA6FB7
-- |     Pairing hint: 36 (Administrator; Device manual)
-- |     Session Idle Interval: 2000 ms
-- |     Session Active Interval: 2000 ms
-- |     Session Active Threshold: 4000 ms
-- |     Port: 5540
-- |     Host: DAA69B29F9D12EEE.local
-- |   Thread border router (_meshcop._udp):
-- |     Instance: New Apple TV
-- |     Network name: MyHome1004112387
-- |     Extended PAN ID: \x04\x8E\x89\xF2\xC4+D\x11
-- |     Thread version: 1.3.0
-- |     Extended address: \x8A\xD9\x9E,\xDA45\xBC
-- |     Border agent port: \xB3\xD2\x91I
-- |     Sequence number:
-- |     BBR seq number: \xF0\xBF
-- |     State bitmap: \x00\x00\x0F\xB1
-- |     Port: 49153
-- |_    Host: New-Apple-TV.local
--
-- @see dns-service-discovery.nse

author = "Zoltan Balazs"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


-- ---------------------------------------------------------------------------
-- Constants
-- ---------------------------------------------------------------------------

local MDNS_PORT     = 5353
local MATTER_PORT   = 5540
local QUERY_TIMEOUT = 2000  -- ms per service-type query

-- DNS-SD service types defined by the Matter spec, queried via PTR.
local MATTER_SERVICES = {
  {
    qname = "_matter._tcp.local",
    label = "Commissioned Matter device (_matter._tcp)",
    kind  = "operational",
  },
  {
    qname = "_matterc._udp.local",
    label = "Commissioning Matter device (_matterc._udp)",
    kind  = "commissioning",
  },
  {
    qname = "_meshcop._udp.local",
    label = "Thread border router (_meshcop._udp)",
    kind  = "meshcop",
  },
}

-- Vendor IDs from connectedhomeip src/lib/core/CHIPVendorIdentifiers.hpp.
-- The full CSA registry is much larger; unknown IDs are shown as raw hex.
local VENDOR_NAMES = {
  [0x0000] = "Common / Unspecified",
  [0x1349] = "Apple",
  [0x6006] = "Google",
  [0xFFF1] = "Test Vendor 1",
  [0xFFF2] = "Test Vendor 2",
  [0xFFF3] = "Test Vendor 3",
  [0xFFF4] = "Test Vendor 4",
  [0xFFFF] = "Not Specified",
}

-- Device type IDs extracted from connectedhomeip
-- src/app/zap-templates/zcl/data-model/chip/matter-devices.xml.
local DEVICE_TYPE_NAMES = {
  [0x000A] = "Door Lock",
  [0x000B] = "Door Lock Controller",
  [0x000E] = "Aggregator",
  [0x000F] = "Generic Switch",
  [0x0011] = "Power Source",
  [0x0012] = "OTA Requestor",
  [0x0013] = "Bridged Node",
  [0x0014] = "OTA Provider",
  [0x0015] = "Contact Sensor",
  [0x0016] = "Root Node",
  [0x0017] = "Solar Power",
  [0x0018] = "Battery Storage",
  [0x0019] = "Secondary Network Interface",
  [0x0022] = "Speaker",
  [0x0023] = "Casting Video Player",
  [0x0024] = "Content App",
  [0x0027] = "Mode Select",
  [0x0028] = "Basic Video Player",
  [0x0029] = "Casting Video Client",
  [0x002A] = "Video Remote Control",
  [0x002B] = "Fan",
  [0x002C] = "Air Quality Sensor",
  [0x002D] = "Air Purifier",
  [0x0041] = "Water Freeze Detector",
  [0x0042] = "Water Valve",
  [0x0043] = "Water Leak Detector",
  [0x0044] = "Rain Sensor",
  [0x0045] = "Soil Sensor",
  [0x0070] = "Refrigerator",
  [0x0071] = "Temperature Controlled Cabinet",
  [0x0072] = "Room Air Conditioner",
  [0x0073] = "Laundry Washer",
  [0x0074] = "Robotic Vacuum Cleaner",
  [0x0075] = "Dishwasher",
  [0x0076] = "Smoke CO Alarm",
  [0x0077] = "Cook Surface",
  [0x0078] = "Cooktop",
  [0x0079] = "Microwave Oven",
  [0x007A] = "Extractor Hood",
  [0x007B] = "Oven",
  [0x007C] = "Laundry Dryer",
  [0x0090] = "Network Infrastructure Manager",
  [0x0091] = "Thread Border Router",
  [0x0100] = "On/Off Light",
  [0x0101] = "Dimmable Light",
  [0x0103] = "On/Off Light Switch",
  [0x0104] = "Dimmer Switch",
  [0x0105] = "Color Dimmer Switch",
  [0x0106] = "Light Sensor",
  [0x0107] = "Occupancy Sensor",
  [0x010A] = "On/Off Plug-in Unit",
  [0x010B] = "Dimmable Plug-in Unit",
  [0x010C] = "Color Temperature Light",
  [0x010D] = "Extended Color Light",
  [0x010F] = "Mounted On/Off Control",
  [0x0110] = "Mounted Dimmable Load Control",
  [0x0130] = "Joint Fabric Administrator",
  [0x0202] = "Window Covering",
  [0x0203] = "Window Covering Controller",
  [0x0301] = "Thermostat",
  [0x0302] = "Temperature Sensor",
  [0x0303] = "Pump",
  [0x0304] = "Pump Controller",
  [0x0305] = "Pressure Sensor",
  [0x0306] = "Flow Sensor",
  [0x0307] = "Humidity Sensor",
  [0x0309] = "Heat Pump",
  [0x030A] = "Thermostat Controller",
  [0x050C] = "EVSE",
  [0x050D] = "Device Energy Management",
  [0x050F] = "Water Heater",
  [0x0510] = "Electrical Sensor",
  [0x0840] = "Control Bridge",
  [0x0850] = "On/Off Sensor",
}

-- Commissioning mode values, from connectedhomeip
-- src/lib/dnssd/Advertiser.h enum CommissioningMode.
local CM_MODES = {
  [0] = "disabled",
  [1] = "basic commissioning mode",
  [2] = "enhanced commissioning mode",
  [3] = "joint fabric commissioning mode",
}

-- Pairing hint bitmap (PH TXT key) bit definitions, from
-- Matter Core Specification section 5.4.2.3.2.
local PAIRING_HINT_BITS = {
  { mask = 0x00001, desc = "Power cycle" },
  { mask = 0x00002, desc = "Device manufacturer URL (in PI)" },
  { mask = 0x00004, desc = "Administrator" },
  { mask = 0x00008, desc = "Settings menu on the device" },
  { mask = 0x00010, desc = "Custom instruction (in PI)" },
  { mask = 0x00020, desc = "Device manual" },
  { mask = 0x00040, desc = "Press reset button" },
  { mask = 0x00080, desc = "Press reset button with power" },
  { mask = 0x00100, desc = "Press reset button for N seconds" },
  { mask = 0x00200, desc = "Press reset button until light blinks" },
  { mask = 0x00400, desc = "Press reset button for N seconds with power" },
  { mask = 0x00800, desc = "Press reset until light blinks with power" },
  { mask = 0x01000, desc = "Press setup button" },
  { mask = 0x02000, desc = "Press setup button with power" },
  { mask = 0x04000, desc = "Press setup button for N seconds" },
  { mask = 0x08000, desc = "Press setup button until light blinks" },
  { mask = 0x10000, desc = "Press setup button for N seconds with power" },
  { mask = 0x20000, desc = "Press setup until light blinks with power" },
}


-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

--; Format a Vendor ID with its CSA name (when known).
local function fmt_vendor(vid)
  local name = VENDOR_NAMES[vid]
  if name then
    return string.format("0x%04X (%s)", vid, name)
  end
  return string.format("0x%04X", vid)
end

--; Format a device type ID with its Matter device-library name (when known).
local function fmt_devtype(dt)
  local name = DEVICE_TYPE_NAMES[dt]
  if name then
    return string.format("0x%04X (%s)", dt, name)
  end
  return string.format("0x%04X", dt)
end

--; Decode the 32-bit PH bitmap into a human-readable hint list.
local function fmt_pairing_hint(ph_str)
  local ph = tonumber(ph_str)
  if not ph then return ph_str end
  local hints = {}
  for _, entry in ipairs(PAIRING_HINT_BITS) do
    if ph & entry.mask ~= 0 then
      hints[#hints + 1] = entry.desc
    end
  end
  if #hints == 0 then return tostring(ph) end
  return string.format("%d (%s)", ph, table.concat(hints, "; "))
end

--; Strip a service-type FQDN suffix from a service-instance FQDN.
--  "Inst._matter._tcp.local" minus "_matter._tcp.local" -> "Inst".
local function strip_service_suffix(fqdn, service_qname)
  local suffix = "." .. service_qname
  if fqdn:sub(-#suffix) == suffix then
    return fqdn:sub(1, #fqdn - #suffix)
  end
  return fqdn
end

--; Parse a single DNS-SD TXT string ("KEY=VALUE" or bare flag) into kv.
local function parse_txt_string(str, kv)
  local k, v = str:match("^([^=]+)=(.*)$")
  if k then
    kv[k] = v
  else
    kv[str] = true
  end
end


-- ---------------------------------------------------------------------------
-- mDNS query / response handling
-- ---------------------------------------------------------------------------

--; Send a PTR query for `qname` to `host` on UDP port 5353 (mDNS).
--  Returns a decoded packet on success, or nil on timeout / failure.
local function query_mdns(host, qname)
  local status, response = dns.query(qname, {
    host      = (type(host) == "table") and host.ip or host,
    port      = MDNS_PORT,
    proto     = "udp",
    dtype     = "PTR",
    retPkt    = true,
    retAll    = true,
    sendCount = 1,
    timeout   = QUERY_TIMEOUT,
  })
  if not status then return nil end
  return response
end

--; Walk the additional/answer sections of a decoded mDNS packet and
--  collect TXT key/value pairs and the SRV port/target for `instance_fqdn`.
local function collect_instance_records(response, instance_fqdn)
  local txt_kv, srv_port, srv_target = {}, nil, nil

  local function process(rrs)
    for _, rr in ipairs(rrs or {}) do
      if rr.dname == instance_fqdn then
        if rr.dtype == dns.types.TXT and rr.TXT and rr.TXT.text then
          for _, txt_str in ipairs(rr.TXT.text) do
            if #txt_str > 0 then parse_txt_string(txt_str, txt_kv) end
          end
        elseif rr.dtype == dns.types.SRV and rr.SRV then
          srv_port   = srv_port or rr.SRV.port
          srv_target = srv_target or rr.SRV.target
        end
      end
    end
  end

  process(response.answers)
  process(response.add)

  return txt_kv, srv_port, srv_target
end


-- ---------------------------------------------------------------------------
-- Output formatters (one per Matter service kind)
-- ---------------------------------------------------------------------------

--; Build an output table for a commissioned (_matter._tcp) device.
local function build_operational_output(instance, txt, srv_port, srv_target)
  local t = stdnse.output_table()
  t["Instance"] = instance

  -- Instance name encodes "FabricID-NodeID", each as a 16-hex-char value.
  local fid, nid = instance:match("^(%x+)%-(%x+)$")
  if fid and nid then
    t["Fabric ID"] = "0x" .. fid:upper()
    t["Node ID"]   = "0x" .. nid:upper()
  end

  if txt["T"]   then
    t["TCP support"] = (txt["T"] == "1") and "yes" or "no"
  end
  if txt["SII"] then t["Session Idle Interval"]    = txt["SII"] .. " ms" end
  if txt["SAI"] then t["Session Active Interval"]  = txt["SAI"] .. " ms" end
  if txt["SAT"] then t["Session Active Threshold"] = txt["SAT"] .. " ms" end
  if txt["ICD"] and txt["ICD"] ~= "0" then
    t["Intermittently Connected Device"] = "yes"
  end
  if srv_port   then t["Port"] = tostring(srv_port) end
  if srv_target then t["Host"] = srv_target end
  return t
end

--; Build an output table for a commissioning-mode (_matterc._udp) device.
local function build_commissioning_output(instance, txt, srv_port, srv_target)
  local t = stdnse.output_table()
  t["Instance"] = instance

  if txt["VP"] then
    -- VP encodes "VendorID+ProductID" in decimal.
    local vid_s, pid_s = txt["VP"]:match("^(%d+)%+(%d+)$")
    if vid_s then
      t["Vendor ID"]  = fmt_vendor(tonumber(vid_s))
      t["Product ID"] = string.format("0x%04X", tonumber(pid_s))
    else
      t["VP"] = txt["VP"]
    end
  end

  if txt["DT"] then t["Device type"] = fmt_devtype(tonumber(txt["DT"])) end
  if txt["DN"] then t["Device name"]  = txt["DN"] end
  if txt["D"]  then t["Discriminator"] = txt["D"] end
  if txt["CM"] then
    local cm = tonumber(txt["CM"]) or 0
    t["Commissioning mode"] =
      string.format("%d (%s)", cm, CM_MODES[cm] or "unknown")
  end
  if txt["JF"] then t["Joint fabric mode"]   = txt["JF"] end
  if txt["RI"] then t["Rotating device ID"]  = txt["RI"] end
  if txt["PH"] then t["Pairing hint"]        = fmt_pairing_hint(txt["PH"]) end
  if txt["PI"] and txt["PI"] ~= "" then
    t["Pairing instruction"] = txt["PI"]
  end
  if txt["CP"] then t["Commissioner passcode"] = txt["CP"] end
  if txt["T"]  then
    t["TCP support"] = (txt["T"] == "1") and "yes" or "no"
  end
  if txt["SII"] then t["Session Idle Interval"]    = txt["SII"] .. " ms" end
  if txt["SAI"] then t["Session Active Interval"]  = txt["SAI"] .. " ms" end
  if txt["SAT"] then t["Session Active Threshold"] = txt["SAT"] .. " ms" end
  if txt["ICD"] and txt["ICD"] ~= "0" then
    t["Intermittently Connected Device"] = "yes"
  end
  if srv_port   then t["Port"] = tostring(srv_port) end
  if srv_target then t["Host"] = srv_target end
  return t
end

--; Build an output table for a Thread border router (_meshcop._udp).
local function build_meshcop_output(instance, txt, srv_port, srv_target)
  local t = stdnse.output_table()
  t["Instance"] = instance
  if txt["nn"] then t["Network name"]      = txt["nn"] end
  if txt["xp"] then t["Extended PAN ID"]   = txt["xp"] end
  if txt["tv"] then t["Thread version"]    = txt["tv"] end
  if txt["xa"] then t["Extended address"]  = txt["xa"] end
  if txt["pt"] then t["Border agent port"] = txt["pt"] end
  if txt["sq"] then t["Sequence number"]   = txt["sq"] end
  if txt["bb"] then t["BBR seq number"]    = txt["bb"] end
  if txt["sb"] then
    local sb = tonumber(txt["sb"], 16) or tonumber(txt["sb"])
    t["State bitmap"] = sb and string.format("0x%X", sb) or txt["sb"]
  end
  if srv_port   then t["Port"] = tostring(srv_port) end
  if srv_target then t["Host"] = srv_target end
  return t
end

local OUTPUT_BUILDERS = {
  operational   = build_operational_output,
  commissioning = build_commissioning_output,
  meshcop       = build_meshcop_output,
}


-- ---------------------------------------------------------------------------
-- Discovery driver
-- ---------------------------------------------------------------------------

--; For one Matter service type, query mDNS and return a list of
--  { label, info } device tables (possibly empty).
local function discover_service(host, svc)
  local response = query_mdns(host, svc.qname)
  if not response then return {} end

  local devices = {}

  for _, ans in ipairs(response.answers or {}) do
    if ans.dtype == dns.types.PTR and ans.dname == svc.qname
       and ans.domain then
      local instance_fqdn = ans.domain
      local instance = strip_service_suffix(instance_fqdn, svc.qname)

      local txt_kv, srv_port, srv_target =
        collect_instance_records(response, instance_fqdn)

      local builder = OUTPUT_BUILDERS[svc.kind]
      if builder then
        devices[#devices + 1] = {
          label = svc.label,
          info  = builder(instance, txt_kv, srv_port, srv_target),
        }
      end
    end
  end

  return devices
end


-- ---------------------------------------------------------------------------
-- NSE entry points
-- ---------------------------------------------------------------------------

--; Match either mDNS (5353/udp) or Matter operational (5540) ports.
portrule = function(host, port)
  return shortport.portnumber(MDNS_PORT, "udp")(host, port)
      or port.number == MATTER_PORT
end

action = function(host, port)
  -- For port 5540 we just flag the open port; mDNS yields richer info.
  if port.number == MATTER_PORT then
    return ("Matter operational port is open " ..
            "(run with -p 5353/udp for mDNS device details)")
  end

  local all_devices = {}
  for _, svc in ipairs(MATTER_SERVICES) do
    for _, dev in ipairs(discover_service(host, svc)) do
      all_devices[#all_devices + 1] = dev
    end
  end

  if #all_devices == 0 then return nil end

  -- Build the top-level output table; number duplicate service labels.
  local output     = stdnse.output_table()
  local label_seen = {}
  for _, d in ipairs(all_devices) do
    label_seen[d.label] = (label_seen[d.label] or 0) + 1
  end

  local label_idx = {}
  for _, d in ipairs(all_devices) do
    local key
    if label_seen[d.label] == 1 then
      key = d.label
    else
      label_idx[d.label] = (label_idx[d.label] or 0) + 1
      key = string.format("%s #%d", d.label, label_idx[d.label])
    end
    output[key] = d.info
  end

  return output
end
