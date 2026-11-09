local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Attempts to obtain information from Trane Tracer SC devices. Trane Tracer SC
 is an intelligent field panel for communicating with HVAC equipment controllers
 deployed across several sectors including commercial facilities and others.

The information is obtained from the web server that exposes sensitive content to
 unauthenticated users.

References:
* http://websec.mx/publicacion/blog/Scripts-de-Nmap-para-Trane-Tracer-SC-HVAC
]]

---
-- @usage nmap -p80,443 --script http-trane-info <target>
--
-- @output
-- | http-trane-info:
-- |   serverName: XXXXX
-- |   serverTime: 2017-09-24T01:03:08-05:00
-- |   serverBootTime: 2017-08-03T02:06:39-05:00
-- |   vendorName: Trane
-- |   productName: Tracer SC
-- |   productVersion: v4.20.1128 (release)
-- |   kernelVersion: 2.6.30_HwVer12AB-hydra
-- |   hardwareType: HwVer12AB
-- |   hardwareSerialNumber: XXXXX
-- |   devices:
-- |
-- |       equipmentUri: /equipment/dac/generic/1
-- |       displayName: RTU-01
-- |       deviceName: RTU-01
-- |       equipmentFamily: AirHandler
-- |       roleDocument: BCI-I_9a8c9b8116cd392fc0b4a233405f3f5964fa6b885809c810a8d0ed5478XXXXXX__RTU_Ipak_VAV
-- |_      isOffline: false
--
-- @xmloutput
-- <elem key="serverName">XXXXX</elem>
-- <elem key="serverTime">2017-09-24T01:05:28-05:00</elem>
-- <elem key="serverBootTime">2017-08-03T02:06:39-05:00</elem>
-- <elem key="vendorName">Trane</elem>
-- <elem key="productName">Tracer SC</elem>
-- <elem key="productVersion">v4.20.1128 (release)</elem>
-- <elem key="kernelVersion">2.6.30_HwVer12AB-hydra</elem>
-- <elem key="hardwareType">HwVer12AB</elem>
-- <elem key="hardwareSerialNumber">XXXXX</elem>
-- <table key="devices">
-- <table>
-- <elem key="equipmentUri">/equipment/dac/generic/1</elem>
-- <elem key="displayName">RTU-01</elem>
-- <elem key="deviceName">RTU-01</elem>
-- <elem key="equipmentFamily">AirHandler</elem>
-- <elem key="roleDocument">BCI-I_9a8c9b8116cd392fc0b4a233405f3f5964fa6b885809c810a8d0ed5478XXXXX__RTU_Ipak_VAV</elem>
-- <elem key="isOffline">false</elem>
-- </table></table>
---

author = "Pedro Joaquin <pjoaquin()websec.mx>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "version", "safe"}

portrule = function(host, port)
  return (shortport.http(host, port) and nmap.version_intensity() >= 7)
end

local ABOUT_URI = "/evox/about"
local SUMMARY_URI = "/evox/equipment/installedSummary"

local ABOUT_KEYS = {"serverName", "serverTime", "serverBootTime", "vendorName",
  "productName", "productVersion", "kernelVersion", "hardwareType",
  "hardwareSerialNumber"}
local DEVICE_KEYS = {"equipmentUri", "displayName", "deviceName",
  "equipmentFamily", "roleDocument", "isOffline"}

local function get_val(xml, key)
  return xml:match('name="' .. key .. '"%s+val="([^"]*)"')
end

-- Copy every key in keylist that exists in xml into an ordered table.
local function collect(xml, keylist)
  local out = stdnse.output_table()
  for _, key in ipairs(keylist) do
    local v = get_val(xml, key)
    if v then
      out[key] = v
    else
      stdnse.debug2("Key not present: %s", key)
    end
  end
  return out
end

local function parse_devices(xml)
  local starts = {}
  local init = 1
  while true do
    local s = xml:find('name="equipmentUri"', init, true)
    if not s then break end
    starts[#starts + 1] = s
    init = s + 1
  end

  local devices = {}
  for i, s in ipairs(starts) do
    local e = starts[i + 1] or (#xml + 1)
    local device = collect(xml:sub(s, e - 1), DEVICE_KEYS)
    table.insert(devices, device)
  end
  return devices
end

local function get_page(host, port, uri, result_404, known_404)
  -- Never follow redirects: a redirect to a generic landing page would come
  -- back as a 200 and be mistaken for the Evox endpoint.
  local response = http.get(host, port, uri, {redirect_ok = false})
  if response.status ~= 200 or not response.body then
    stdnse.debug1("%s: %s", uri, response["status-line"] or "no response")
    return nil
  end
  -- Compare against the server's "200 for everything" page, if it has one.
  if not http.page_exists(response, result_404, known_404, uri, false) then
    stdnse.debug1("%s matches the server's generic 200 page", uri)
    return nil
  end
  return response
end

-- CPE 2.2 URI components: lowercase, spaces to "_", anything else outside
-- [A-Za-z0-9._-] percent-encoded (Nmap writes tracer_sc%2b, never tracer_sc+).
local function cpe_component(s)
  s = s:lower():gsub("%s+", "_")
  return (s:gsub("[^%w%._%-]", function(c)
    return ("%%%02x"):format(c:byte())
  end))
end

local function set_version(host, port, info)
  port.version.name = "http"
  port.version.name_confidence = 10
  if info.vendorName and info.productName then
    port.version.product = info.vendorName .. " " .. info.productName
    table.insert(port.version.cpe, ("cpe:/h:%s:%s"):format(
      cpe_component(info.vendorName), cpe_component(info.productName)))
  end
  if info.productVersion then
    port.version.version = info.productVersion
  end
  port.version.devicetype = "specialized"
  nmap.set_port_version(host, port, "hardmatched")
end

action = function(host, port)
  -- Learn how this server answers requests for pages that do not exist.
  -- identify_404 returns false when it cannot tell (for example 200 with a
  -- body that changes on every request); treat that as "cannot trust a 200".
  local status_404, result_404, known_404 = http.identify_404(host, port)
  if not status_404 then
    stdnse.debug1("Cannot characterize 404 behavior on %s:%s (%s); exiting.",
      host.ip, port.number, tostring(result_404))
    return nil
  end

  local about = get_page(host, port, ABOUT_URI, result_404, known_404)
  if not about then
    return nil
  end

  if not get_val(about.body, "serverName") then
    stdnse.debug1("%s is not Evox XML (no serverName element)", ABOUT_URI)
    return nil
  end
  local output = collect(about.body, ABOUT_KEYS)

  local summary = get_page(host, port, SUMMARY_URI, result_404, known_404)
  if summary then
    if summary.body:find("Error code: 00017", 1, true) then
      stdnse.debug1("%s is not available on this device", SUMMARY_URI)
    else
      local devices = parse_devices(summary.body)
      if #devices > 0 then
        output.devices = devices
      else
        stdnse.debug1("%s returned no installed equipment", SUMMARY_URI)
      end
    end
  end

  set_version(host, port, output)
  return output
end
