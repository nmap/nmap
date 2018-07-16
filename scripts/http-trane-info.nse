local nmap = require "nmap"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local shortport = require "shortport"
local table = require "table"

description = [[
Attempts to obtain information from Trane Tracer SC devices. Trane Tracer SC
 is an intelligent field panel for communicating with HVAC equipment controllers
 deployed across several sectors including commercial facilities and others.

The information is obtained from the web server that exposes sensitive content to
 unauthenticated users.

Tested on Trane Tracer SC version 4.40.1211 and below.

References:
* http://websec.mx/publicacion/blog/Scripts-de-Nmap-para-Trane-Tracer-SC-HVAC
]]

---
-- @usage nmap -p80 --script trane-info.nse <target>
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
-- |       isOffline: false 
-- |       equipmentUri: /equipment/dac/generic/1 
-- |       displayName: RTU-01 
-- |       equipmentFamily: AirHandler 
-- |       roleDocument: BCI-I_9a8c9b8116cd392fc0b4a233405f3f5964fa6b885809c810a8d0ed5478XXXXXX__RTU_Ipak_VAV 
-- |       deviceName: RTU-01 
--
-- @xmloutput
-- <elem key="serverName">XXXXX </elem>
-- <elem key="serverTime">2017-09-24T01:05:28-05:00 </elem>
-- <elem key="serverBootTime">2017-08-03T02:06:39-05:00 </elem>
-- <elem key="vendorName">Trane </elem>
-- <elem key="productName">Tracer SC </elem>
-- <elem key="productVersion">v4.20.1128 (release) </elem>
-- <elem key="kernelVersion">2.6.30_HwVer12AB-hydra </elem>
-- <elem key="hardwareType">HwVer12AB </elem>
-- <elem key="hardwareSerialNumber">XXXXX </elem>
-- <table key="devices">
-- <table>
-- <elem key="equipmentUri">/equipment/dac/generic/1 </elem>
-- <elem key="equipmentFamily">AirHandler </elem>
-- <elem key="deviceName">RTU-01 </elem>
-- <elem key="isOffline">false </elem>
-- <elem key="roleDocument">BCI-I_9a8c9b8116cd392fc0b4a233405f3f5964fa6b885809c810a8d0ed5478XXXXX__RTU_Ipak_VAV </elem>
-- <elem key="displayName">RTU-01 </elem>
-- </table></table>
---

author = "Pedro Joaquin <pjoaquin()websec.mx>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "version", "safe"}

portrule = function(host, port)
  return (shortport.http(host,port) and nmap.version_intensity() >= 7)
end

local function GetInformation(host, port)
  local output = stdnse.output_table()
  --Get information from /evox/about
  local uri = '/evox/about'
  local response = http.get(host, port, uri)
  if response['status-line'] and response['status-line']:match("200") then
    --Verify parsing of XML from /evox/about
    local deviceType = response['body']:match('serverName" val=([^<]*)/>')
    if not deviceType then
      stdnse.debug1("Problem with XML parsing of /evox/about")
      return nil,"Problem with XML parsing of /evox/about"
    end

    --Parse information from /evox/about
    local keylist = {"serverName","serverTime","serverBootTime","vendorName","productName","productVersion","kernelVersion","hardwareType","hardwareSerialNumber"}
    for _,key in ipairs(keylist) do
      stdnse.debug2("Looking for : "..key)
      output[key] = response['body']:match(key..'" val=([^<]*)/>')
      stdnse.debug2("Found : "..output[key])
      output[key] = output[key]:gsub('"', "")
    end

	
	
    --Get information from /evox/equipment/installedSummary
    local uri = '/evox/equipment/installedSummary'
    local response = http.get(host, port, uri)
    if response['status-line'] and response['status-line']:match("200") then
      --Verify parsing of XML from /evox/equipment/installedSummary
      local error = response['body']:match('Error code: 00017')
      if error then
        stdnse.debug1("/evox/equipment/installedSummary is not available")
      end
      local equipmentUri = response['body']:match('equipmentUri" val=([^<]*)/>')
      if not equipmentUri then
        stdnse.debug1("Problem with XML parsing")
      end
      if not error then
        --Parse information from /evox/equipment/installedSummary
        local keylist = {"equipmentUri","displayName","deviceName","equipmentFamily","roleDocument","isOffline"}
        local _,lastequipmentUri = response['body']:find(".*equipmentUri")
	stdnse.debug2("lastequipmentUri : "..lastequipmentUri)
	local count = 1
	local nextequipmentUri = 1
        local devices = {}
	while nextequipmentUri < lastequipmentUri do
          local device = {}
          for _,key in ipairs(keylist) do
            stdnse.debug2("Looking for : "..key)
            device[key] = response['body']:match(key..'" val=([^<]*)/>',nextequipmentUri)
            if not device[key] then
              device[key] = "Not available"
            else
              device[key] = device[key]:gsub('"', "")
              stdnse.debug2("Found : ".. device[key])
            end
	  end
          _,nextequipmentUri = response['body']:find("equipmentUri",nextequipmentUri)
          table.insert(devices, device)
          count = count + 1
        end
        output["devices"] = devices
    end
  end
  stdnse.debug2("status-line: "..response['status-line'])
  local error = response['status-line']:match('Error')
  if error then
    stdnse.debug2("Request returned a network error.")
    return nil, "Request returned a network error."
  end

  -- Set the port version
  port.version.name = "http"
  port.version.name_confidence = 10
  port.version.product = output["productName"] 
  port.version.version = output["productVersion"] 
  port.version.devicetype = output["hardwareType"] 
  table.insert(port.version.cpe, "cpe:/h:".. output["vendorName"] .. ":" .. output["productName"])

  nmap.set_port_version(host, port, "hardmatched")
  return output
  end
end

action = function(host,port)

  -- Identify servers that answer 200 to invalid HTTP requests and exit as these would invalidate the tests
  local status_404, result_404, _ = http.identify_404(host,port)
  if ( status_404 and result_404 == 200 ) then
    stdnse.debug1("Exiting due to ambiguous response from web server on %s:%s. All URIs return status 200.", host.ip, port.number)
    return nil
  end

  return GetInformation(host, port)
end
