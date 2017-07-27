local http = require "http"
local table = require "table"
local shortport = require "shortport"
local stdnse = require "stdnse"
local slaxml = require "slaxml"
local nmap = require "nmap"

description = [[
Retrieve hardwares details and configuration information utilizing HNAP, the "Home Network Administration Protocol".
It is an HTTP-Simple Object Access Protocol (SOAP)-based protocol which allows for remote topology discovery,
configuration, and management of devices (routers, cameras, PCs, NAS, etc.)]]

---
-- @usage
-- nmap --script hnap-info -p80,8080 <target>
--
-- @output
-- PORT     STATE SERVICE    REASON
-- 8080/tcp open  http-proxy syn-ack
-- | hnap-info:
-- |   Type: GatewayWithWiFi
-- |   Device: Ingraham
-- |   Vendor: Linksys
-- |   Description: Linksys E1200
-- |   Model: E1200
-- |   Firmware: 1.0.00 build 11
-- |   Presentation URL: http://192.168.1.1/
-- |   SOAPACTIONS:
-- |     http://purenetworks.com/HNAP1/IsDeviceReady
-- |     http://purenetworks.com/HNAP1/GetDeviceSettings
-- |     http://purenetworks.com/HNAP1/SetDeviceSettings
-- |     http://purenetworks.com/HNAP1/GetDeviceSettings2
-- |     http://purenetworks.com/HNAP1/SetDeviceSettings2
--
--
-- @xmloutput
-- <elem key="Type">GatewayWithWiFi</elem>
-- <elem key="Device">Ingraham</elem>
-- <elem key="Vendor">Linksys</elem>
-- <elem key="Description">Linksys E1200</elem>
-- <elem key="Model">E1200</elem>
-- <elem key="Firmware">1.0.00 build 11</elem>
-- <elem key="Presentation URL">http://192.168.1.1/</elem>
-- <table key="SOAPACTIONS">
--   <elem>http://purenetworks.com/HNAP1/IsDeviceReady</elem>
--   <elem>http://purenetworks.com/HNAP1/GetDeviceSettings</elem>
--   <elem>http://purenetworks.com/HNAP1/SetDeviceSettings</elem>
--   <elem>http://purenetworks.com/HNAP1/GetDeviceSettings2</elem>
--   <elem>http://purenetworks.com/HNAP1/SetDeviceSettings2</elem>
-- </table>
-----------------------------------------------------------------------

author = "Gyanendra Mishra"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {
  "safe",
  "discovery",
  "default",
  "version"
}


portrule = function(host, port)
  return (shortport.http(host,port) and nmap.version_intensity() >= 7)
end

local ELEMENTS = {["Type"] = "Type",
["DeviceName"] = "Device",
["VendorName"] = "Vendor",
["ModelDescription"] = "Description",
["ModelName"] = "Model",
["FirmwareVersion"] = "Firmware",
["PresentationURL"] = "Presentation URL",
["string"] = "SOAPACTIONS",
["SubDeviceURLs"] = "Sub Device URLs"}

function get_text_callback(store, name)
  if ELEMENTS[name] == nil then return end
  name = ELEMENTS[name]
  if name == 'SOAPACTIONS' or name == 'Sub Device URLs' or name == 'Type' then
    return function(content)
      store[name] = store[name] or {}
      table.insert(store[name], content)
    end
  else
    return function(content)
      store[name] = content
    end
  end
end

function action (host, port)

  -- Identify servers that answer 200 to invalid HTTP requests and exit as these would invalidate the tests
  local status_404, result_404, _ = http.identify_404(host,port)
  if ( status_404 and result_404 == 200 ) then
    stdnse.debug1("Exiting due to ambiguous response from web server on %s:%s. All URIs return status 200.", host.ip, port.number)
    return nil
  end

  local output = stdnse.output_table()
  local response = http.get(host, port, '/HNAP1')
  if response.status and response.status == 200 then
    local parser = slaxml.parser:new()
    parser._call = {startElement = function(name)
      parser._call.text = get_text_callback(output, name) end,
      closeElement = function(name) parser._call.text = function() return nil end end
    }
    parser:parseSAX(response.body, {stripWhitespace=true})

    -- exit if the parser does not return output
    if not next(output) then return nil end

    -- set the port verson
    port.version.name = "hnap"
    port.version.name_confidence = 10
    port.version.product = output["Description"] or nil
    port.version.version = output["Model"] or nil
    port.version.devicetype = output["Type"] and output["Type"][1] or nil
    port.version.cpe = port.version.cpe or {}

    if output["Vendor"] and output["Model"] then
      table.insert(port.version.cpe, "cpe:/h:".. output["Vendor"]:lower() .. ":" .. output["Model"]:lower())
    end
    nmap.set_port_version(host, port, "hardmatched")

    return output
  end
end

