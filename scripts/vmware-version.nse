description = [[
Queries VMware server (vCenter, ESX, ESXi) SOAP API to extract the version information.

The same script as VMware Fingerprinter from VASTO created by Claudio Criscione, Paolo Canaletti
]]

---
-- @usage
-- nmap --script vmware-version -p443 <host>
--
-- @output
-- | vmware-version:
-- |   Server version: VMware ESX 4.1.0
-- |   Build: 348481
-- |   Locale version: INTL 000
-- |   OS type: vmnix-x86
-- |_  Product Line ID: esx
----------------------------------------------------------

author = "Alexey Tyurin"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

portrule = function (host, port)
  if nmap.version_intensity() < 7 or nmap.port_is_excluded(port.number, port.protocol) then
    return false
  end
  return shortport.http(host, port)
end

local function get_file(host, port, path)
  local req
  req='<soap:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header><operationID>00000001-00000001</operationID></soap:Header><soap:Body><RetrieveServiceContent xmlns="urn:internalvim25"><_this xsi:type="ManagedObjectReference" type="ServiceInstance">ServiceInstance</_this></RetrieveServiceContent></soap:Body></soap:Envelope>'

  local result = http.post( host, port, path, nil, nil, req)
  if(result['status'] ~= 200 or result['content-length'] == 0) then
    return false, "Couldn't download file: " .. path
  end

  return true, result.body
end

action = function(host, port)

  local result, body = get_file(host, port, "/sdk")

  if(not(result)) then
    stdnse.debug1("%s", body)
    return nil
  end

  local vwname = body:match("<name>([^<]*)</name>")

  if not vwname then
    stdnse.debug1("Problem with XML parsing.")
    return nil
  end

  local vwversion = body:match("<version>([^<]*)</version>")
  local vwbuild = body:match("<build>([^<]*)</build>")
  local vwlversion = body:match("<localeVersion>([^<]*)</localeVersion>")
  local vwlbuild = body:match("<localeBuild>([^<]*)</localeBuild>")
  local vmostype = body:match("<osType>([^<]*)</osType>")
  local vmprod= body:match("<productLineId>([^<]*)</productLineId>")

  if not port.version.product then
    port.version.product = ("%s SOAP API"):format(vwname)
    port.version.version = vwversion
  end
  table.insert(port.version.cpe, ("cpe:/o:vmware:%s:%s"):format(vwname:gsub("^[Vv][Mm][Ww]are ", ""), vwversion))
  nmap.set_port_version(host, port, "hardmatched")

  local response = stdnse.output_table()

  response["Server version"] = ("%s %s"):format(vwname, vwversion)
  response["Build"] = vwbuild
  response["Locale version"] = ("%s %s"):format(vwlversion, vwlbuild)
  response["OS type"] = vmostype
  response["Product Line ID"] = vmprod

  return response
end
