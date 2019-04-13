description = [[
Attempts to extract information from HP iLO boards including versions and addresses.

HP iLO boards have an unauthenticated info disclosure at <ip>/xmldata?item=all.
It lists board informations such as server model, firmware version,
MAC addresses, IP addresses, etc. This script uses the slaxml library
to parse the iLO xml file and display the info.
]]

---
--@usage nmap --script hp-ilo-info -p 80 <target>
--
--@usage nmap --script hp-ilo-info -sV <target>
--
--@output
--PORT   STATE SERVICE
--80/tcp open  http
--| ilo-info:
--|   ServerType: ProLiant MicroServer Gen8
--|   ProductID: XXXXXX-XXX
--|   UUID: XXXXXXXXXXXXXXXX
--|   cUUID: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX
--|   ILOType: Integrated Lights-Out 4 (iLO 4)
--|   ILOFirmware: X.XX
--|   SerialNo: ILOXXXXXXXXXX
--|   NICs:
--|     NIC 1:
--|       Description: iLO 4
--|       MacAddress: 12:34:56:78:9a:bc
--|       IPAddress: 10.10.10.10
--|       Status: OK
--|     NIC 2:
--|       Description: iLo 4
--|       MacAddress: 11:22:33:44:55:66
--|       IPAddress: Unknown
--|_      Status: Disabled
--

author = "Rajeev R Menon"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe","discovery"}

local http = require "http"
local slaxml = require "slaxml"
local stdnse = require "stdnse"
local shortport = require "shortport"

portrule = shortport.http

function getTag(table,tag)
  for _,n in ipairs(table.kids) do
    if n.type == "element" and n.name == tag then
      return n
    elseif n.type == "element" then
      local ret =  getTag(n,tag)
      if ret ~= nil then return ret end
    end
  end
  return nil
end

function parseXML(dom)
  local response = stdnse.output_table()
  local info = stdnse.output_table()
  info['ServerType'] = getTag(dom,"SPN")
  info['ProductID'] = getTag(dom,"PRODUCTID")
  info['UUID'] = getTag(dom,"UUID")
  info['cUUID'] = getTag(dom,"cUUID")
  info['ILOType'] = getTag(dom,"PN")
  info['ILOFirmware'] = getTag(dom,"FWRI")
  info['SerialNo'] = getTag(dom,"SN")

  for key,_ in pairs(info) do
    if info[key] ~= nil then
      response[tostring(key)] = info[key].kids[1].value
    end
  end

  response.NICs = stdnse.output_table()
  local nicdom = getTag(dom,"NICS")
  if nicdom ~= nil then
  local count = 1
  for _,n in ipairs(nicdom.kids) do
    local nic = stdnse.output_table()
    info = stdnse.output_table()
    for k,m in ipairs(n.kids) do
      if #m.kids >= 1 and m.kids[1].type == "text" then
        if m.name == "DESCRIPTION" then
          info["Description"] = m.kids[1].value
        elseif m.name == "MACADDR" then
          info["MacAddress"] = m.kids[1].value
        elseif m.name == "IPADDR" then
          info["IPAddress"] = m.kids[1].value
        elseif m.name == "STATUS" then
          info["Status"] = m.kids[1].value
        end
      end
    end
    for key,_ in pairs(info) do
      nic[tostring(key)] = info[key]
    end
    response.NICs["NIC "..tostring(count)] = nic
    count = count + 1
    end
  end
  return response
end

action = function(host,port)
  local response = http.get(host,port,"/xmldata?item=all")
  if response["status"] ~= 200
    or not response.body
    or not response.body:match('<RIMP>')
    or not response.body:match('iLO')
  then
    return
  end
  local domtable = slaxml.parseDOM(response["body"],{stripWhitespace=true})
  return parseXML(domtable)
end
