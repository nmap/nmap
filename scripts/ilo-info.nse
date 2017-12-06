description = [[
Extracts information about HP iLO boards.

HP iLO boards have an unauthenticated info disclosure at <ip>/xmldata?item=all.
It lists board informations such as server model, firmware version, 
MAC addresses, IP addresses etc. This script uses the slaxml library
to parse the iLO xml file and display the info.
]]

---
--@usage
--nmap --script ilo-info -p 80 <host>
--
--@output
--PORT   STATE SERVICE
--80/tcp open  http
--| ilo-info:
--|   ILOType     : Integrated Lights-Out 4 (iLO 4)
--|   Serial No   : ILOXXXXXXXXXX
--|   ILOFirmware : X.XX
--|   UUID        : XXXXXXXXXXXXXXXX
--|   cUUID       : XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX
--|   ServerType  : ProLiant MicroServer Gen8
--|   ProductID   : XXXXXX-XXX
--|   NICs:
--|     NIC 1:
--|       Mac Address : 12:34:56:78:9a:bc
--|       Description : iLO 4
--|       IP Address  : 10.10.10.10
--|       Status      : OK
--|     NIC 2:
--|       Mac Address : 11:22:33:44:55:66
--|       Description : iLO 4
--|       IP Address  : Unknown
--|_      Status      : Disabled
---

author = "Rajeev R Menon"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe","discovery"}

local http = require "http"
local slaxml = require "slaxml"
local stdnse = require "stdnse"

portrule = function(host,port)
	return (port.number == 80 or port.number == 443)
	and port.protocol == "tcp"
	and (port.service == "http" or port.service == "https")
	and port.state == "open"
end

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
	local response = {}
	local info = {}
	info['ServerType '] = getTag(dom,"SPN")
	info['ProductID  '] = getTag(dom,"PRODUCTID")
	info['UUID       '] = getTag(dom,"UUID")
	info['cUUID      '] = getTag(dom,"cUUID")
	info['ILOType    '] = getTag(dom,"PN")
  	info['ILOFirmware'] = getTag(dom,"FWRI")
	info['Serial No  '] = getTag(dom,"SN")

	for key,_ in pairs(info) do
		if info[key] ~= nil then
			table.insert(response,tostring(key).." : "..info[key].kids[1].value)
		end
	end
	local nicdom = getTag(dom,"NICS")
	if nicdom ~= nil then
		local nics = {}
		nics['name'] = "NICs:"
		local count = 1
		for _,n in ipairs(nicdom.kids) do
			local nic = {}
			info = {}
			nic['name'] = "NIC "..tostring(count)..":"
			count = count + 1
			for k,m in ipairs(n.kids) do
				if m.name == "DESCRIPTION" then
					info["Description"] = m.kids[1].value
				elseif m.name == "MACADDR" then
					info["Mac Address"] = m.kids[1].value
				elseif m.name == "IPADDR" then
					info["IP Address "] = m.kids[1].value
				elseif m.name == "STATUS" then
					info["Status     "] = m.kids[1].value
				end
			end
			for key,_ in pairs(info) do
				table.insert(nic,tostring(key).." : "..info[key])
			end
			table.insert(nics,nic)

		end
		table.insert(response,nics)
	end
	return response
end

action = function(host,port)
	local response = http.get(host,port,"/xmldata?item=all")
	if response["status"] == "404"
		or string.match(response["body"], '<RIMP>') == nil
		or string.match(response["body"], 'iLO') == nil
	then
		return
	end
	local domtable = slaxml.parseDOM(response["body"],{stripWhitespace=true})
	return stdnse.format_output(true, parseXML(domtable))
end
