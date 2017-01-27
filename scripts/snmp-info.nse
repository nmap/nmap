local bin = require "bin"
local datafiles = require "datafiles"
local ipOps = require "ipOps"
local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local stdnse = require "stdnse"
local U = require "lpeg-utility"
local comm = require "comm"

description = [[
Extracts basic information from an SNMPv3 GET request. The same probe is used
here as in the service version detection scan.
]]

---
--@output
--161/udp open  snmp    udp-response ttl 244   ciscoSystems SNMPv3 server (public)
--| snmp-info:
--|   enterprise: ciscoSystems
--|   engineIDFormat: mac
--|   engineIDData: 00:d4:8c:00:11:22
--|   snmpEngineBoots: 6
--|_  snmpEngineTime: 358d01h13m46s
--
--@xmloutput
-- <elem key="enterprise">ciscoSystems</elem>
-- <elem key="engineIDFormat">mac</elem>
-- <elem key="engineIDData">00:d4:8c:b5:32:bc</elem>
-- <elem key="snmpEngineBoots">6</elem>
-- <elem key="snmpEngineTime">358d01h26m34s</elem>

author = "Daniel Miller"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "version", "safe"}

portrule = shortport.version_port_or_service(161, "snmp", "udp")

-- Lifted from nmap-service-probes:
local SNMPv3GetRequest = "\x30\x3a\x02\x01\x03\x30\x0f\x02\x02\x4a\x69\x02\x03\0\xff\xe3\x04\x01\x04\x02\x01\x03\x04\x10\x30\x0e\x04\0\x02\x01\0\x02\x01\0\x04\0\x04\0\x04\0\x30\x12\x04\0\x04\0\xa0\x0c\x02\x02\x37\xf0\x02\x01\0\x02\x01\0\x30\0"

-- TODO: This should probably check for version 1 and version 2, since those
-- can operate on the same port. Right now it's really just "snmp3-info"
action = function (host, port)
  local ENTERPRISE_NUMS = nmap.registry.enterprise_numbers
  if not ENTERPRISE_NUMS then
    local status
    status, ENTERPRISE_NUMS = datafiles.parse_file("nselib/data/enterprise_numbers.txt",
      {[function(l) return tonumber(l:match("^%d+")) end] = "\t(.*)$"})
    if not status then
      stdnse.debug1("Couldn't parse enterprise numbers datafile: %s", ENTERPRISE_NUMS)
      ENTERPRISE_NUMS = {}
      setmetatable(ENTERPRISE_NUMS, {__index = function(i) return "unknown" end})
    end
    nmap.registry.enterprise_numbers = ENTERPRISE_NUMS
  end

  local response
  -- Did the service engine already do the hard work?
  if port.version and port.version.service_fp then
    -- Probes sent, replies received, but no match.
    response = U.get_response(port.version.service_fp, "SNMPv3GetRequest")
  end

  if not response then
    -- Have to send the probe ourselves
    local status
    status, response = comm.exchange(host, port, SNMPv3GetRequest)
    if not status then
      stdnse.debug1("Couldn't get a response: %s", response)
      return nil
    end
  end

  local pos, decoded = snmp.decode(response)

  -- Check for SNMP version 3 and msgid 0x4a69 (from the probe)
  if ((not decoded) or
      (decoded[1] or false) ~= 3 or
      (not decoded[2]) or
      (decoded[2][1] or false) ~= 0x4a69) then
    stdnse.debug1("Service is not SNMPv3, or packet structure not recognized")
    return nil
  end

  -- This really only works for User-based Security Model (USM)
  if decoded[2][4] ~= 3 then
    -- TODO: at least report the security model in use
    stdnse.debug1("SNMP service not using User-based Security Model")
    return nil
  end

  -- Decode the msgSecurityParameters octet-string
  pos, decoded = snmp.decode(decoded[3])

  local output = stdnse.output_table()
  -- Decode the msgAuthoritativeEngineID octet-string
  local engineID = decoded[1]
  local pos, enterprise = bin.unpack(">I", engineID)
  if enterprise > 0x80000000 then
    enterprise = enterprise - 0x80000000
    output.enterprise = ENTERPRISE_NUMS[enterprise]
    local format, data
    pos, format = bin.unpack("C", engineID, pos)
    if format == 1 then
      output.engineIDFormat = "ipv4"
      output.engineIDData = ipOps.str_to_ip(engineID:sub(pos,pos+3))
    elseif format == 2 then
      output.engineIDFormat = "ipv6"
      output.engineIDData = ipOps.str_to_ip(engineID:sub(pos,pos+15))
    elseif format == 3 then
      output.engineIDFormat = "mac"
      output.engineIDData = stdnse.tohex(engineID:sub(pos,pos+5), {separator=':'})
    elseif format == 4 then
      output.engineIDFormat = "text"
      output.engineIDData = engineID:sub(pos)
    elseif format == 5 then
      output.engineIDFormat = "octets"
      output.engineIDData = stdnse.tohex(engineID:sub(pos))
    else
      output.engineIDFormat = "unknown"
      output.engineIDData = stdnse.tohex(engineID:sub(pos))
    end
  else
    output.enterprise = ENTERPRISE_NUMS[enterprise] or enterprise
    output.engineIDFormat = "unknown"
    output.engineIDData = stdnse.tohex(engineID:sub(5))
  end
  output.snmpEngineBoots = decoded[2]
  output.snmpEngineTime = stdnse.format_time(decoded[3])

  port.version = port.version or {}
  port.version.service = "snmp"
  if port.version.product and port.version.product ~= "SNMPv3 server" then
    port.version.product = ("%s; %s SNMPv3 server"):format(port.version.product, output.enterprise)
  else
    port.version.product = ("%s SNMPv3 server"):format(output.enterprise)
  end
  nmap.set_port_version(host, port, "hardmatched")

  return output
end
