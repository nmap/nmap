-- mcafee-epo-agent.nse V0.0.2, checks if ePO agent is running
-- Developed by Didier Stevens and Daniel Miller
-- Use at your own risk
--
-- History:
--   2012/05/31: Start
--   2012/06/01: extracting data from XML; tested with ePO 4.5 and 4.6
--   2012/06/05: V0.0.2 conversion to version script by Daniel Miller
--   2012/06/20: new portrule by Daniel Miller

description = [[
Check if ePO agent is running on port 8081 or port identified as ePO Agent port.
]]

---
-- @output
-- PORT      STATE SERVICE VERSION
-- 8081/tcp  open  http    McAfee ePolicy Orchestrator Agent 4.5.0.1852 (ePOServerName: EPOSERVER, AgentGuid: D2E157F4-B917-4D31-BEF0-32074BADF081)
-- Service Info: Host: TESTSERVER

author = {"Didier Stevens", "Daniel Miller"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"version", "safe"}

local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"

portrule = function(host, port)
  if port.version ~= nil and port.version.product ~= nil then
    return ((port.version.product:find("[eE][pP]olicy Orch")
          or port.version.product:find("[eE]PO [aA]gent"))
          and nmap.version_intensity() >= 7)
  else
    return ((port.number == 8081 and port.protocol == "tcp")
            and nmap.version_intensity() >= 7)
  end
end

function ExtractXMLElement(xmlContent, elementName)
  return xmlContent:match("<" .. elementName .. ">([^<]*)</" .. elementName .. ">")
end

action = function(host, port)
  local options, data, epoServerName, agentGUID

  -- Change User-Agent string to MSIE so that the ePO agent will reply with XML
  options = {header={}}
  options['header']['User-Agent'] = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; mcafee-epo-agent)"
  data = http.get(host, port, '/', options)

  if data.body then
    stdnse.debug2("data.body:sub = %s", data.body:sub(1, 80))

    if data.body:match('^<%?xml .*%?>%s*<naLog>') then
      port.version.hostname = ExtractXMLElement(data.body, "ComputerName")
      epoServerName = ExtractXMLElement(data.body, "ePOServerName") or ""
      port.version.version =  ExtractXMLElement(data.body, "version") or ""
      agentGUID =     ExtractXMLElement(data.body, "AgentGUID") or ""

      port.version.name = 'http'
      port.version.product = 'McAfee ePolicy Orchestrator Agent'
      port.version.extrainfo = string.format('ePOServerName: %s, AgentGuid: %s', epoServerName, agentGUID)
      nmap.set_port_version(host, port)
      return nil
    end
  end

  if nmap.verbosity() > 1 then
    return "ePO Agent not found"
  else
    return nil
  end
end
