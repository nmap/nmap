local comm = require "comm"
local string = require "string"
local shortport = require "shortport"
local nmap = require "nmap"

description = "Detect the T3 RMI protocol and Weblogic version"
author = {"Alessandro ZANNI <alessandro.zanni@bt.com>", "Daniel Miller"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default","safe","discovery","version"}

portrule = function(host, port)
  if type(port.version) == "table" and port.version.name_confidence > 3 and port.version.product ~= nil then
    return string.find(port.version.product, "WebLogic", 1, true) and nmap.version_intensity() >= 7
  end
  return shortport.version_port_or_service({7001,7002,7003},"http")(host,port)
end

action = function(host, port)
  local status, result = comm.exchange(host, port,
    "t3 12.1.2\nAS:2048\nHL:19\n\n")

  if (not status) then
    return nil
  end

  local weblogic_version = string.match(result, "^HELO:(%d+%.%d+%.%d+%.%d+)%.")

  local rval = nil
  port.version = port.version or {}
  local extrainfo = port.version.extrainfo
  if extrainfo == nil then
    extrainfo = ""
  else
    extrainfo = extrainfo .. "; "
  end
  if weblogic_version then
    if weblogic_version == "12.1.2" then
      status, result = comm.exchange(host, port,
        "t3 11.1.2\nAS:2048\nHL:19\n\n")
      weblogic_version = string.match(result, "^HELO:(%d+%.%d+%.%d+%.%d+)%.")
      if weblogic_version == "11.1.2" then
        -- Server just echoes whatever version we send.
        rval = "T3 protocol in use (Unknown WebLogic version)"
      else
        port.version.version = weblogic_version
        rval = "T3 protocol in use (WebLogic version: " .. weblogic_version .. ")"
      end
    else
      port.version.version = weblogic_version
      rval = "T3 protocol in use (WebLogic version: " .. weblogic_version .. ")"
    end
    port.version.extrainfo = extrainfo .. "T3 enabled"
  elseif string.match(result, "^LGIN:") then
    port.version.extrainfo = extrainfo .. "T3 enabled"
    rval = "T3 protocol in use (handshake failed)"
  elseif string.match(result, "^SERV:") then
    port.version.extrainfo = extrainfo .. "T3 enabled"
    rval = "T3 protocol in use (No such service)"
  elseif string.match(result, "^UNAV:") then
    port.version.extrainfo = extrainfo .. "T3 enabled"
    rval = "T3 protocol in use (Service unavailable)"
  elseif string.match(result, "^LICN:") then
    port.version.extrainfo = extrainfo .. "T3 enabled"
    rval = "T3 protocol in use (No license)"
  elseif string.match(result, "^RESC:") then
    port.version.extrainfo = extrainfo .. "T3 enabled"
    rval = "T3 protocol in use (No resource)"
  elseif string.match(result, "^VERS:") then
    weblogic_version = string.match(result, "^VERS:Incompatible versions %- this server:(%d+%.%d+%.%d+%.%d+)")
    if weblogic_version then
      port.version.version = weblogic_version
    end
    port.version.extrainfo = extrainfo .. "T3 enabled"
    rval = "T3 protocol in use (Incompatible version)"
  elseif string.match(result, "^CATA:") then
    port.version.extrainfo = extrainfo .. "T3 enabled"
    rval = "T3 protocol in use (Catastrophic failure)"
  elseif string.match(result, "^CMND:") then
    port.version.extrainfo = extrainfo .. "T3 enabled"
    rval = "T3 protocol in use (No such command)"
  end

  if rval then
    if port.version.product == nil then
      port.version.product = "WebLogic application server"
    end
    nmap.set_port_version(host, port, "hardmatched")
  end

  return rval
end
