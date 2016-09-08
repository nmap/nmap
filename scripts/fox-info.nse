local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local comm = require "comm"
local ipOps = require "ipOps"

description = [[
Tridium Niagara Fox is a protocol used within Building Automation Systems. Based
off Billy Rios and Terry McCorkle's work this Nmap NSE will collect information
from A Tridium Niagara system.

http://digitalbond.com

]]

---
-- @usage
-- nmap --script fox-info.nse -p 1911 <host>
--
-- @output
-- 1911/tcp open  Niagara Fox
-- | fox-info:
-- |   fox.version: 1.0.1
-- |   hostName: xpvm-0omdc01xmy
-- |   hostAddress: 192.168.1.1
-- |   app.name: Workbench
-- |   app.version: 3.7.44
-- |   vm.name: Java HotSpot(TM) Server VM
-- |   vm.version: 20.4-b02
-- |   os.name: Windows XP
-- |   timeZone: America/Chicago
-- |   hostId: Win-99CB-D49D-5442-07BB
-- |   vmUuid: 8b530bc8-76c5-4139-a2ea-0fabd394d305
-- |_  brandId: vykon
--
-- @xmloutput
--<elem key="fox.version">1.0.1</elem>
--<elem key="hostName">xpvm-0omdc01xmy</elem>
--<elem key="hostAddress">192.168.1.1</elem>
--<elem key="app.name">Workbench</elem>
--<elem key="app.version">3.7.44</elem>
--<elem key="vm.name">Java HotSpot(TM) Server VM</elem>
--<elem key="vm.version">20.4-b02</elem>
--<elem key="os.Name">Windows XP</elem>
--<elem key="timeZone">America/Chicago</elem>
--<elem key="hostId">Win-99CB-D49D-5442-07BB</elem>
--<elem key="vmUuid">8b530bc8-76c5-4139-a2ea-0fabd394d305</elem>
--<elem key="brandId">vykon</elem>

author = "Stephen Hilt (Digital Bond)"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "version"}


portrule = shortport.port_or_service({1911, 4911}, "niagara-fox", "tcp")

--  Action Function that is used to run the NSE. This function will send the
--  initial query to the host and port that were passed in via nmap. The
--  initial response is parsed to determine if host is a Niagara Fox device. If it
--  is then more actions are taken to gather extra information.
--
-- @param host Host that was scanned via nmap
-- @param port port that was scanned via nmap
action = function(host, port)
  --set the first query data for sending
  local orig_query =
  [==[fox a 1 -1 fox hello
{
fox.version=s:1.0
id=i:1
};;
]==]

  -- receive response
  local socket, response, proto = comm.tryssl(host, port, orig_query)
  if not socket then
    stdnse.debug1( "Receive error: %s", response)
    return nil
  end
  socket:close()

  if proto == "ssl" then
    port.version.service_tunnel = "ssl"
  end

  local pos = response:find("{")
  if not pos or not response:match("^fox a 0") then
    stdnse.debug1("Not Niagara Fox protocol")
    return nil
  end

  -- output table that will be returned to nmap
  local to_return = stdnse.output_table()

  local set = function (key, value)
    to_return[key] = value
  end

  local dispatch = {
    hostName = function (key, value)
      if not ipOps.ip_to_str(value) then
        -- If this is an IP address, don't set it as a hostname
        port.version.hostname = value
      end
      to_return[key] = value
    end,
    hostAddress = set,
    ["fox.version"] = set,
    ["app.name"] = set,
    ["app.version"] = set,
    ["vm.name"] = set,
    ["vm.version"] = set,
    ["os.name"] = set,
    timeZone = function (key, value)
      to_return[key] = value:match("^[^;]+")
    end,
    hostId = set,
    vmUuid = set,
    brandId = set,
    fatal = set, -- sometimes reports a fatal error about unsupported
  }

  for key, value in response:gmatch("\n([%w.]+)=s:([^\n]+)") do
    local act = dispatch[key]
    if act then
      act(key, value)
    end
  end

  if #to_return <= 0 then
    return nil
  end

  port.version.name = "niagara-fox"
  nmap.set_port_version(host, port)

  -- return output table to nmap
  return to_return
end
