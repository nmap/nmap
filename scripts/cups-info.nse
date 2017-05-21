local ipp = require "ipp"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Lists printers managed by the CUPS printing service.
]]

---
-- @usage
-- nmap -p 631 <ip> --script cups-info
--
-- @output
-- PORT    STATE SERVICE
-- 631/tcp open  ipp
-- | cups-info:
-- |   Generic-PostScript-Printer
-- |     DNS-SD Name: Lexmark S300-S400 Series @ ubu1110
-- |     Location:
-- |     Model: Local Raw Printer
-- |     State: Processing
-- |     Queue: 0 print jobs
-- |   Lexmark-S300-S400-Series
-- |     DNS-SD Name: Lexmark S300-S400 Series @ ubu1110
-- |     Location:
-- |     Model: Local Raw Printer
-- |     State: Stopped
-- |     Queue: 0 print jobs
-- |   PDF
-- |     DNS-SD Name: PDF @ ubu1110
-- |     Location:
-- |     Model: Generic CUPS-PDF Printer
-- |     State: Idle
-- |_    Queue: 0 print jobs
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}


portrule = shortport.port_or_service(631, "ipp", "tcp", "open")

action = function(host, port)

  local helper = ipp.Helper:new(host, port)
  if ( not(helper:connect()) ) then
    return stdnse.format_output(false, "Failed to connect to server")
  end

  local status, printers = helper:getPrinters()
  if ( not(status) ) then
    return
  end

  local output = {}
  for _, printer in ipairs(printers) do
    local states = {
      [ipp.IPP.PrinterState.IPP_PRINTER_IDLE] = "Idle",
      [ipp.IPP.PrinterState.IPP_PRINTER_PROCESSING] = "Processing",
      [ipp.IPP.PrinterState.IPP_PRINTER_STOPPED] = "Stopped",
    }
    local state = string.unpack(">I4", printer.state)
    table.insert(output, {
      name = printer.name,
      ("DNS-SD Name: %s"):format(printer.dns_sd_name or ""),
      ("Location: %s"):format(printer.location or ""),
      ("Model: %s"):format(printer.model or ""),
      ("State: %s"):format(states[state] or ""),
      ("Queue: %s print jobs"):format(tonumber(printer.queue_count) or 0),
    } )
  end

  if ( 0 ~= #output ) then
    return stdnse.format_output(true, output)
  end
end
