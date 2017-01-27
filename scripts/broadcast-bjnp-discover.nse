description = [[
Attempts to discover Canon devices (Printers/Scanners) supporting the
BJNP protocol by sending BJNP Discover requests to the network
broadcast address for both ports associated with the protocol.

The script then attempts to retrieve the model, version and some additional
information for all discovered devices.
]]

---
-- @usage
-- nmap --script broadcast-bjnp-discover
--
-- @output
-- | broadcast-bjnp-discover:
-- |   192.168.0.10
-- |     Printer
-- |       Manufacturer: Canon
-- |       Model: MG5200 series
-- |       Description: Canon MG5200 series
-- |       Firmware version: 1.050
-- |       Command: BJL,BJRaster3,BSCCe,NCCe,IVEC,IVECPLI
-- |     Scanner
-- |       Manufacturer: Canon
-- |       Model: MG5200 series
-- |       Description: Canon MG5200 series
-- |_      Command: MultiPass 2.1,IVEC
--
-- @args broadcast-bjnp-discover.timeout specifies the amount of seconds to sniff
--       the network interface. (default 30s)

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "broadcast"}

local bjnp = require("bjnp")
local stdnse = require("stdnse")
local coroutine = require("coroutine")
local nmap = require("nmap")
local table = require("table")

local printer_port = { number = 8611, protocol = "udp"}
local scanner_port = { number = 8612, protocol = "udp"}
local arg_timeout  = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))

prerule = function()
  if ( nmap.address_family() ~= 'inet' ) then
    stdnse.debug1("is IPv4 compatible only.")
    return false
  end
  return true
end

local function identifyDevices(devices, devtype)
  local result
  local port = ( "printers" == devtype and printer_port or scanner_port )
  for _, ip in ipairs(devices or {}) do
    local helper = bjnp.Helper:new({ ip = ip }, port)
    if ( helper:connect() ) then
      local status, attrs
      if ( "printers" == devtype ) then
        status, attrs = helper:getPrinterIdentity()
      end
      if ( "scanners" == devtype ) then
        status, attrs = helper:getScannerIdentity()
      end
      if ( status ) then
        result = result or {}
        result[ip] = attrs
      end
    end
    helper:close()
  end
  return result
end

local function identifyScanners(scanners)
  return identifyDevices(scanners, "scanners")
end

local function identifyPrinters(printers)
  return identifyDevices(printers, "printers")
end

local function getKeys(devices)
  local dupes = {}
  local function iter()
    for k, _ in pairs(devices) do
      for k2, _ in pairs(devices[k]) do
        if ( not(dupes[k2]) ) then
          dupes[k2] = true
          coroutine.yield(k2)
        end
      end
    end
    coroutine.yield(nil)
  end
  return coroutine.wrap(iter)
end

local function getPrinters(devices)
  local condvar = nmap.condvar(devices)
  local helper = bjnp.Helper:new( { ip = "255.255.255.255" }, printer_port, { bcast = true, timeout = arg_timeout } )
  if ( not(helper:connect()) ) then
    condvar "signal"
    return
  end
  local status, printers = helper:discoverPrinter()
  helper:close()
  if ( status ) then
    devices["printers"] = identifyPrinters(printers)
  end
  condvar "signal"
end

local function getScanners(devices)
  local condvar = nmap.condvar(devices)
  local helper = bjnp.Helper:new( { ip = "255.255.255.255" }, scanner_port, { bcast = true, timeout = arg_timeout } )
  if ( not(helper:connect()) ) then
    condvar "signal"
    return
  end
  local status, scanners = helper:discoverScanner()
  helper:close()
  if ( status ) then
    devices["scanners"] = identifyScanners(scanners)
  end
  condvar "signal"
end


action = function()
  arg_timeout = ( arg_timeout and arg_timeout * 1000 or 5000)
  local devices, result, threads = {}, {}, {}
  local condvar = nmap.condvar(devices)

  local co = stdnse.new_thread(getPrinters, devices)
  threads[co] = true

  co = stdnse.new_thread(getScanners, devices)
  threads[co] = true

  while(next(threads)) do
    for t in pairs(threads) do
      threads[t] = ( coroutine.status(t) ~= "dead" ) and true or nil
    end
    if ( next(threads) ) then
      condvar "wait"
    end
  end

  for ip in getKeys(devices) do
    local result_part = {}
    local printer = ( devices["printers"] and devices["printers"][ip] )
    local scanner = ( devices["scanners"] and devices["scanners"][ip] )

    if ( printer ) then
      printer.name = "Printer"
      table.insert(result_part, printer)
    end
    if ( scanner ) then
      scanner.name = "Scanner"
      table.insert(result_part, scanner)
    end
    if ( #result_part > 0 ) then
      result_part.name = ip
      table.insert(result, result_part)
    end
  end

  if ( result ) then
    return stdnse.format_output(true, result)
  end
end
