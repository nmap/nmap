local comm = require "comm"
local math = require "math"
local shortport = require "shortport"
local string = require "string"
local stringaux = require "stringaux"
local table = require "table"

description = [[
Reads hard disk information (such as brand, model, and sometimes temperature) from a listening hddtemp service.
]]

---
-- @usage
-- nmap -p 7634 -sV -sC <target>
--
-- @output
-- 7634/tcp open  hddtemp
-- | hddtemp-info:
-- |_  /dev/sda: WDC WD2500JS-60MHB1: 38 C
--
-- @xmloutput
-- <table>
--   <elem key="label">WDC WD2500JS-60MHB1</elem>
--   <elem key="unit">C</elem>
--   <elem key="device">/dev/sda</elem>
--   <elem key="temperature">38</elem>
-- </table>
-- <table>
--   <elem key="label">WDC WD3200BPVT-75JJ5T0</elem>
--   <elem key="unit">C</elem>
--   <elem key="device">/dev/sdb</elem>
--   <elem key="temperature">41</elem>
-- </table>

author = "Toni Ruottu"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


portrule = shortport.port_or_service (7634, "hddtemp", {"tcp"})

local fmt_meta = {
  __tostring = function (t)
    return string.format("%s: %s: %s %s", t.device, t.label, t.temperature, t.unit)
  end
}
action = function( host, port )
  -- 5000B should be enough for 100 disks
  local status, data = comm.get_banner(host, port, {bytes=5000})
  if not status then
    return
  end
  local separator = string.sub(data, 1, 1)
  local fields = stringaux.strsplit(separator, data)
  local info = {}
  local disks = math.floor((# fields) / 5)
  for i = 0, (disks - 1) do
    local start = i * 5
    local diskinfo = {
      device = fields[start + 2],
      label = fields[start + 3],
      temperature = fields[start + 4],
      unit = fields[start + 5],
    }
    setmetatable(diskinfo, fmt_meta)
    table.insert(info, diskinfo)
  end
  return info
end
