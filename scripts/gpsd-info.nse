local datetime = require "datetime"
local gps = require "gps"
local match = require "match"
local nmap = require "nmap"
local os = require "os"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Retrieves GPS time, coordinates and speed from the GPSD network daemon.
]]

---
-- @usage
-- nmap -p 2947 <ip> --script gpsd-info
--
-- @output
-- PORT     STATE SERVICE REASON
-- 2947/tcp open  gpsd-ng syn-ack
-- | gpsd-info:
-- |   Time of fix: Sat Apr 14 15:54:23 2012
-- |   Coordinates: 59.321685,17.886493
-- |_  Speed: - knots
--
-- @args gpsd-info.timeout timespec defining how long to wait for data (default 10s)


author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.port_or_service(2947, "gpsd-ng", "tcp")

local arg_timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
arg_timeout = arg_timeout or 10

local function updateData(gpsinfo, entry)
  for k, v in pairs(gpsinfo) do
    if ( entry[k] and 0 < #tostring(entry[k]) ) then
      gpsinfo[k] = entry[k]
    end
  end
end

local function hasAllData(gpsinfo)
  for k, v in pairs(gpsinfo) do
    if ( k ~= "speed" and v == '-' ) then
      return false
    end
  end
  return true
end

local function fail(err) return stdnse.format_output(false, err) end

action = function(host, port)

  local gpsinfo = {
    longitude = "-",
    latitude = "-",
    speed = "-",
    time  = "-",
    date  = "-",
  }

  local socket = nmap.new_socket()
  socket:set_timeout(1000)

  local status = socket:connect(host, port)

  if ( not(status) ) then
    return fail("Failed to connect to server")
  end

  -- get the banner
  local status, line = socket:receive_lines(1)
  socket:send('?WATCH={"enable":true,"nmea":true}\r\n')

  local start_time = os.time()

  repeat
    local entry
    status, line = socket:receive_buf(match.pattern_limit("\r\n", 2048), false)
    if ( status ) then
      status, entry = gps.NMEA.parse(line)
      if ( status ) then
        updateData(gpsinfo, entry)
      end
    end
  until( os.time() - start_time > arg_timeout or hasAllData(gpsinfo) )

  socket:send('?WATCH={"enable":false}\r\n')

  if ( not(hasAllData(gpsinfo)) ) then
    return
  end

  local output = {
    ("Time of fix: %s"):format(datetime.format_timestamp(gps.Util.convertTime(gpsinfo.date, gpsinfo.time))),
    ("Coordinates: %.4f,%.4f"):format(tonumber(gpsinfo.latitude), tonumber(gpsinfo.longitude)),
    ("Speed: %s knots"):format(gpsinfo.speed)
  }
  return stdnse.format_output(true, output)
end
