local bit = require "bit"
local os = require "os"
local stdnse = require "stdnse"
local string = require "string"
_ENV = stdnse.module("gps", stdnse.seeall)

---
-- A smallish gps parsing module.
-- Currently does GPRMC NMEA decoding
--
-- @author Patrik Karlsson <patrik@cqure.net>
--
--

NMEA = {

  -- Parser for the RMC sentence
  RMC = {

    parse = function(str)

      local time, status, latitude, ns_indicator, longitude,
        ew_indicator, speed, course, date, variation,
        ew_variation, checksum = str:match("^%$GPRMC,([^,]*),([^,]*),([^,]*),([^,]*),([^,]*),([^,]*),([^,]*),([^,]*),([^,]*),([^,]*),([^%*]*)(.*)$")

      if ( not(latitude) or not(longitude) ) then
        return
      end

      local deg, min = latitude:match("^(..)(.*)$")
      if ( not(deg) or not(min) ) then
        return
      end
      latitude = tonumber(deg) + (tonumber(min)/60)

      deg, min = longitude:match("^(..)(.*)$")
      if ( not(deg) or not(min) ) then
        return
      end
      longitude = tonumber(deg) + (tonumber(min)/60)
      if ( ew_indicator == 'W' ) then
        longitude = -longitude
      end

      if ( ns_indicator == 'S' ) then
        latitude = -latitude
      end

      return { time = time, status = status, latitude = latitude,
      longitude = longitude, speed = speed, course = course,
      date = date, variation = variation,
      ew_variation = ew_variation }
    end,

  },

  -- Calculates an verifies the message checksum
  --
  -- @param str containing the GPS sentence
  -- @return status true on success, false if the checksum does not match
  -- @return err string if status is false
  checksum = function(str)
    local val = 0
    for c in str:sub(2,-4):gmatch(".") do
      val = bit.bxor(val, string.byte(c))
    end

    if ( str:sub(-2):upper() ~= stdnse.tohex(string.char(val)):upper() ) then
      return false, ("Failed to verify checksum (got: %s; expected: %s)"):format(stdnse.tohex(string.char(val)), str:sub(-2))
    end
    return true
  end,

  -- Parses a GPS sentence using the appropriate parser
  --
  -- @param str containing the GPS sentence
  -- @return entry table containing the parsed response or
  --         err string if status is false
  -- @return status true on success, false on failure
  parse = function(str)

    local status, err = NMEA.checksum(str)
    if ( not(status) ) then
      return false, err
    end

    local prefix = str:match("^%$GP([^,]*)")
    if ( not(prefix) ) then
      return false, "Not a NMEA sentence"
    end

    if ( NMEA[prefix] and NMEA[prefix].parse ) then
      local e = NMEA[prefix].parse(str)
      if (not(e)) then
        return false, ("Failed to parse entry: %s"):format(str)
      end
      return true, e
    else
      local err = ("No parser for prefix: %s"):format(prefix)
      stdnse.debug2("%s", err)
      return false, err
    end

  end

}

Util = {

  convertTime = function(date, time)
    local d = {}
    d.hour, d.min, d.sec = time:match("(..)(..)(..)")
    d.day, d.month, d.year = date:match("(..)(..)(..)")
    d.year = d.year + 2000
    return os.time(d)
  end
}

return _ENV;
