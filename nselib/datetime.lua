--- Functions for dealing with dates and timestamps
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @class module
-- @name datetime
-- @author Daniel Miller

local stdnse = require "stdnse"
local os = require "os"
local math = require "math"
local string = require "string"
_ENV = stdnse.module("datetime", stdnse.seeall)

local difftime = os.difftime
local time = os.time
local date = os.date

local floor = math.floor
local fmod = math.fmod

local format = string.format
local match = string.match

--- Record a time difference between the scanner and the target
--
-- The skew will be recorded in the host's registry for later retrieval and
-- analysis. Adjusts for network distance by subtracting half the smoothed
-- round-trip time.
--
--@param host The host being scanned
--@param timestamp The target timestamp, in seconds.
--@param received The local time the stamp was received, in seconds.
function record_skew(host, timestamp, received)
  local skew_tab = host.registry.datetime_skew
  skew_tab = skew_tab or {}
  -- No srtt? I suppose we'll ignore it, but this could cause problems
  local srtt = host.times and host.times.srtt or 0
  local adjusted = difftime(floor(timestamp), floor(received)) - srtt / 2.0
  skew_tab[#skew_tab + 1] = adjusted
  stdnse.debug2("record_skew: %s", adjusted)
  host.registry.datetime_skew = skew_tab
end

-- Work around Windows error formatting time zones where 1970/1/1 UTC was 1969/12/31
local utc_offset_seconds
do
  -- What does the calendar say locally?
  local localtime = date("*t", 86400)
  -- What does the calendar say in UTC?
  local gmtime = date("!*t", 86400)
  -- Interpret both as local calendar dates and find the difference.
  utc_offset_seconds = difftime(time(localtime), time(gmtime))
end

-- The offset in seconds between local time and UTC.
--
-- That is, if we interpret a UTC date table as a local date table by passing
-- it to os.time, how much must be added to the resulting integer timestamp to
-- make it correct?
--
-- In other words, subtract this value from a timestamp if you intend to use it
-- in os.date.
function utc_offset() return utc_offset_seconds end

--- Convert a date table into an integer timestamp.
--
-- Unlike os.time, this does not assume that the date table represents a local
-- time. Rather, it takes an optional offset number of seconds representing the
-- time zone, and returns the timestamp that would result using that time zone
-- as local time. If the offset is omitted or 0, the date table is interpreted
-- as a UTC date. For example, 4:00 UTC is the same as 5:00 UTC+1:
-- <code>
-- date_to_timestamp({year=1970,month=1,day=1,hour=4,min=0,sec=0})          --> 14400
-- date_to_timestamp({year=1970,month=1,day=1,hour=4,min=0,sec=0}, 0)       --> 14400
-- date_to_timestamp({year=1970,month=1,day=1,hour=5,min=0,sec=0}, 1*60*60) --> 14400
-- </code>
-- And 4:00 UTC+1 is an earlier time:
-- <code>
-- date_to_timestamp({year=1970,month=1,day=1,hour=4,min=0,sec=0}, 1*60*60) --> 10800
-- </code>
function date_to_timestamp(date_t, offset)
  local status, tm = pcall(time, date_t)
  if not status then
    stdnse.debug1("Invalid date for this platform: %s", tm)
    return nil
  end
  offset = offset or 0
  return tm + utc_offset() - offset
end

local function format_tz(offset)
  local sign, hh, mm

  if not offset then
    return ""
  end
  if offset < 0 then
    sign = "-"
    offset = -offset
  else
    sign = "+"
  end
  -- Truncate to minutes.
  offset = floor(offset / 60)
  hh = floor(offset / 60)
  mm = floor(fmod(offset, 60))

  return format("%s%02d:%02d", sign, hh, mm)
end
--- Format a date and time (and optional time zone) for structured output.
--
-- Formatting is done according to RFC 3339 (a profile of ISO 8601), except
-- that a time zone may be omitted to signify an unspecified local time zone.
-- Time zones are given as an integer number of seconds from UTC. Use
-- <code>0</code> to mark UTC itself. Formatted strings with a time zone look
-- like this:
-- <code>
-- format_timestamp(os.time(), 0)       --> "2012-09-07T23:37:42+00:00"
-- format_timestamp(os.time(), 2*60*60) --> "2012-09-07T23:37:42+02:00"
-- </code>
-- Without a time zone they look like this:
-- <code>
-- format_timestamp(os.time())          --> "2012-09-07T23:37:42"
-- </code>
--
-- This function should be used for all dates emitted as part of NSE structured
-- output.
function format_timestamp(t, offset)
  if type(t) == "table" then
    return format(
      "%d-%02d-%02dT%02d:%02d:%02d",
      t.year, t.month, t.day, t.hour, t.min, t.sec
      )
  else
    local tz_string = format_tz(offset)
    offset = offset or 0
    local status, result = pcall(date, "!%Y-%m-%dT%H:%M:%S", floor(t + offset))
    if not status then
      local tmp = floor(t + offset)
      local extra_years
      local seconds_in_year = 31556926
      if tmp > 0xffffffff then
        -- Maybe too far in the future?
        extra_years = (tmp  - 0xffffffff) // seconds_in_year + 1
      elseif tmp < -utc_offset() then
        -- Windows can't display times before the epoch
        extra_years = tmp // seconds_in_year
      end
      if extra_years then
        tmp = tmp - extra_years * seconds_in_year
        status, result = pcall(date, "!*t", tmp)
        if status then
          -- seconds_in_year is imprecise, so we truncate to date only
          result = format("%d-%02d-%02d?", result.year + extra_years, result.month, result.day)
        end
      end
    end
    if not status then
      return ("Invalid timestamp: %s"):format(t)
    end
    return result .. tz_string
  end
end

--- Format a time interval into a string
--
-- String is in the same format as format_difftime
-- @param interval A time interval
-- @param unit The time unit division as a number. If <code>interval</code> is
--             in milliseconds, this is 1000 for instance. Default: 1 (seconds)
-- @return The time interval in string format
function format_time(interval, unit)
  local sign = ""
  if interval < 0 then
    sign = "-"
    interval = math.abs(interval)
  end
  unit = unit or 1
  local precision = floor(math.log(unit, 10))

  local sec = (interval % (60 * unit)) / unit
  interval = interval // (60 * unit)
  local min = interval % 60
  interval = interval // 60
  local hr = interval % 24
  interval = interval // 24

  local s = format("%.0fd%02.0fh%02.0fm%02.".. precision .."fs",
    interval, hr, min, sec)
  -- trim off leading 0 and "empty" units
  return sign .. (match(s, "([1-9].*)") or format("%0.".. precision .."fs", 0))
end

--- Format the difference between times <code>t2</code> and <code>t1</code>
-- into a string
--
-- String is in one of the forms (signs may vary):
-- * 0s
-- * -4s
-- * +2m38s
-- * -9h12m34s
-- * +5d17h05m06s
-- * -2y177d10h13m20s
-- The string shows <code>t2</code> relative to <code>t1</code>; i.e., the
-- calculation is <code>t2</code> minus <code>t1</code>.
function format_difftime(t2, t1)
  local d, s, sign, yeardiff

  d = difftime(time(t2), time(t1))
  if d > 0 then
    sign = "+"
  elseif d < 0 then
    sign = "-"
    t2, t1 = t1, t2
    d = -d
  else
    sign = ""
  end
  -- t2 is always later than or equal to t1 here.

  -- The year is a tricky case because it's not a fixed number of days
  -- the way a day is a fixed number of hours or an hour is a fixed
  -- number of minutes. For example, the difference between 2008-02-10
  -- and 2009-02-10 is 366 days because 2008 was a leap year, but it
  -- should be printed as 1y0d0h0m0s, not 1y1d0h0m0s. We advance t1 to be
  -- the latest year such that it is still before t2, which means that its
  -- year will be equal to or one less than t2's. The number of years
  -- skipped is stored in yeardiff.
  if t2.year > t1.year then
    local tmpyear = t1.year
    -- Put t1 in the same year as t2.
    t1.year = t2.year
    d = difftime(time(t2), time(t1))
    if d < 0 then
      -- Too far. Back off one year.
      t1.year = t2.year - 1
      d = difftime(time(t2), time(t1))
    end
    yeardiff = t1.year - tmpyear
    t1.year = tmpyear
  else
    yeardiff = 0
  end

  local s = format_time(d)
  if yeardiff == 0 then return sign .. s end
  -- Years.
  s = format("%dy", yeardiff) .. s
  return sign .. s
end

return _ENV
