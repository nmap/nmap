--- Functions for dealing with dates and timestamps
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @class module
-- @name datetime
-- @author Daniel Miller

local stdnse = require "stdnse"
local os = require "os"
local math = require "math"
_ENV = stdnse.module("datetime", stdnse.seeall)

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
  local adjusted = os.difftime(math.floor(timestamp), math.floor(received)) - srtt / 2.0
  skew_tab[#skew_tab + 1] = adjusted
  stdnse.debug2("record_skew: %s", adjusted)
  host.registry.datetime_skew = skew_tab
end

return _ENV
