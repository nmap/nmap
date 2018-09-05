local mobileme = require "mobileme"
local datetime = require "datetime"
local stdnse = require "stdnse"
local tab = require "tab"

description = [[
Retrieves the locations of all "Find my iPhone" enabled iOS devices by querying
the MobileMe web service (authentication required).
]]

---
-- @usage
-- nmap -sn -Pn --script http-icloud-findmyiphone --script-args='username=<user>,password=<pass>'
--
-- @output
-- Pre-scan script results:
-- | http-icloud-findmyiphone:
-- |   name                           location        accuracy  date               type
-- |   Patrik Karlsson's MacBook Air  -,-             -         -                  -
-- |   Patrik Karlsson's iPhone       40.690,-74.045  65        04/10/12 16:56:37  Wifi
-- |_  Mac mini                       40.690,-74.045  65        04/10/12 16:56:36  Wifi
--
-- @args http-icloud-findmyiphone.username the Apple Id username
-- @args http-icloud-findmyiphone.password the Apple Id password
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "external"}


local arg_username = stdnse.get_script_args(SCRIPT_NAME .. ".username")
local arg_password = stdnse.get_script_args(SCRIPT_NAME .. ".password")

prerule = function() return true end

-- decode basic UTF8 encoded strings
-- iOS devices are commonly named after the user eg:
--  * Patrik Karlsson's Macbook Air
--  * Patrik Karlsson's iPhone
--
-- This function decodes the single quote as a start and should really
-- be replaced with a proper UTF-8 decoder in the future
local function decodeString(str)
  return str:gsub("\226\128\153", "'")
end

local function fail(err) return stdnse.format_output(false, err) end

action = function()

  if ( not(arg_username) or not(arg_password) ) then
    return fail("No username or password was supplied")
  end

  local mobileme = mobileme.Helper:new(arg_username, arg_password)
  local status, response = mobileme:getLocation()

  if ( not(status) ) then
    stdnse.debug2("%s", response)
    return fail("Failed to retrieve location information")
  end

  local output = tab.new(4)
  tab.addrow(output, "name", "location", "accuracy", "date", "type")
  for name, info in pairs(response) do
    local loc
    if ( info.latitude and info.longitude ) then
      loc = ("%.3f,%.3f"):format(
        tonumber(info.latitude) or "-",
        tonumber(info.longitude) or "-")
    else
      loc = "-,-"
    end
    local ts
    if ( info.timestamp and 1000 < info.timestamp ) then
      ts = datetime.format_timestamp(info.timestamp//1000)
    else
      ts = "-"
    end
    tab.addrow(output, decodeString(name), loc, info.accuracy or "-", ts, info.postype or "-")
  end

  if ( 1 < #output ) then
    return stdnse.format_output(true, tab.dump(output))
  end
end
