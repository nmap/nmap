local mobileme = require "mobileme"
local stdnse = require "stdnse"
local tab = require "tab"

description = [[
Sends a message to a iOS device through the Apple MobileMe web service. The
device has to be registered with an Apple ID using the Find My Iphone
application.
]]

---
-- @usage
-- nmap -sn -Pn --script http-icloud-sendmsg --script-args="username=<user>,password=<pass>,http-icloud-sendmsg.listdevices"
-- nmap -sn -Pn --script http-icloud-sendmsg --script-args="username=<user>,password=<pass>,deviceindex=1,subject='subject',message='hello world.',sound=false"
--
-- @output
-- Pre-scan script results:
-- | http-icloud-sendmsg: 
-- |_  Message was successfully sent to "Patrik Karlsson's iPhone"
--
-- @args http-icloud-sendmsg.username the Apple ID username
-- @args http-icloud-sendmsg.password the Apple ID password
-- @args http-icloud-sendmsg.listdevices list the devices managed by the
--       specified Apple ID.
-- @args http-icloud-sendmsg.deviceindex the device index to which the message
--       should be sent (@see http-icloud-sendmsg.listdevices)
-- @args http-icloud-sendmsg.subject the subject of the message to send to the
--       device.
-- @args http-icloud-sendmsg.message the body of the message to send to the
--       device.
-- @args http-icloud-sendmsg.sound boolean specifying if a loud sound should be
--       played while displaying the message. (default: true)

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "external"}


local arg_username    = stdnse.get_script_args(SCRIPT_NAME .. ".username")
local arg_password    = stdnse.get_script_args(SCRIPT_NAME .. ".password")
local arg_listdevices = stdnse.get_script_args(SCRIPT_NAME .. ".listdevices")
local arg_deviceindex = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".deviceindex"))
local arg_subject     = stdnse.get_script_args(SCRIPT_NAME .. ".subject")
local arg_message     = stdnse.get_script_args(SCRIPT_NAME .. ".message")
local arg_sound       = stdnse.get_script_args(SCRIPT_NAME .. ".sound") or true


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

local function fail(err) return ("\n  ERROR: %s"):format(err or "") end

local function listDevices(mm)
	local status, devices = mm:getDevices()
	if ( not(status) ) then
		return fail("Failed to get devices")
	end

	local output = tab.new(2)
	tab.addrow(output, "id", "name")
	for i=1, #devices do
		local name = decodeString(devices[i].name or "")
		tab.addrow(output, i, name)
	end
	
	if ( 1 < #output ) then
		return stdnse.format_output(true, tab.dump(output))
	end
end


action = function()
	if ( not(arg_username) or not(arg_password) ) then
		return fail("No username or password was supplied")
	end
	
	if ( not(arg_deviceindex) and not(arg_listdevices) ) then
		return fail("No device ID was specificed")
	end

	if ( 1 == tonumber(arg_listdevices) or "true" == arg_listdevices ) then
		local mm = mobileme.Helper:new(arg_username, arg_password)
		return listDevices(mm)
	elseif ( not(arg_subject) or not(arg_message) ) then
		return fail("Missing subject or message")
	else
		local mm = mobileme.Helper:new(arg_username, arg_password)
		local status, devices = mm:getDevices()
		
		if ( not(status) ) then
			return fail("Failed to get devices")
		end
	
		if ( status and arg_deviceindex <= #devices ) then
			local status = mm:sendMessage( devices[arg_deviceindex].id, arg_subject, arg_message, arg_sound)
			if ( status ) then
				return ("\n  Message was successfully sent to \"%s\""):format(decodeString(devices[arg_deviceindex].name or ""))
			else
				return "\n  Failed to send message"
			end
		end
	end
end
