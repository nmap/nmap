--- Debugging functions for Nmap scripts. 
--
-- This module contains various handy functions for debugging. These should
-- never be used for actual results, only during testing. 
-- 
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

local require = require
local type = type
local pairs = pairs
local nmap = require "nmap";
local stdnse = require "stdnse";

local EMPTY = {}; -- Empty constant table

module(... or "nmapdebug");

---Converts an arbitrary data type into a string. Will recursively convert 
-- tables. This can be very useful for debugging. 
--
--@param data   The data to convert. 
--@param indent (optional) The number of times to indent the line. Default
--              is 0. 
--@return A string representation of a data, will be one or more full lines. 
function tostr(data, indent)
	local str = ""

	if(indent == nil) then
		indent = 0
	end

	-- Check the type
	if(type(data) == "nil") then
		str = str .. (" "):rep(indent) .. data .. "\n"
	elseif(type(data) == "string") then
		str = str .. (" "):rep(indent) .. data .. "\n"
	elseif(type(data) == "number") then
		str = str .. (" "):rep(indent) .. data .. "\n"
	elseif(type(data) == "boolean") then
		if(data == true) then
			str = str .. "true"
		else
			str = str .. "false"
		end
	elseif(type(data) == "table") then
		local i, v
		for i, v in pairs(data) do
			-- Check for a table in a table
			if(type(v) == "table") then
				str = str .. (" "):rep(indent) .. i .. ":\n"
				str = str .. tostr(v, indent + 2)
			else
				str = str .. (" "):rep(indent) .. i .. ": " .. tostr(v, 0)
			end
		end
	else
		stdnse.print_debug(1, "Error: unknown data type: %s", type(data))
	end
		
	return str
end

