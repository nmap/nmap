---
-- Debugging functions for Nmap scripts. 
--
-- This module contains various handy functions for debugging. These should
-- never be used for actual results, only during testing. 
-- 
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

require "stdnse"

local EMPTY = {}; -- Empty constant table

module(... or "nsedebug", package.seeall);

---
-- Converts an arbitrary data type into a string. Will recursively convert 
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
		str = str .. (" "):rep(indent) .. "nil\n"
	elseif(type(data) == "string") then
		str = str .. (" "):rep(indent) .. string.format("%q", data) .. "\n"
	elseif(type(data) == "number") then
		str = str .. (" "):rep(indent) .. data .. "\n"
	elseif(type(data) == "boolean") then
		if(data == true) then
			str = str .. "true\n"
		else
			str = str .. "false\n"
		end
	elseif(type(data) == "table") then
		local i, v
		for i, v in pairs(data) do
			-- Check for a table in a table
			if(type(v) == "table") then
				str = str .. (" "):rep(indent) .. tostring(i) .. ":\n"
				str = str .. tostr(v, indent + 2)
			else
				str = str .. (" "):rep(indent) .. tostring(i) .. ": " .. tostr(v, 0)
			end
		end
	else
		stdnse.print_debug(1, "Error: unknown data type: %s", type(data))
	end
		
	return str
end

-- Print out a string in hex, for debugging. 
function print_hex(str)

	-- Prints out the full lines
	for line=1, #str/16, 1 do
		io.write(string.format("%08x ", (line - 1) * 16))

		-- Loop through the string, printing the hex
		for char=1, 16, 1 do
			local ch = string.byte(str, ((line - 1) * 16) + char)
			io.write(string.format("%02x ", ch))
		end

		io.write("   ")

		-- Loop through the string again, this time the ascii
		for char=1, 16, 1 do
			local ch = string.byte(str, ((line - 1) * 16) + char)
			if ch < 0x20 or ch > 0x7f then
				ch = string.byte(".", 1)
			end
			io.write(string.format("%c", ch))
		end

		io.write("\n")
	end

	-- Prints out the final, partial line
	local line = math.floor((#str/16)) + 1
	io.write(string.format("%08x ", (line - 1) * 16))

	for char=1, #str % 16, 1 do
		local ch = string.byte(str, ((line - 1) * 16) + char)
		io.write(string.format("%02x ", ch))
	end
	io.write(string.rep("   ", 16 - (#str % 16)));
	io.write("   ")

	for char=1, #str % 16, 1 do
		local ch = string.byte(str, ((line - 1) * 16) + char)
		if ch < 0x20 or ch > 0x7f then
			ch = string.byte(".", 1)
		end
		io.write(string.format("%c", ch))
	end

	-- Print out the length
	io.write(string.format("\n         Length: %d [0x%x]\n", #str, #str))

end

---Print out a stacktrace. The stacktrace will naturally include this function call. 
function print_stack()
	local thread = coroutine.running()
	local trace = debug.traceback(thread);
	if trace ~= "stack traceback:" then
		print(thread, "\n", trace, "\n");
	end
end


