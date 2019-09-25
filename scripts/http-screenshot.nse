-- Copyright (C) 2019 Securifera
-- http://www.securifera.com
-- 
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; version 2 dated June, 1991 or at your option
-- any later version.
-- 
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
-- GNU General Public License for more details.
-- 
-- A copy of the GNU General Public License is available in the source tree;
-- if not, write to the Free Software Foundation, Inc.,
-- 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

description = [[
Gets a screenshot from the host
]]

author = "Ryan Wincey"

license = "GPLv2"

categories = {"default", "discovery", "safe"}

-- Updated the NSE Script imports and variable declarations
local shortport = require "shortport"

local stdnse = require "stdnse"

local script_path = string.sub(debug.getinfo(1).source, 2, (string.len("http-screenshot.nse") + 1) * -1)
-- local script_path = debug.getinfo(1).source
stdnse.debug(1, "Script path: %s", script_path)

portrule = shortport.http

action = function(host, port)
	
	-- Execute the shell command python screenshot.py 
	local cmd = 'python "' .. script_path .. package.config:sub(1,1) .. 'screenshot.py" -u ' .. host.ip .. " -p " .. port.number	
	local ret = os.execute(cmd)

	-- If the command was successful, print the saved message, otherwise print the fail message
	local result = "Screenshot failed. Ensure you have all dependencies installed, see screenshot.py"

	if ret then
		result = "Screenshot saved."
	end

	-- Return the output message
	return stdnse.format_output(true,  result)

end
