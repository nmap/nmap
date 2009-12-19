description = [[
Attempts to extract information from IBM DB2 Server instances.  The script sends a
DB2 EXCSAT (exchange server attributes) command packet and parses the response.
]]

-- rev 1.3 (2009-12-16)
  
author = "Tom Sellers"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe", "discovery", "version"}

require "stdnse"
require "shortport"

portrule = shortport.port_or_service({50000,60000},"ibm-db2", "tcp", {"open", "open|filtered"})

-- This function processes a section of the EXCSAT response packet

--@param response	This is the data returned from the server as a result of the client query.
--@param position	This is the position within the response that this function will start processing from. 
--@param ebcdic2ascii	This is a table containing a conversion chart for returning the ASCII value of EBCDIC encoded HEX value.
--@return section_length	This is the length of the currect section. Will be used to move position for processing next section.
--@return data_string	This string contains the data pulled from this section of the server response.
local function process_block(response, position, ebcdic2ascii)

	-- This fuction assumes that the current position is the start of a section within
	-- the DB2 EXCSAT response packet
		
	-- Get the length of this section of the response packet
	local section_length = string.format("%d",string.byte(response,position +1)) .. string.format("%d",string.byte(response,position + 2))
	position = position + 2
		
	-- locate the data string and convert it from EBCDIC to ASCII
	local i = 0
	local data_string = ""
	for i = (position + 3),(position + section_length -2 ),1 do
		-- stdnse.print_debug("%s","INFO: Current postion (i) = " .. i)
		-- stdnse.print_debug("%s","INFO: Hex value = " .. string.format("%x",string.byte(response,i)))
		-- stdnse.print_debug("%s","INFO: Current data_string = " .. data_string)	
		if string.format("%x",string.byte(response,i)) == "0" then
			break
		end		
		data_string  = data_string .. ebcdic2ascii[string.format("%x",string.byte(response,i))]
	end
	
	return section_length, data_string
	
end -- fuction process_block



action = function(host, port)
	
	local ebcdic2ascii = {
		-- The following reference was used for this table:  http://www.simotime.com/asc2ebc1.htm
		["00"] = string.format("%c", 00),
		["40"] = " ",
		["81"] = "a",
		["82"] = "b",
		["83"] = "c",
		["84"] = "d",
		["85"] = "e",
		["86"] = "f",
		["87"] = "g",
		["88"] = "h",
		["89"] = "i",
		["91"] = "j",
		["92"] = "k",
		["93"] = "l",
		["94"] = "m",
		["95"] = "n",
		["96"] = "o",
		["97"] = "p",
		["98"] = "q",
		["99"] = "r",
		["a2"] = "s",
		["a3"] = "t",
		["a4"] = "u",
		["a5"] = "v",
		["a6"] = "w",
		["a7"] = "x",
		["a8"] = "y",
		["a9"] = "z",
		["c1"] = "A",
		["c2"] = "B",
		["c3"] = "C",
		["c4"] = "D",
		["c5"] = "E",
		["c6"] = "F",
		["c7"] = "G",
		["c8"] = "H",
		["c9"] = "I",
		["d1"] = "J",
		["d2"] = "K",
		["d3"] = "L",
		["d4"] = "M",
		["d5"] = "N",
		["d6"] = "O",
		["d7"] = "P",
		["d8"] = "Q",
		["d9"] = "R",
		["e2"] = "S",
		["e3"] = "T",
		["e4"] = "U",
		["e5"] = "V",
		["e6"] = "W",
		["e7"] = "X",
		["e8"] = "Y",
		["e9"] = "Z",
		["f0"] = 0,
		["f1"] = 1,
		["f2"] = 2,
		["f3"] = 3,
		["f4"] = 4,
		["f5"] = 5,
		["f6"] = 6,
		["f7"] = 7,
		["f8"] = 8,
		["f9"] = 9,
		["4b"] = ".",
		["4c"] = "<",
		["4d"] = "(",
		["4e"] = "+",
		["4f"] = "|",
		["5a"] = "!",
		["5b"] = "$",
		["5c"] = "*",
		["5d"] = ")",
		["5e"] = ";",
		["60"] = "-",
		["61"] = "/",
		["6b"] = ",",
		["6c"] = "%",
		["6d"] = "_",
		["6e"] = ">",
		["6f"] = "?",
		["79"] = "`",
		["7a"] = ":",
		["7b"] = "#",
		["7c"] = "@",
		["7d"] = "'",
		["7e"] = "=",
		["7f"] = "\"",
		["a1"] = "~",
		["ba"] = "[",
		["bb"] = "]",
		["c0"] = "{",
		["d0"] = "}",
		["e0"] = "\\"  -- escape the \ character
	}

	-- ebcdic2ascii does not contain all value, set a default value
	-- to improve stability.
	setmetatable(ebcdic2ascii, { __index = function() return " " end })
	
	-- create the socket used for our connection
	local socket = nmap.new_socket()
	
	-- set a reasonable timeout value
	socket:set_timeout(10000)
	
	-- do some exception handling / cleanup
	local catch = function()
		stdnse.print_debug("%s", "db2-info: ERROR communicating with " .. host.ip .. " on port " .. port.number .. "/" .. port.protocol)
		socket:close()
	end
	
	local try = nmap.new_try(catch)

	try(socket:connect(host.ip, port.number, "tcp"))

	-- Build DB2 EXCSAT (exchange server attributes) command packet
	
	local query = string.char(0x00, 0x98, 0xd0, 0x41, 0x00, 0x01, 0x00, 0x92, 0x10, 0x41)  -- Header 
	
	--  NOTE:  The server's response packet is in the same format at the client query packet being built
	--         in the section below.
	
	--  External Name section: first two bytes (00,48) are section length in HEX, next bytes (11,5e) are section identifier for External Name
	--  In this packet the external name is 'db2jcc_application  JCC03570300' encoded in EBCDIC
	query = query .. string.char(0x00, 0x48, 0x11, 0x5e, 0x84, 0x82, 0xf2, 0x91, 0x83, 0x83, 0x6d, 0x81, 0x97, 0x97, 0x93, 0x89) 
	query = query .. string.char(0x83, 0x81, 0xa3, 0x89, 0x96, 0x95, 0x40, 0x40, 0xd1, 0xc3, 0xc3, 0xf0, 0xf3, 0xf5, 0xf7, 0xf0)
	query = query .. string.char(0xf3, 0xf0, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	query = query .. string.char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	query = query .. string.char(0x00, 0x00, 0x00, 0x60, 0xf0, 0xf0, 0xf0, 0xf1)
	
	 -- Client Name section: first two bytes (00,16) are section length in HEX, next two bytes (11,6d) are section identifier for Server Name
	 -- In the request packet Server Name = client name.  The value here is all spaces, encoded in EBCDIC
	query = query .. string.char(0x00, 0x16, 0x11, 0x6d, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40) 
	query = query .. string.char(0x40, 0x40, 0x40, 0x40, 0x40, 0x40)
	
	-- Product Release Level section:  This section is not as important in the client query as it is in the server response.
	-- The first two bytes (00,0c) are section length in HEX, next two bytes (11,5a) are section identifier for Product Release Level
	-- The value here is 'JCC03570' encoded in EBCDIC
	query = query .. string.char(0x00, 0x0c, 0x11, 0x5a, 0xd1, 0xc3, 0xc3, 0xf0, 0xf3, 0xf5, 0xf7, 0xf0)  
		
	-- Manager level section: first two bytes (00,18) are section length in HEX, next two bytes (14,04) are section identifier for Manager-Level List
	query = query .. string.char(0x00, 0x18, 0x14, 0x04, 0x14, 0x03, 0x00, 0x07, 0x24, 0x07, 0x00, 0x0a, 0x24, 0x0f, 0x00, 0x08)
	query = query .. string.char(0x14, 0x40, 0x00, 0x09, 0x14, 0x74, 0x00, 0x08)
	
	-- Server Class section: first two bytes (00,0c) are section length in HEX, next two bytes (11,47) are section identifier for Server Class Name
	-- This section is essentially platform software information.  The value here is 'QDB2/JBM' encoded in EBCDIC)
	query = query .. string.char(0x00, 0x0c, 0x11, 0x47, 0xd8, 0xc4, 0xc2, 0xf2, 0x61, 0xd1, 0xe5, 0xd4) 
	
	 -- Access Security section
	query = query .. string.char(0x00, 0x26, 0xd0, 0x01, 0x00, 0x02, 0x00, 0x20, 0x10, 0x6d, 0x00, 0x06, 0x11, 0xa2, 0x00, 0x03) 
	

	-- Database name section:  This is the client's query for a specific database.  A DB2 default database name, 'db2insta1', was chosen.
	-- It is encoded below in EBCDIC.  The first two bytes (00,16) are section length in HEX, next two bytes (21,10) are section identifier 
	-- for Relational Database Name
	query = query .. string.char(0x00, 0x16, 0x21, 0x10, 0x84, 0x82, 0xf2, 0x89, 0x95, 0xa2, 0xa3, 0xf1, 0x40, 0x40, 0x40, 0x40)
	query = query .. string.char(0x40, 0x40, 0x40, 0x40, 0x40, 0x40)
		
	try(socket:send(query))
	
	local status
	local response
	
	-- read in any response we might get
	status, response = socket:receive()

	socket:close()
	
	if (not status) or (response == "TIMEOUT") or (response == nil) then
		stdnse.print_debug("%s","db2-info: ERROR: No data, ending communications with " .. host.ip .. ":" .. port.number .. "/" .. port.protocol)
		return
	end
	
	local position = 0
	
	-- Check to see if the data is actually a DB2 DDM EXCSAT response.
	-- 0d in the 3rd byte of the data section seems to be a reliable test.
	if string.format("%x",string.byte(response,position + 3)) ~= "d0" then
		return
	end
	
	local bytes = " "
	local len_response = string.len(response) - 2
	
	-- Parse response until the EXCSAT identifier is found.  From here we should
	-- be able to find everything else.
	while (bytes ~= "1443") and (position <= len_response) do
		bytes = string.format("%x",string.byte(response,position +1)) .. string.format("%x",string.byte(response,position + 2))
		if bytes == nil then
			return
		end
		position = position + 2
	end
	
	if position >= len_response then
		-- If this section is true then this either not a valid response or
		-- it is in a format that we have not seen.  Exit cleanly.
		return
	end
		
	-- ****************************************************************************
	-- Process the Server class section of the response packet
	-- ****************************************************************************
	local len_external_name, external_name = process_block(response, position, ebcdic2ascii)

	-- ****************************************************************************
	-- Process the Manager Level section of the response packet
	-- ****************************************************************************
	-- Move the position to the beginning of the current section
	position = position + len_external_name
	
	-- Get the length of the next block, Wireshark calls this "Manager-Level list"
	-- We are going to skip over this section
	local len_manager_level = string.format("%d",string.byte(response, position +1)) .. string.format("%d",string.byte(response,position + 2))
	
	
	-- ****************************************************************************
	-- Process the Server class section of the response packet
	-- ****************************************************************************
	-- Move the position to the beginning of the current section
	position = position + len_manager_level
	local len_server_class, server_class = process_block(response, position, ebcdic2ascii)
		
	
	-- ****************************************************************************
	-- Process the Server name section of the response packet
	-- ****************************************************************************
	-- Move the position to the beginning of the current section
	position = position + len_server_class
	local len_server_name, server_name = process_block(response, position, ebcdic2ascii)
	
	-- ****************************************************************************
	-- Process the Server version section of the response packet
	-- ****************************************************************************
	-- Move the position to the beginning of the current section
	position = position + len_server_name 
	
	local len_server_version, server_version = process_block(response, position, ebcdic2ascii)
	
	if string.sub(server_version,1,3) == "SQL" then
		local major_version = string.sub(server_version,4,5)

		-- strip the leading 0 from the major version, for consistency with 
		-- nmap-service-probes results
		if string.sub(major_version,1,1) == "0" then
			major_version = string.sub(major_version,2)
		end
		local minor_version = string.sub(server_version,6,7)
		local hotfix = string.sub(server_version,8)
		server_version = major_version .. "." .. minor_version .. "." .. hotfix
	end
		
	-- Try to determine which of the two values (probe version vs script) has more 
	-- precision.  A couple DB2 versions send DB2 UDB 7.1 vs SQL090204 (9.02.04)
	local _
	local current_count = 0
	if port.version.version ~= nil then
		_, current_count = string.gsub(port.version.version, "%.", "%.")
	end	

	local new_count = 0
	if server_version ~= nil then
		_, new_count = string.gsub(server_version, "%.", "%.")
	end
	
	if current_count < new_count then
		port.version.version = server_version
	end
		
	-- Set port information
	port.version.name = "ibm-db2"
	port.version.product = "IBM DB2 Database Server"
	port.version.name_confidence = 100
	nmap.set_port_state(host, port, "open")
	if server_class ~= nil then port.version.extrainfo = server_class   end
	
	nmap.set_port_version(host, port, "hardmatched")
	
	-- Generate results
	    local results = "DB2 Version: " .. server_version .. "\n"
	results = results .. "Server Platform: " .. server_class .. "\n"
	results = results .. "Instance Name:   " .. server_name .. "\n"
	results = results .. "External Name:   " .. external_name
	
	return results
			
end


