---
-- Creates and parses NetBIOS traffic. The primary use for this is to send
-- NetBIOS name requests. 
--
-- @author Ron Bowes <ron@skullsecurity.net>
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

module(... or "netbios", package.seeall)

require 'bit'
require 'bin'
require 'stdnse'

--- Encode a NetBIOS name for transport. Most packets that use the NetBIOS name
--  require this encoding to happen first. It takes a name containing any possible
--  character, and converted it to all uppercase characters (so it can, for example,
--  pass case-sensitive data in a case-insensitive way)
--
-- There are two levels of encoding performed:
-- * L1: Pad the string to 16 characters withs spaces (or NULLs if it's the 
--     wildcard "*") and replace each byte with two bytes representing each
--     of its nibbles, plus 0x41. 
-- * L2: Prepend the length to the string, and to each substring in the scope
--     (separated by periods). 
--@param name The name that will be encoded (eg. "TEST1"). 
--@param scope [optional] The scope to encode it with. I've never seen scopes used
--       in the real world (eg, "insecure.org"). 
--@return The L2-encoded name and scope 
--        (eg. "\x20FEEFFDFEDBCACACACACACACACACAAA\x08insecure\x03org")
function name_encode(name, scope)

	stdnse.print_debug(3, "Encoding name '%s'", name)
	-- Truncate or pad the string to 16 bytes
	if(#name >= 16) then
		name = string.sub(name, 1, 16)
	else
		local padding = " "
		if name == "*" then
			padding = "\0"
		end

		repeat
			name = name .. padding
		until #name == 16
	end

	-- Convert to uppercase
	name = string.upper(name)

	-- Do the L1 encoding
	local L1_encoded = ""
	for i=1, #name, 1 do
		local b = string.byte(name, i)
		L1_encoded = L1_encoded .. string.char(bit.rshift(bit.band(b, 0xF0), 4) + 0x41)
		L1_encoded = L1_encoded .. string.char(bit.rshift(bit.band(b, 0x0F), 0) + 0x41)
	end

	-- Do the L2 encoding 
	local L2_encoded = string.char(32) .. L1_encoded

	if scope ~= nil then
		-- Split the scope at its periods
		local piece
		for piece in string.gmatch(scope, "[^.]+") do
			L2_encoded = L2_encoded .. string.char(#piece) .. piece
		end
	end

	stdnse.print_debug(3, "=> '%s'", L2_encoded)
	return L2_encoded
end



--- Does the exact opposite of name_encode. Converts an encoded name to
--  the string representation. If the encoding is invalid, it will still attempt
--  to decode the string as best as possible. 
--@param encoded_name The L2-encoded name
--@return the decoded name and the scope. The name will still be padded, and the
--         scope will never be nil (empty string is returned if no scope is present)
function name_decode(encoded_name)
	local name = ""
	local scope = ""

	local len = string.byte(encoded_name, 1)
	local i

	stdnse.print_debug(3, "Decoding name '%s'", encoded_name)

	for i = 2, len + 1, 2 do
		local ch = 0
		ch = bit.bor(ch, bit.lshift(string.byte(encoded_name, i)     - 0x41, 4))
		ch = bit.bor(ch, bit.lshift(string.byte(encoded_name, i + 1) - 0x41, 0))

		name = name .. string.char(ch)
	end

	-- Decode the scope
	local pos = 34
	while #encoded_name > pos do
		local len = string.byte(encoded_name, pos)
		scope = scope .. string.sub(encoded_name, pos + 1, pos + len) .. "."
		pos = pos + 1 + len
	end

	-- If there was a scope, remove the trailing period
	if(#scope > 0) then
		scope = string.sub(scope, 1, #scope - 1)
	end

	stdnse.print_debug(3, "=> '%s'", name)

	return name, scope
end

--- Sends out a UDP probe on port 137 to get a human-readable list of names the
--  the system is using. 
--@param host The IP or hostname to check. 
--@param prefix [optional] The prefix to put on each line when it's returned. 
--@return (status, result) If status is true, the result is a human-readable 
--        list of names. Otherwise, result is an error message. 
function get_names(host, prefix)

	local status, names, statistics = do_nbstat(host)

	if(prefix == nil) then
		prefix = ""
	end


	if(status) then
		local result = ""
		for i = 1, #names, 1 do
			result = result .. string.format("%s%s<%02x>\n", prefix, names[i]['name'], names[i]['prefix'])
		end

		return true, result
	else
		return false, names
	end
end

--- Sends out a UDP probe on port 137 to get the server's name (that is, the
--  entry in its NBSTAT table with a 0x20 suffix). 
--@param host The IP or hostname of the server. 
--@param names [optional] The names to use, from <code>do_nbstat</code>. 
--@return (status, result) If status is true, the result is the NetBIOS name. 
--        otherwise, result is an error message. 
function get_server_name(host, names)

	local status
	local i

	if names == nil then
		status, names = do_nbstat(host)
	
		if(status == false) then
			return false, names
		end
	end

	for i = 1, #names, 1 do
		if names[i]['suffix'] == 0x20 then
			return true, names[i]['name']
		end
	end

	return false, "Couldn't find NetBIOS server name"
end

--- Sends out a UDP probe on port 137 to get the user's name (that is, the 
--  entry in its NBSTAT table with a 0x03 suffix, that isn't the same as
--  the server's name. If the username can't be determined, which is frequently
--  the case, nil is returned. 
--@param host The IP or hostname of the server. 
--@param names [optional] The names to use, from <code>do_nbstat</code>. 
--@return (status, result) If status is true, the result is the NetBIOS name or nil. 
--        otherwise, result is an error message.
function get_user_name(host, names)

	local status, server_name = get_server_name(host, names)

	if(status == false) then
		return false, server_name
	end

	if(names == nil) then
		status, names = do_nbstat(host)
	
		if(status == false) then
			return false, names
		end
	end

	for i = 1, #names, 1 do
		if names[i]['suffix'] == 0x03 and names[i]['name'] ~= server_name then
			return true, names[i]['name']
		end
	end
	
	return true, nil
	
end


--- This is the function that actually handles the UDP query to retrieve
--  the NBSTAT information. We make use of the Nmap registry here, so if another
--  script has already performed a nbstat query, the result can be re-used. 
--
-- The NetBIOS request's header looks like this:
--<code>
--  --------------------------------------------------
--  |  15 14 13 12 11 10 9  8  7  6  5  4  3  2  1  0 |
--  |                  NAME_TRN_ID                    |
--  | R |   OPCODE  |      NM_FLAGS      |   RCODE    | (FLAGS)
--  |                    QDCOUNT                      |
--  |                    ANCOUNT                      |
--  |                    NSCOUNT                      |
--  |                    ARCOUNT                      |
--  --------------------------------------------------
--</code>
--
-- In this case, the TRN_ID is a constant (0x1337, what else?), the flags
-- are 0, and we have one question. All fields are network byte order. 
--
-- The body of the packet is a list of names to check for in the following
-- format:
-- * (ntstring) encoded name
-- * (2 bytes)  query type (0x0021 = NBSTAT)
-- * (2 bytes)  query class (0x0001 = IN)
--
-- The response header is the exact same, except it'll have some flags set
-- (0x8000 for sure, since it's a response), and ANCOUNT will be 1. The format
-- of the answer is:
--
-- * (ntstring) requested name
-- * (2 bytes)  query type
-- * (2 bytes)  query class
-- * (2 bytes)  time to live
-- * (2 bytes)  record length
-- * (1 byte)   number of names
-- * [for each name]
-- *  (16 bytes) padded name, with a 1-byte suffix
-- *  (2 bytes)  flags
-- * (variable) statistics (usually mac address)
--
--@param host The IP or hostname of the system. 
--@return (status, names, statistics) If status is true, then the servers names are
--        returned as a table containing 'name', 'suffix', and 'flags'. 
--        Otherwise, names is an error message and statistics is undefined. 
function do_nbstat(host)

	local status, err
	local socket = nmap.new_socket()
	local encoded_name = name_encode("*")
	local statistics

	stdnse.print_debug(3, "Performing nbstat on host '%s'", host)
	-- Check if it's cased in the registry for this host
	if(nmap.registry["nbstat_names_" .. host] ~= nil) then
		stdnse.print_debug(3, " |_ [using cached value]")
		return true, nmap.registry["nbstat_names_" .. host], nmap.registry["nbstat_statistics_" .. host]
	end

	-- Create the query header
	local query = bin.pack(">SSSSSS", 
			0x1337,  -- Transaction id
			0x0000,  -- Flags
			1,       -- Questions
			0,       -- Answers
			0,       -- Authority
			0        -- Extra
		)

	query = query .. bin.pack(">zSS", 
			encoded_name, -- Encoded name
			0x0021,       -- Query type (0x21 = NBSTAT)
			0x0001        -- Class = IN
		)
	status, err = socket:connect(host, 137, "udp")
	if(status == false) then
		return false, err
	end

	status, err = socket:send(query)
	if(status == false) then
		return false, err
	end

	socket:set_timeout(1000)

	local status, result = socket:receive_bytes(1)
	if(status == false) then
		return false, result
	end

	local close_status, err = socket:close()
	if(close_status == false) then
		return false, err
	end

	if(status) then
		local pos, TRN_ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT, rr_name, rr_type, rr_class, rr_ttl
		local rrlength, name_count

		pos, TRN_ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = bin.unpack(">SSSSSS", result)

		-- Sanity check the result (has to have the same TRN_ID, 1 answer, and proper flags)
		if(TRN_ID ~= 0x1337) then
			return false, string.format("Invalid transaction ID returned: 0x%04x", TRN_ID)
		end
		if(ANCOUNT ~= 1) then
			return false, "Server returned an invalid number of answers"
		end
		if(bit.band(FLAGS, 0x8000) == 0) then
			return false, "Server's flags didn't indicate a response"
		end
		if(bit.band(FLAGS, 0x0007) ~= 0) then
			return false, string.format("Server returned a NetBIOS error: 0x%02x", bit.band(FLAGS, 0x0007))
		end

		-- Start parsing the answer field
		pos, rr_name, rr_type, rr_class, rr_ttl = bin.unpack(">zSSI", result, pos)

		-- More sanity checks
		if(rr_name ~= encoded_name) then
			return false, "Server returned incorrect name"
		end
		if(rr_class ~= 0x0001) then
			return false, "Server returned incorrect class"
		end
		if(rr_type ~= 0x0021) then
			return false, "Server returned incorrect query type"
		end

		pos, rrlength, name_count = bin.unpack(">SC", result, pos)

		local names = {}
		for i = 1, name_count do
			local name, suffix, flags

			-- Instead of reading the 16-byte name and pulling off the suffix, 
			-- we read the first 15 bytes and then the 1-byte suffix. 
			pos, name, suffix, flags = bin.unpack(">A15CS", result, pos)
			name = string.gsub(name, "[ ]*$", "")

			names[i] = {}
			names[i]['name']   = name
			names[i]['suffix'] = suffix
			names[i]['flags']  = flags

			-- Decrement the length
			rrlength = rrlength - 18
		end

		if(rrlength > 0) then
			rrlength = rrlength - 1
		end
		pos, statistics = bin.unpack(string.format(">A%d", rrlength), result, pos)

		-- Put it in the registry, in case anybody else needs it
		nmap.registry["nbstat_names_"      .. host] = names
		nmap.registry["nbstat_statistics_" .. host] = statistics

		return true, names, statistics

	else
		return false, "Name query failed: " .. result
	end
end

---Convert the 16-bit flags field to a string. 
--@param flags The 16-bit flags field
--@return A string representing the flags
function flags_to_string(flags)
	local result = ""

	if(bit.band(flags, 0x8000) ~= 0) then
		result = result .. "<group>"
	else
		result = result .. "<unique>"
	end

	if(bit.band(flags, 0x1000) ~= 0) then
		result = result .. "<deregister>"
	end

	if(bit.band(flags, 0x0800) ~= 0) then
		result = result .. "<conflict>"
	end

	if(bit.band(flags, 0x0400) ~= 0) then
		result = result .. "<active>"
	end

	if(bit.band(flags, 0x0200) ~= 0) then
		result = result .. "<permanent>"
	end

	return result
end

