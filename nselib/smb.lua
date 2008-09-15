--- A library for SMB (Server Message Block) (aka CIFS) traffic. This traffic is normally
--  sent to/from ports 139 or 445 of Windows systems, although it's also implemented by
--  others (the most notable one being Samba). 
--
-- The intention of this library is toe ventually handle all aspects of the SMB protocol,
-- A programmer using this library must already have some knowledge of the SMB protocol, 
-- although a lot isn't necessary. You can pick up a lot by looking at the code that uses
-- this. The basic login is this:
--
-- [connect]
-- C->S SMB_COM_NEGOTIATE_PROTOCOL
-- S->C SMB_COM_NEGOTIATE_PROTOCOL
-- C->S SMB_COM_SESSION_SETUP_ANDX
-- S->C SMB_COM_SESSION_SETUP_ANDX
-- C->S SMB_COM_TREE_CONNCT_ANDX
-- S->C SMB_COM_TREE_CONNCT_ANDX
--
-- In terms of functions here, the protocol is:
-- status, socket           = smb.start(host)
-- status, negotiate_result = smb.negotiate_protocol(socket)
-- status, session_result   = smb.start_session(socket, username, negotiate_result['session_key'], negotiate_result['capabilities'])
-- status, tree_result      = smb.tree_connect(socket, path, session_result['uid'])
-- 
-- To initially begin the connection, there are two options:
-- 1) Attempt to start a raw session over 445, if it's open. \n
-- 2) Attempt to start a NetBIOS session over 139. Although the 
--    protocol's the same, it requires a "session request" packet. 
--    That packet requires the computer's name, which is requested
--    using a NBSTAT probe over UDP port 137. \n
--
-- Once it's connected, a SMB_COM_NEGOTIATE_PROTOCOL packet is sent, 
-- requesting the protocol "NT LM 0.12", which is the most commonly
-- supported one. Among other things, the server's response contains
-- the host's security level, the system time, and the computer/domain
-- name.
--
-- If that's successful, SMB_COM_SESSION_SETUP_ANDX is sent. It is essentially the logon
-- packet, where the username, domain, and password are sent to the server for verification. 
-- The response to SMB_COM_SESSION_SETUP_ANDX is fairly simple, containing a boolean for 
-- success, along with the operating system and the lan manager name. 
--
-- After a successful SMB_COM_SESSION_START_ANDX has been made, a 
-- SMB_COM_TREE_CONNECT_ANDX packet can be sent. This is what connects to a share. 
-- The server responds to this with a boolean answer, and little more information. 

-- Each share will either return STATUS_BAD_NETWORK_NAME if the share doesn't
-- exist, STATUS_ACCESS_DENIED if it exists but we don't have access, or 
-- STATUS_SUCCESS if exists and we do have access. 
--
-- Thanks go to Christopher R. Hertel and Implementing CIFS, which 
-- taught me everything I know about Microsoft's protocols. 
--
--@author Ron Bowes <ron@skullsecurity.net>
--@copyright See nmaps COPYING for licence
-----------------------------------------------------------------------
module(... or "smb", package.seeall)

require 'bit'
require 'bin'
require 'netbios'
require 'stdnse'

mutex_id = "SMB"

--- Determines whether or not SMB checks are possible on this host, and, if they are, 
--  which port is best to use. This is how it decides:\n
--\n
-- a) If port tcp/445 is open, use it for a raw connection\n
-- b) Otherwise, if ports tcp/139 and udp/137 are open, do a NetBIOS connection. Since
--    UDP scanning isn't default, we're also ok with udp/137 in an unknown state. 
--
--@param host The host object. 
--@return The port number to use, or nil if we don't have an SMB port
function get_port(host)
	local port_u137 = nmap.get_port_state(host, {number=137, protocol="udp"})
	local port_t139 = nmap.get_port_state(host, {number=139, protocol="tcp"})
	local port_t445 = nmap.get_port_state(host, {number=445, protocol="tcp"})

	if(port_t445 ~= nil and port_t445.state == "open") then
		 -- tcp/445 is open, we're good
		 return 445
	end

	if(port_t139 ~= nil and port_t139.state == "open") then
		 -- tcp/139 is open, check uf udp/137 is open or unknown
		 if(port_u137 == nil or port_u137.state == "open" or port_u137.state == "open|filtered") then
			  return 139
		 end
	end

	return nil
end

--- Begins a SMB session, automatically determining the best way to connect. Also starts a mutex
--  with mutex_id. This prevents multiple threads from making queries at the same time (which breaks
--  SMB). 
--
-- @param host The host object
-- @return (status, socket) if the status is true, result is the newly crated socket. 
--         otherwise, socket is the error message. 
function start(host)
	local port = get_port(host)
	local mutex = nmap.mutex(mutex_id)

	if(port == nil) then
		return false, "Couldn't find a valid port to check"
	end

	mutex "lock"

	if(port == 445) then
		return start_raw(host, port)
	elseif(port == 139) then
		return start_netbios(host, port)
	end

	return false, "Couldn't find a valid port to check"
end

--- Kills the SMB connection, closes the socket, and releases the mutex. Because of the mutex 
--  being released, a script HAS to call stop() before it exits, no matter why it's exiting! 
--
--@param socket The socket associated with the connection. 
--@return (status, result) If status is false, result is an error message. Otherwise, result
--        is undefined. 
function stop(socket) 
	local mutex = nmap.mutex(mutex_id)

	-- It's possible that the mutex wouldn't be created if there was an error condition. Therefore, 
	-- I'm calling 'trylock' first to ensure we have a lock on it. I'm not sure if that's the best
	-- way to do this, though... 
	mutex "trylock"
	mutex "done"

	stdnse.print_debug(2, "Closing SMB socket")
	if(socket ~= nil) then
		local status, err = socket:close()

		if(status == false) then
			return false, err
		end
	end

	return true
end

--- Begins a raw SMB session, likely over port 445. Since nothing extra is required, this
--  function simply makes a connection and returns the socket. 
--  it off to smb_start(). 
-- 
--@param host The host object to check. 
--@param port The port to use (most likely 445).
--@return (status, socket) if status is true, result is the newly created socket. 
--        Otherwise, socket is the error message. 
function start_raw(host, port)
	local status, err
	local socket = nmap.new_socket()

	status, err = socket:connect(host.ip, port, "tcp")

	if(status == false) then
		return false, err
	end

	return true, socket
end

--- This function will take a string like "a.b.c.d" and return "a", "a.b", "a.b.c", and "a.b.c.d". 
--  This is used for discovering NetBIOS names. 
--@param name The name to take apart
--@param list [optional] If list is set, names will be added to it then returned
--@return An array of the sub names
local function get_subnames(name)
	local i = -1
	local list = {}

	repeat
		local subname = name

		i = string.find(name, "[.]", i + 1)
		if(i ~= nil) then
			subname = string.sub(name, 1, i - 1)
		end

		list[#list + 1] = string.upper(subname)

	until i == nil

	return list
end

--- Begins a SMB session over NetBIOS. This requires a NetBIOS Session Start message to 
--  be sent first, which in turn requires the NetBIOS name. The name can be provided as
--  a parameter, or it can be automatically determined. \n
--\n
-- Automatically determining the name is interesting, to say the least. Here are the names
-- it tries, and the order it tries them in:\n
-- 1) The name the user provided, if present\n
-- 2) The name pulled from NetBIOS (udp/137), if possible\n
-- 3) The generic name "*SMBSERVER"\n
-- 4) Each subset of the domain name (for example, scanme.insecure.org would attempt "scanme",
--    "scanme.insecure", and "scanme.insecure.org")\n
--\n
-- This whole sequence is a little hackish, but it's the standard way of doing it. 
--
--@param host The host object to check. 
--@param port The port to use (most likely 139).
--@param name [optional] The NetBIOS name of the host. Will attempt to automatically determine
--            if it isn't given. 
--@return (status, socket) if status is true, result is the port
--        Otherwise, socket is the error message. 
function start_netbios(host, port, name)
	local i
	local status, err
	local pos, result, flags, length
	local socket = nmap.new_socket()

	-- First, populate the name array with all possible names, in order of significance
	local names = {}

	-- Use the name parameter
	if(name ~= nil) then
		names[#names + 1] = name
	end

	-- Get the name of the server from NetBIOS
	status, name = netbios.get_server_name(host.ip)
	if(status == true) then
		names[#names + 1] = name
	end

	-- "*SMBSERVER" is a special name that any server should respond to
	names[#names + 1] = "*SMBSERVER"

	-- If all else fails, use each substring of the DNS name (this is a HUGE hack, but is actually
	-- a recommended way of doing this!)
	if(host.name ~= nil and host.name ~= "") then
		new_names = get_subnames(host.name)
		for i = 1, #new_names, 1 do
			names[#names + 1] = new_names[i]
		end
	end

	-- This loop will try all the NetBIOS names we've collected, hoping one of them will work. Yes,
	-- this is a hackish way, but it's actually the recommended way. 
	i = 1
	repeat

		-- Use the current name
		name = names[i]

		-- Some debug information
		stdnse.print_debug(1, "Trying to start NetBIOS session with name = '%s'", name)
		-- Request a NetBIOS session
		session_request = bin.pack(">CCSzz", 
					0x81,                        -- session request
					0x00,                        -- flags
					0x44,                        -- length
					netbios.name_encode(name),   -- server name
					netbios.name_encode("NMAP")  -- client name
				);

		stdnse.print_debug(3, "Connecting to %s", host.ip)
		status, err = socket:connect(host.ip, port, "tcp")
		if(status == false) then
			socket:close()
			return false, err
		end

		-- Send the session request
		stdnse.print_debug(3, "Sending NetBIOS session request with name %s", name)
		status, err = socket:send(session_request)
		if(status == false) then
			socket:close()
			return false, err
		end
		socket:set_timeout(1000)
	
		-- Receive the session response
		stdnse.print_debug(3, "Receiving NetBIOS session response")
		status, result = socket:receive_bytes(4);
		if(status == false) then
			socket:close()
			return false, result
		end
		pos, result, flags, length = bin.unpack(">CCS", result)
	
		-- Check for a position session response (0x82)
		if result == 0x82 then
			stdnse.print_debug(3, "Successfully established NetBIOS session with server name %s", name)
			return true, socket
		end

		-- If the session failed, close the socket and try the next name
		stdnse.print_debug(3, "Session request failed, trying next name")
		socket:close()
	
		-- Try the next name
		i = i + 1

	until i > #names

	-- We reached the end of our names list
	stdnse.print_debug(3, "None of the NetBIOS names worked!")
	return false, "Couldn't find a NetBIOS name that works for the server. Sorry!"
end



--- Creates a string containing a SMB packet header. The header looks like this:\n
-- --------------------------------------------------------------------------------------------------\n
-- | 31 30 29 28 27 26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10 9  8  7  6  5  4  3  2  1  0 |\n
-- --------------------------------------------------------------------------------------------------\n
-- |         0xFF           |          'S'          |        'M'            |         'B'           |\n
-- --------------------------------------------------------------------------------------------------\n
-- |        Command         |                             Status...                                 |\n
-- --------------------------------------------------------------------------------------------------\n
-- |    ...Status           |        Flags          |                    Flags2                     |\n
-- --------------------------------------------------------------------------------------------------\n
-- |                    PID_high                    |                  Signature.....               |\n
-- --------------------------------------------------------------------------------------------------\n
-- |                                        ....Signature....                                       |\n
-- --------------------------------------------------------------------------------------------------\n
-- |              ....Signature                     |                    Unused                     |\n
-- --------------------------------------------------------------------------------------------------\n
-- |                      TID                       |                     PID                       |\n
-- --------------------------------------------------------------------------------------------------\n
-- |                      UID                       |                     MID                       |\n
-- ------------------------------------------------------------------------------------------------- \n
--
-- All fields are, incidentally, encoded in little endian byte order. \n
--\n
-- For the purposes here, the program doesn't care about most of the fields so they're given default \n
-- values. The fields of interest are:\n
-- * Command -- The command of the packet (SMB_COM_NEGOTIATE, SMB_COM_SESSION_SETUP_ANDX, etc)\n
-- * UID/TID -- Sent by the server, and just have to be echoed back\n
--@param command The command to use.
--@param uid     The UserID, which is returned by SMB_COM_SESSION_SETUP_ANDX (0 otherwise)
--@param tid     The TreeID, which is returned by SMB_COM_TREE_CONNECT_ANDX (0 otherwise)
--@return A binary string containing the packed packet header. 
local function smb_encode_header(command, uid, tid)

	-- Used for the header
	local smb = string.char(0xFF) .. "SMB"

	-- Pretty much every flags is deprecated. We set these two because they're required to be on. 
	local flags  = bit.bor(0x10, 0x08) -- SMB_FLAGS_CANONICAL_PATHNAMES | SMB_FLAGS_CASELESS_PATHNAMES
	-- These flags are less deprecated. We negotiate 32-bit status codes and long names. We also don't include Unicode, which tells
	-- the server that we deal in ASCII. 
	local flags2 = bit.bor(0x4000, 0x0040, 0x0001) -- SMB_FLAGS2_32BIT_STATUS | SMB_FLAGS2_IS_LONG_NAME | SMB_FLAGS2_KNOWS_LONG_NAMES

	local header = bin.pack("<CCCCCICSSLSSSSS",
				smb:byte(1),  -- Header
				smb:byte(2),  -- Header
				smb:byte(3),  -- Header
				smb:byte(4),  -- Header
				command,      -- Command
				0,            -- status
				flags,        -- flags
				flags2,       -- flags2
				0,            -- extra (pid_high)
				0,            -- extra (signature)
				0,            -- extra (unused)
				tid,          -- tid
				0,            -- pid
				uid,          -- uid
				0             -- mid
			)

	return header
end

--- Converts a string containing the parameters section into the encoded parameters string. 
-- The encoding is simple:\n
-- (1 byte)   The number of 2-byte values in the parameters section\n
-- (variable) The parameter section\n
-- This is automatically done by smb_send(). 
-- 
-- @param parameters The parameters section. 
-- @return The encoded parameters. 
local function smb_encode_parameters(parameters)
	return bin.pack("<CA", string.len(parameters) / 2, parameters)
end

--- Converts a string containing the data section into the encoded data string. 
-- The encoding is simple:\n
-- (2 bytes)  The number of bytes in the data section\n
-- (variable) The data section\n
-- This is automatically done by smb_send(). 
--
-- @param data The data section. 
-- @return The encoded data.
local function smb_encode_data(data)
	return bin.pack("<SA", string.len(data), data)
end

--- Prepends the NetBIOS header to the packet, which is essentially the length, encoded
--  in 4 bytes of big endian, and sends it out. The length field is actually 17 or 24 bits 
--  wide, depending on whether or not we're using raw, but that shouldn't matter. 
--
--@param socket The socket to send the packet on.
--@param header The header, encoded with smb_get_header().
--@param parameters The parameters
--@param data The data
--@return (result, err) If result is false, err is the error message. Otherwise, err is
--        undefined
function smb_send(socket, header, parameters, data)
    local encoded_parameters = smb_encode_parameters(parameters)
    local encoded_data       = smb_encode_data(data)
    local len = string.len(header) + string.len(encoded_parameters) + string.len(encoded_data)
    local out = bin.pack(">I<AAA", len, header, encoded_parameters, encoded_data)

	stdnse.print_debug(2, "Sending SMB packet (len: %d)", string.len(out))
    return socket:send(out)
end

--- Reads the next packet from the socket, and parses it into the header, parameters, 
--  and data. 
-- [TODO] This assumes that exactly one packet arrives, which may not be the case. 
--        Some buffering should happen here. Currently, we're waiting on 32 bytes, which
--        is the length of the header, but there's no guarantee that we get the entire
--        body. 
--@param socket The socket to read the packet from
--@return (status, header, parameters, data) If status is true, the header, 
--        parameters, and data are all the raw arrays (with the lengths already
--        removed). If status is false, header contains an error message and parameters/
--        data are undefined. 
function smb_read(socket)
	local status, result
	local pos, length, header, parameter_length, parameters, data_length, data

	-- Receive the response
	-- [TODO] set the timeout length per jah's strategy:
	--   http://seclists.org/nmap-dev/2008/q3/0702.html
	socket:set_timeout(1000)
	status, result = socket:receive_bytes(32);

	-- Make sure the connection is still alive
	if(status ~= true) then
		return false, result
	end

	-- The length of the packet is 4 bytes of big endian (for our purposes).
	-- The header is 32 bytes.
	pos, length, header   = bin.unpack(">I<A32", result)
	-- The parameters length is a 1-byte value.
	pos, parameter_length = bin.unpack("<C",     result, pos)
	-- Double the length parameter, since parameters are two-byte values. 
	pos, parameters       = bin.unpack(string.format("<A%d", parameter_length*2), result, pos)
	-- The data length is a 2-byte value. 
	pos, data_length      = bin.unpack("<S",     result, pos)
	-- Read that many bytes of data.
	pos, data             = bin.unpack(string.format("<A%d", data_length),        result, pos)

	stdnse.print_debug(2, "Received %d bytes from SMB", string.len(result))
	return status, header, parameters, data
end

--- Sends out SMB_COM_NEGOTIATE_PROTOCOL, which is typically the first SMB packet sent out. 
-- Sends the following:\n
-- * List of known protocols\n
--\n
-- Receives:\n
-- * The prefered dialect\n
-- * The security mode\n
-- * Max number of multiplexed connectiosn, virtual circuits, and buffer sizes\n
-- * The server's system time and timezone\n
-- * The "encryption key" (aka, the server challenge)\n
-- * The capabilities\n
-- * The server and domain names\n
--@param socket The socket, in the proper state (ie, newly connected). 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a 
--        table with the following elements:\n
--      'security_mode'    Whether or not to use cleartext passwords, message signatures, etc.\n
--      'max_mpx'          Maximum number of multiplexed connections\n
--      'max_vc'           Maximum number of virtual circuits\n
--      'max_buffer'       Maximum buffer size\n
--      'max_raw_buffer'   Maximum buffer size for raw connections (considered obsolete)\n
--      'session_key'      A value that's basically just echoed back\n
--      'capabilities'     The server's capabilities\n
--      'time'             The server's time (in UNIX-style seconds since 1970)\n
--      'date'             The server's date in a user-readable format\n
--      'timezone'         The server's timezone, in hours from UTC\n
--      'timezone_str'     The server's timezone, as a string\n
--      'server_challenge' A random string used for challenge/response\n
--      'domain'           The server's primary domain\n
--      'server'           The server's name\n
function negotiate_protocol(socket)
	local header, parameters, data
	local pos
	local header1, header2, header3, ehader4, command, status, flags, flags2, pid_high, signature, unused, pid, mid
	local dialect, security_mode, max_mpx, max_vc, max_buffer, max_raw_buffer, session_key, capabilities, time, timezone, key_length
	local server_challenge, date, timezone_str
	local domain, server
	local response = {}

	header     = smb_encode_header(0x72, 0, 0)

	-- Parameters are blank
	parameters = ""

	-- Data is a list of strings, terminated by a blank one. 
	data       = bin.pack("<CzCz", 2, "NT LM 0.12", 2, "")

	-- Send the negotiate request
	stdnse.print_debug(2, "Sending SMB_COM_NEGOTIATE_PROTOCOL")
	result, err = smb_send(socket, header, parameters, data)
	if(status == false) then
		return err
	end

	-- Read the result
	status, header, parameters, data = smb_read(socket)
	if(status ~= true) then
		return false, header
	end

	-- Since this is our first response, parse out the header
	pos, header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid = bin.unpack("<CCCCCICSSlSSSSS", header)

	-- Parse the parameter section
	pos, dialect, security_mode, max_mpx, max_vc, max_buffer, max_raw_buffer, session_key, capabilities, time, timezone, key_length = bin.unpack("<SCSSIIIILsC", parameters)

	-- Convert the time and timezone to more useful values
	time = (time / 10000000) - 11644473600
	date = os.date("%Y-%m-%d %H:%M:%S", time)
	timezone = -(timezone / 60)
	if(timezone == 0) then
		timezone_str = "UTC+0"
	elseif(timezone < 0) then
		timezone_str = "UTC-" .. math.abs(timezone)
	else
		timezone_str = "UTC+" .. timezone
	end

	-- Data section
	-- This one's a little messier, because I don't appear to have unicode support
	pos, server_challenge = bin.unpack(string.format("<A%d", key_length), data)

	-- Get the domain as a Unicode string
	local ch, dummy
	domain = ""
	pos, ch, dummy = bin.unpack("<CC", data, pos)
	while ch ~= 0 do
		domain = domain .. string.char(ch)
		pos, ch, dummy = bin.unpack("<CC", data, pos)
	end

	-- Get the server name as a Unicode string
	server = ""
	pos, ch, dummy = bin.unpack("<CC", data, pos)
	while ch do
		server = server .. string.char(ch)
		pos, ch, dummy = bin.unpack("<CC", data, pos)
	end

	-- Fill out response variables
	response['security_mode']    = security_mode
	response['max_mpx']          = max_mpx
	response['max_vc']           = max_vc
	response['max_buffer']       = max_buffer
	response['max_raw_buffer']   = max_raw_buffer
	response['session_key']      = session_key
	response['capabilities']     = capabilities
	response['time']             = time
	response['date']             = date
	response['timezone']         = timezone
	response['timezone_str']     = timezone_str
	response['server_challenge'] = server_challenge
	response['domain']           = domain
	response['server']           = server

	return true, response
end

--- Sends out SMB_COM_SESSION_START_ANDX, which attempts to log a user in. 
-- Sends the following:\n
-- * Negotiated parameters (multiplexed connections, virtual circuit, capabilities)\n
-- * Passwords (plaintext, unicode, lanman, ntlm, lmv2, ntlmv2, etc)\n
-- * Account name\n
-- * OS (I just send "Nmap")\n
-- * Native LAN Manager (no clue what that is, but it seems to be ignored)\n
--\n
-- Receives the following:\n
-- * User ID\n
-- * Server OS\n
--\n
--@param socket       The socket, in the proper state (ie, after protocol has been negotiated).
--@param username     The account name to use. For Null sessions, leave it blank (''). 
--@param session_key  The session_key value, returned by SMB_COM_NEGOTIATE_PROTOCOL.  
--@param capabilities The server's capabilities, returned by SMB_COM_NEGOTIATE_PROTOCOL. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a 
--        table with the following elements:\n
--      'uid'         The UserID for the session
--      'is_guest'    If set, the username wasn't found so the user was automatically logged in
--                    as the guest account
--      'os'          The operating system
--      'lanmanager'  The servers's LAN Manager
function start_session(socket, username, session_key, capabilities)
	local status, result
	local header, parameters, data
	local pos
	local header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid 
	local andx_command, andx_reserved, andx_offset, action
	local os, lanmanager, domain
	local response = {}

	header     = smb_encode_header(0x73, 0, 0)

	-- Parameters
	parameters = bin.pack("<CCSSSSISSII", 
				0xFF,        -- ANDX -- no further commands
				0x00,        -- ANDX -- Reserved (0)
				0x0000,      -- ANDX -- next offset
				0x1000,      -- Max buffer size
				0x0001,      -- Max multiplexes
				0x0000,      -- Virtual circuit num
				session_key, -- The session key
				0,           -- ANSI/Lanman password length
				0,           -- Unicode/NTLM password length
				0,           -- Reserved
                capabilities -- Capabilities
			)

	-- Data is a list of strings, terminated by a blank one. 
	data       = bin.pack("<zzzz", 
				                -- ANSI/Lanman password
				                -- Unicode/NTLM password
				username,       -- Account
				"",             -- Domain
				"Nmap",         -- OS
				"Native Lanman" -- Native LAN Manager
			)
	-- Send the session setup request
	stdnse.print_debug(2, "Sending SMB_COM_SESSION_SETUP_ANDX")
	result, err = smb_send(socket, header, parameters, data)
	if(result == false) then
		return false, err
	end

	-- Read the result
	status, header, parameters, data = smb_read(socket)
	if(status ~= true) then
		return false, header
	end

	-- Check if we were allowed in
	pos, header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid = bin.unpack("<CCCCCICSSlSSSSS", header)
	if(status ~= 0) then
		return false, status
	end

	-- Parse the parameters
	pos, andx_command, andx_reserved, andx_offset, action = bin.unpack("<CCSS", parameters)

	-- Parse the data
	pos, os, lanmanager, domain = bin.unpack("<zzz", data)

	-- Fill in the response string
	response['uid']        = uid
	response['is_guest']   = bit.band(action, 1)
	response['os']         = os
	response['lanmanager'] = lanmanager

	return true, response

end
 
--- Sends out SMB_COM_SESSION_TREE_CONNECT_ANDX, which attempts to connect to a share. 
-- Sends the following:\n
-- * Password (for share-level security, which we don't support)\n
-- * Share name\n
-- * Share type (or "?????" if it's unknown, that's what we do)\n
--\n
-- Receives the following:\n
-- * Tree ID\n
--\n
--@param socket The socket, in the proper state. 
--@param path   The path to connect (eg, \\servername\C$)
--@param uid    The UserID, returned by SMB_COM_SESSION_SETUP_ANDX
--@return (status, result) If status is false, result is an error message. Otherwise, result is a 
--        table with the following elements:\n
--      'tid'         The TreeID for the session
function tree_connect(socket, path, uid)
	local response = ""
	local header, parameters, data
	local pos
	local header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, pid, mid 
	local andx_command, andx_reserved, andx_offset, action
	local response = {}

	header = smb_encode_header(0x75, uid, 0)
	parameters = bin.pack("<CCSSS", 
					0xFF,   -- ANDX no further commands
					0x00,   -- ANDX reserved
					0x0000, -- ANDX offset
					0x0000, -- flags
					0x0000 -- password length (for share-level security)
				)
	data = bin.pack("zz", 
					        -- Share-level password
					path,   -- Path
					"?????" -- Type of tree ("?????" = any)
				)

	-- Send the tree connect request
	stdnse.print_debug(2, "Sending SMB_COM_TREE_CONNECT_ANDX")
	result, err = smb_send(socket, header, parameters, data)
	if(result == false) then
		return false, err
	end

	-- Read the result
	status, header, parameters, data = smb_read(socket)
	if(status ~= true) then
		return false, header
	end

	-- Check if we were allowed in
	pos, header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid = bin.unpack("<CCCCCICSSlSSSSS", header)
	if(status ~= 0) then
		return false, status
	end

	response['tid'] = tid

	return true, response
	
end

