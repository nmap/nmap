--- Server Message Block (SMB, also known as CIFS) traffic.
--
-- SMB traffic is normally sent to/from ports 139 or 445 of Windows systems, some of them
-- properly and many of them not. Samba implements it, as do many printers and other embedded
-- devices. Although the protocol has been documented decently well by Samba and others, 
-- many 3rd party implementations are broken or make assumptions. 
--
-- Naturally, I do the same; however, that being said, this has been tested against every
-- broken implementation we could find, and will accept (or fail gracefully) against any 
-- bad implementations we could find. 
--
-- The intention of this library is to eventually handle all aspects of the SMB protocol.
-- That being said, I'm only implementing the pieces that I find myself needing. If you 
-- require something more, let me know and I'll put it on my todo list. 
--
-- A programmer using this library must already have some knowledge of the SMB protocol, 
-- although a lot isn't necessary. You can pick up a lot by looking at the code that uses
-- this. The basic login/logoff is this:
--
--<code>
-- [connect]
-- C->S SMB_COM_NEGOTIATE
-- S->C SMB_COM_NEGOTIATE
-- C->S SMB_COM_SESSION_SETUP_ANDX
-- S->C SMB_COM_SESSION_SETUP_ANDX
-- C->S SMB_COM_TREE_CONNECT_ANDX
-- S->C SMB_COM_TREE_CONNECT_ANDX
-- ...
-- C->S SMB_COM_TREE_DISCONNECT
-- S->C SMB_COM_TREE_DISCONNECT
-- C->S SMB_COM_LOGOFF_ANDX
-- S->C SMB_COM_LOGOFF_ANDX
--</code>
--
-- In terms of functions here, the protocol is:
--
--<code>
-- status, smbstate = smb.start(host)
-- status, err      = smb.negotiate_protocol(smbstate)
-- status, err      = smb.start_session(smbstate)
-- status, err      = smb.tree_connect(smbstate, path)
-- ...
-- status, err      = smb.tree_disconnect(smbstate)
-- status, err      = smb.logoff(smbstate)
-- status, err      = smb.stop(smbstate)
--</code>
--
-- The <code>stop</code> function will automatically call tree_disconnect and logoff, 
-- cleaning up the session, if it hasn't been done already.
-- 
-- To initially begin the connection, there are two options:
--
-- 1) Attempt to start a raw session over 445, if it's open.
--
-- 2) Attempt to start a NetBIOS session over 139. Although the 
--    protocol's the same, it requires a <code>session request</code> packet. 
--    That packet requires the computer's name, which is requested
--    using a NBSTAT probe over UDP port 137. 
--
-- Once it's connected, a <code>SMB_COM_NEGOTIATE</code> packet is sent, requesting the protocol 
-- "NT LM 0.12", which is the most commonly supported one. Among other things, the server's 
-- response contains the host's security level, the system time, and the computer/domain name. 
-- Some systems will refuse to use that protocol and return "-1" or "1" instead of 0. If that's 
-- detected, we kill the connection (because the protocol following will be unexpected). 
--
-- If that's successful, <code>SMB_COM_SESSION_SETUP_ANDX</code> is sent. It is essentially the logon
-- packet, where the username, domain, and password are sent to the server for verification. 
-- The username and password are generally picked up from the program parameters, which are
-- set when running a script, or from the registry [TODO: Where?], which are set by other 
-- scripts. However, they can also be passed as parameters to the function, which will 
-- override any other username/password set. 
--
-- If a username is set without a password, then a NULL session is started. If a login fails,
-- we attempt to log in as the 'GUEST' account with a blank password. If that fails, we try
-- setting up a NULL session. Starting a NULL session will always work, but we may not get
-- any further (<code>tree_connect</code> might fail). 
--
-- In terms of the login protocol, by default, we sent only NTLMv1 authentication, Lanman
-- isn't sent at all. The reason for this is, NTLMv2 isn't supported by every system (and I 
-- don't know how to do message signing on the v2 protocols), and doesn't have a significant security
-- advantage over NTLMv1 for performing single scans (the major change in NTLMv2 is incorporating 
-- a client challenge). Lanman is somewhat insecure, though, so I don't send it at all. These options 
-- can, however, be overridden either through script parameters or registry settings.
--
-- Lanman v1 is a fairly weak protocol, although it's still fairly difficult to break. NTLMv1 is a slightly more secure
-- protocol (although not much) -- it's also fairly difficult to reverse, though. Windows clients, by default send LMv1 and
-- NTLMv1 together, but every modern Windows server will accept NTLM alone, so I opted to use that. LMv2 and NTLMv2 are
-- slightly more secure, and they let the client specify random data (to help fight malicious servers with pre-
-- generated tables). LMv2 and NTLMv2 are identical, except that NTLMv2 has a longer client challenge. LMv2 can be sent
-- alone, but NTLMv2 can't.
--
-- Another interesting aspect of the password hashing is that the original password isn't even necessary, the
-- password's hash can be used instead. This hash can be dumped from memory of a live system by tools such as
-- pwdump and fgdump, or read straight from the SAM file (maybe some day, I'll do an Nmap script to dump it). 
-- This means that if a password file is recovered, it doesn't even need to be cracked before it can be used here.
--
-- Thanks go to Christopher R. Hertel and his book Implementing CIFS, which 
-- taught me everything I know about Microsoft's protocols. Additionally, I used Samba's
-- list of error codes for my constants, although I don't believe they would be covered
-- by GPL, since they're public now anyways, but I'm not a lawyer and, if somebody feels
-- differently, let me know and we can sort this out. 
--
-- Scripts that use this module can use the script arguments
-- <code>smbusername</code>, <code>smbpassword</code>, <code>smbhash</code>,
-- example of using these script arguments:
-- <code>
-- nmap --script=smb-<script>.nse --script-args=smbuser=ron,smbpass=iagotest2k3 <host>
-- </code>
-- 
--@args  smbusername The SMB username to log in with. The forms "DOMAIN\username" and "username@DOMAIN"
--                   are not understood. To set a domain, use the <code>smbdomain</code> argument. 
--@args  smbdomain   The domain to log in with. If you aren't in a domained environment, then anything
--                   will (should?) be accepted by the server. 
--@args  smbpassword The password to connect with. Be cautious with this, since some servers will lock
--                   accounts if the incorrect password is given. Although it's rare that the
--                   Administrator account can be locked out, in the off chance that it can, you could
--                   get yourself in trouble. 
--@args  smbhash     A password hash to use when logging in. This is given as a single hex string (32
--                   characters) or a pair of hex strings (both 32 characters, optionally separated by a 
--                   single character). These hashes are the LanMan or NTLM hash of the user's password,
--                   and are stored on disk or in memory. They can be retrieved from memory
--                   using the fgdump or pwdump tools. 
--@args  smbtype     The type of SMB authentication to use. These are the possible options:
-- * <code>v1</code>: Sends LMv1 and NTLMv1.
-- * <code>LMv1</code>: Sends LMv1 only.
-- * <code>NTLMv1</code>: Sends NTLMv1 only (default).
-- * <code>v2</code>: Sends LMv2 and NTLMv2.
-- * <code>LMv2</code>: Sends LMv2 only.
--                   The default, <code>NTLMv1</code>, is a pretty
--                   decent compromise between security and compatibility. If you are paranoid, you might 
--                   want to use <code>v2</code> or <code>lmv2</code> for this. (Actually, if you're paranoid, you should be 
--                   avoiding this protocol altogether :P). If you're using an extremely old system, you 
--                   might need to set this to <code>v1</code> or <code>lm</code>, which are less secure but more compatible. 
--@author Ron Bowes <ron@skullsecurity.net>
--@copyright Same as Nmap--See http://nmap.org/book/man-legal.html
-----------------------------------------------------------------------
module(... or "smb", package.seeall)

require 'bit'
require 'bin'
require 'netbios'
require 'stdnse'
have_ssl = (nmap.have_ssl() and pcall(require, "openssl"))

-- These arrays are filled in with constants at the bottom of this file
command_codes = {}
command_names = {}
status_codes = {}
status_names = {}

local mutexes = setmetatable({}, {__mode = "k"});
--local debug_mutex = nmap.mutex("SMB-DEBUG")

---Returns the mutex that should be used by the current connection. This mutex attempts
-- to use the name, first, then falls back to the IP if no name was returned. 
--
--@param smbstate The SMB object associated with the connection
--@return A mutex
local function get_mutex(smbstate)
	local mutex_name = "SMB-"
	local mutex

--	if(nmap.debugging() > 0) then
--		return debug_mutex
--	end

	-- Decide whether to use the name or the ip address as the unique identifier
	if(smbstate['name'] ~= nil) then
		mutex_name = mutex_name .. smbstate['name']
	else
		mutex_name = mutex_name .. smbstate['ip']
	end

	if(mutexes[smbstate] == nil) then
		mutex = nmap.mutex(mutex_name)
		mutexes[smbstate] = mutex
	else
		mutex = mutexes[smbstate]
	end

	stdnse.print_debug(3, "SMB: Using mutex named '%s'", mutex_name)

	return mutex
end

---Locks the mutex being used by this host. Doesn't return until it successfully 
-- obtains a lock. 
--
--@param smbstate The SMB object associated with the connection
--@param func     A name to associate with this call (used purely for debugging
--                and logging)
local function lock_mutex(smbstate, func)
	local mutex

	stdnse.print_debug(3, "SMB: Attempting to lock mutex [%s]", func)
	mutex = get_mutex(smbstate)
	mutex "lock"
	stdnse.print_debug(3, "SMB: Mutex lock obtained [%s]", func)
end

---Unlocks the mutex being used by this host.
--
--@param smbstate The SMB object associated with the connection
--@param func     A name to associate with this call (used purely for debugging
--                and logging)
local function unlock_mutex(smbstate, func)
	local mutex

	stdnse.print_debug(3, "SMB: Attempting to release mutex [%s]", func)
	mutex = get_mutex(smbstate)
	mutex "done"
	stdnse.print_debug(3, "SMB: Mutex released [%s]", func)
end

---Convert a status number from the SMB header into a status name, returning an error message (not nil) if 
-- it wasn't found. 
--
--@param status The numerical status. 
--@return A string representing the error. Never nil. 
function get_status_name(status)

	if(status_names[status] == nil) then
		-- If the name wasn't found in the array, do a linear search on it (TODO: Why is this happening??)
		for i, v in pairs(status_names) do
			if(v == status) then
				return i
			end
		end

		return string.format("NT_STATUS_UNKNOWN (0x%08x)", status)
	else
		return status_names[status]
	end
end


--- Determines whether or not SMB checks are possible on this host, and, if they are, 
--  which port is best to use. This is how it decides:
--
-- * If port tcp/445 is open, use it for a raw connection
-- * Otherwise, if ports tcp/139 and udp/137 are open, do a NetBIOS connection. Since
--   UDP scanning isn't default, we're also ok with udp/137 in an unknown state. 
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

---Either return the string itself, or return "<blank>" (or the value of the second parameter) if the string
-- was blank or nil. 
--@param string The base string. 
--@param blank  The string to return if <code>string</code> was blank
--@return Either <code>string</code> or, if it was blank, <code>blank</code>
function string_or_blank(string, blank)
	if(string == nil or string == "") then
		if(blank == nil) then
			return "<blank>"
		else
			return blank
		end
	else
		return string
	end
end

--- Begins a SMB session, automatically determining the best way to connect. Also starts a mutex
--  with mutex_id. This prevents multiple threads from making queries at the same time (which breaks
--  SMB). 
--
-- @param host The host object
-- @return (status, smb) if the status is true, result is the newly crated smb object; 
--         otherwise, socket is the error message. 
function start(host)
	local port = get_port(host)
	local status, result
	local state = {}

	state['uid']  = 0
	state['tid']  = 0
	state['ip']   = host.ip

	-- Store the name of the server
	status, result = netbios.get_server_name(host.ip)
	if(status == true) then
		state['name'] = result
	end

	stdnse.print_debug(2, "SMB: Starting SMB session for %s (%s)", host.name, host.ip)

	if(port == nil) then
		return false, "SMB: Couldn't find a valid port to check"
	end

	lock_mutex(state, "start(1)")

	if(port == 445) then
		status, state['socket'] = start_raw(host, port)
		state['port'] = 445

		if(status == false) then
			unlock_mutex(state, "start(1)")
			return false, state['socket']
		end
		return true, state

	elseif(port == 139) then
		status, state['socket'] = start_netbios(host, port)
		state['port'] = 139
		if(status == false) then
			unlock_mutex(state, "start(2)")
			return false, state['socket']
		end
		return true, state

	end

	unlock_mutex(state, "start(3)")

	return false, "SMB: Couldn't find a valid port to check"
end

--- Kills the SMB connection, closes the socket, and releases the mutex. Because of the mutex 
--  being released, a script HAS to call <code>stop</code> before it exits, no matter why it's exiting! 
--
--  In addition to killing the connection, this function will log off the user and disconnect
--  the connected tree, if possible.
--
--@param smb    The SMB object associated with the connection
--@return (status, result) If status is false, result is an error message. Otherwise, result
--        is undefined. 
function stop(smb) 

	if(smb['tid'] ~= 0) then
		tree_disconnect(smb)
	end

	if(smb['uid'] ~= 0) then
		logoff(smb)
	end

	unlock_mutex(smb, "stop()")

	stdnse.print_debug(2, "SMB: Closing socket")
	if(smb['socket'] ~= nil) then
		local status, err = smb['socket']:close()

		if(status == false) then
			return false, "SMB: Failed to close socket: " .. err
		end
	end

	return true
end

--- Begins a raw SMB session, likely over port 445. Since nothing extra is required, this
--  function simply makes a connection and returns the socket. 
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
		return false, "SMB: Failed to connect to host: " .. err
	end

	return true, socket
end

--- This function will take a string like "a.b.c.d" and return "a", "a.b", "a.b.c", and "a.b.c.d". 
--  This is used for discovering NetBIOS names. If a NetBIOS name is unknown, the substrings of the 
--  DNS name can be used in this way. 
--
--@param name The name to take apart
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
--  a parameter, or it can be automatically determined. 
--
-- Automatically determining the name is interesting, to say the least. Here are the names
-- it tries, and the order it tries them in:
-- * The name the user provided, if present
-- * The name pulled from NetBIOS (udp/137), if possible
-- * The generic name "*SMBSERVER"
-- * Each subset of the domain name (for example, scanme.insecure.org would attempt "scanme",
--    "scanme.insecure", and "scanme.insecure.org")
--
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
		stdnse.print_debug(1, "SMB: Trying to start NetBIOS session with name = '%s'", name)
		-- Request a NetBIOS session
		session_request = bin.pack(">CCSzz", 
					0x81,                        -- session request
					0x00,                        -- flags
					0x44,                        -- length
					netbios.name_encode(name),   -- server name
					netbios.name_encode("NMAP")  -- client name
				);

		stdnse.print_debug(3, "SMB: Connecting to %s", host.ip)
		status, err = socket:connect(host.ip, port, "tcp")
		if(status == false) then
			socket:close()
			return false, "SMB: Failed to connect: " .. err
		end

		-- Send the session request
		stdnse.print_debug(3, "SMB: Sending NetBIOS session request with name %s", name)
		status, err = socket:send(session_request)
		if(status == false) then
			socket:close()
			return false, "SMB: Failed to send: " .. err
		end
		socket:set_timeout(5000)
	
		-- Receive the session response
		stdnse.print_debug(3, "SMB: Receiving NetBIOS session response")
		status, result = socket:receive_bytes(4);
		if(status == false) then
			socket:close()
			return false, "SMB: Failed to close socket: " .. result
		end
		pos, result, flags, length = bin.unpack(">CCS", result)
	
		-- Check for a position session response (0x82)
		if result == 0x82 then
			stdnse.print_debug(3, "SMB: Successfully established NetBIOS session with server name %s", name)
			return true, socket
		end

		-- If the session failed, close the socket and try the next name
		stdnse.print_debug(1, "SMB: Session request failed, trying next name")
		socket:close()
	
		-- Try the next name
		i = i + 1

	until i > #names

	-- We reached the end of our names list
	stdnse.print_debug(1, "SMB: None of the NetBIOS names worked!")
	return false, "SMB: Couldn't find a NetBIOS name that works for the server. Sorry!"
end

---Generate the Lanman v1 hash (LMv1). The generated hash is incredibly easy to reverse, because the input
-- is padded or truncated to 14 characters, then split into two 7-character strings. Each of these strings
-- are used as a key to encrypt the string, "KGS!@#$%" in DES. Because the keys are no longer than 
-- 7-characters long, it's pretty trivial to bruteforce them. 
--
--@param password the password to hash
--@return (status, hash) If status is true, the hash is returned; otherwise, an error message is returned.
function lm_create_hash(password)
	if(have_ssl ~= true) then
		return false, "SMB: OpenSSL not present"
	end

	local str1, str2
	local key1, key2
	local result

	-- Convert the password to uppercase
	password = string.upper(password)

	-- If password is under 14 characters, pad it to 14
	if(#password < 14) then
		password = password .. string.rep(string.char(0), 14 - #password)
	end

	-- Take the first and second half of the password (note that if it's longer than 14 characters, it's truncated)
	str1 = string.sub(password, 1, 7)
	str2 = string.sub(password, 8, 14)

	-- Generate the keys
	key1 = openssl.DES_string_to_key(str1)
	key2 = openssl.DES_string_to_key(str2)

	-- Encrypt the string "KGS!@#$%" with each half, and concatenate it
	result = openssl.encrypt("DES", key1, nil, "KGS!@#$%") .. openssl.encrypt("DES", key2, nil, "KGS!@#$%")

	return true, result
end

---Generate the NTLMv1 hash. This hash is quite a bit better than LMv1, and is far easier to generate. Basically,
-- it's the MD4 of the Unicode password. 
--
--@param password the password to hash
--@return (status, hash) If status is true, the hash is returned; otherwise, an error message is returned.
function ntlm_create_hash(password)
	if(have_ssl ~= true) then
		return false, "SMB: OpenSSL not present"
	end

	local i
	local unicode = ""

	for i = 1, #password, 1 do
		unicode = unicode .. bin.pack("<S", string.byte(password, i))
	end

	return true, openssl.md4(unicode)
end

---Create the Lanman response to send back to the server. To do this, the Lanman password is padded to 21 
-- characters and split into three 7-character strings. Each of those strings is used as a key to encrypt
-- the server challenge. The three encrypted strings are concatenated and returned. 
--
--@param lanman    The LMv1 hash
--@param challenge The server's challenge. 
--@return (status, response) If status is true, the response is returned; otherwise, an error message is returned.
function lm_create_response(lanman, challenge)
	if(have_ssl ~= true) then
		return false, "SMB: OpenSSL not present"
	end

	local str1, str2, str3
	local key1, key2, key3
	local result

	-- Pad the hash to 21 characters
	lanman = lanman .. string.rep(string.char(0), 21 - #lanman)

	-- Take the first and second half of the password (note that if it's longer than 14 characters, it's truncated)
	str1 = string.sub(lanman, 1,  7)
	str2 = string.sub(lanman, 8,  14)
	str3 = string.sub(lanman, 15, 21)

	-- Generate the keys
	key1 = openssl.DES_string_to_key(str1)
	key2 = openssl.DES_string_to_key(str2)
	key3 = openssl.DES_string_to_key(str3)

	-- Encrypt the challenge with each key
	result = openssl.encrypt("DES", key1, nil, challenge) .. openssl.encrypt("DES", key2, nil, challenge) .. openssl.encrypt("DES", key3, nil, challenge) 

	return true, result
end

---Create the NTLM response to send back to the server. This is actually done the exact same way as the Lanman hash,
-- so I call the <code>Lanman</code> function. 
--
--@param ntlm      The NTLMv1 hash
--@param challenge The server's challenge. 
--@return (status, response) If status is true, the response is returned; otherwise, an error message is returned.
function ntlm_create_response(ntlm, challenge)
	return lm_create_response(ntlm, challenge)
end

---Create the NTLMv2 hash, which is based on the NTLMv1 hash (for easy upgrading), the username, and the domain. 
-- Essentially, the NTLM hash is used as a HMAC-MD5 key, which is used to hash the unicode domain concatenated 
-- with the unicode username. 
--
--@param ntlm     The NTLMv1 hash. 
--@param username The username we're using. 
--@param domain   The domain. 
--@return (status, response) If status is true, the response is returned; otherwise, an error message is returned.
function ntlmv2_create_hash(ntlm, username, domain)
	if(have_ssl ~= true) then
		return false, "SMB: OpenSSL not present"
	end

	local unicode = ""

	username = string.upper(username)
	domain   = string.upper(domain)

	for i = 1, #username, 1 do
		unicode = unicode .. bin.pack("<S", string.byte(username, i))
	end

	for i = 1, #domain, 1 do
		unicode = unicode .. bin.pack("<S", string.byte(domain, i))
	end

	return true, openssl.hmac("MD5", ntlm, unicode)
end

---Create the LMv2 response, which can be sent back to the server. This is identical to the <code>NTLMv2</code> function, 
-- except that it uses an 8-byte client challenge. 
--
-- The reason for LMv2 is a long and twisted story. Well, not really. The reason is basically that the v1 hashes
-- are always 24-bytes, and some servers expect 24 bytes, but the NTLMv2 hash is more than 24 bytes. So, the only
-- way to keep pass-through compatibility was to have a v2-hash that was guaranteed to be 24 bytes. So LMv1 was
-- born -- it has a 16-byte hash followed by the 8-byte client challenge, for a total of 24 bytes. And now you've
-- learned something
--
--@param ntlm      The NVLMv1 hash.
--@param username  The username we're using. 
--@param domain    The domain. 
--@param challenge The server challenge. 
--@return (status, response) If status is true, the response is returned; otherwise, an error message is returned.
function lmv2_create_response(ntlm, username, domain, challenge)
	return ntlmv2_create_response(ntlm, username, domain, challenge, 8)
end

---Create the NTLMv2 response, which can be sent back to the server. This is done by using the HMAC-MD5 algorithm
-- with the NTLMv2 hash as a key, and the server challenge concatenated with the client challenge for the data. 
-- The resulting hash is concatenated with the client challenge and returned.
--
-- The "proper" implementation for this uses a certain structure for the client challenge, involving the time
-- and computer name and stuff (if you don't do this, Wireshark tells you it's a malformed packet). In my tests, 
-- however, I couldn't get Vista to recognize a client challenge longer than 24 bytes, and this structure was
-- guaranteed to be much longer than 24 bytes. So, I just use a random string generated by OpenSSL. I've tested
-- it on every Windows system from Windows 2000 to Windows Vista, and it has always worked. 
function ntlmv2_create_response(ntlm, username, domain, challenge, client_challenge_length)
	if(have_ssl ~= true) then
		return false, "SMB: OpenSSL not present"
	end

	local client_challenge = openssl.rand_bytes(client_challenge_length)
	local ntlmv2_hash

	status, ntlmv2_hash = ntlmv2_create_hash(ntlm, username, domain)

	return true, openssl.hmac("MD5", ntlmv2_hash, challenge .. client_challenge) .. client_challenge
end


--- Creates a string containing a SMB packet header. The header looks like this:
-- 
--<code>
-- --------------------------------------------------------------------------------------------------
-- | 31 30 29 28 27 26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10 9  8  7  6  5  4  3  2  1  0 |
-- --------------------------------------------------------------------------------------------------
-- |         0xFF           |          'S'          |        'M'            |         'B'           |
-- --------------------------------------------------------------------------------------------------
-- |        Command         |                             Status...                                 |
-- --------------------------------------------------------------------------------------------------
-- |    ...Status           |        Flags          |                    Flags2                     |
-- --------------------------------------------------------------------------------------------------
-- |                    PID_high                    |                  Signature.....               |
-- --------------------------------------------------------------------------------------------------
-- |                                        ....Signature....                                       |
-- --------------------------------------------------------------------------------------------------
-- |              ....Signature                     |                    Unused                     |
-- --------------------------------------------------------------------------------------------------
-- |                      TID                       |                     PID                       |
-- --------------------------------------------------------------------------------------------------
-- |                      UID                       |                     MID                       |
-- ------------------------------------------------------------------------------------------------- 
--</code>
--
-- All fields are, incidentally, encoded in little endian byte order.
--
-- For the purposes here, the program doesn't care about most of the fields so they're given default 
-- values. The "command" field is the only one we ever have to set manually, in my experience. The TID
-- and UID need to be set, but those are stored in the smb state and don't require user intervention. 
--
--@param smb     The smb state table. 
--@param command The command to use.
--@return A binary string containing the packed packet header. 
local function smb_encode_header(smb, command)

	-- Used for the header
	local sig = string.char(0xFF) .. "SMB"

	-- Pretty much every flags is deprecated. We set these two because they're required to be on. 
	local flags  = bit.bor(0x10, 0x08) -- SMB_FLAGS_CANONICAL_PATHNAMES | SMB_FLAGS_CASELESS_PATHNAMES
	-- These flags are less deprecated. We negotiate 32-bit status codes and long names. We also don't include Unicode, which tells
	-- the server that we deal in ASCII. 
	local flags2 = bit.bor(0x4000, 0x0040, 0x0001) -- SMB_FLAGS2_32BIT_STATUS | SMB_FLAGS2_IS_LONG_NAME | SMB_FLAGS2_KNOWS_LONG_NAMES

	local header = bin.pack("<CCCCCICSSLSSSSS",
				sig:byte(1),  -- Header
				sig:byte(2),  -- Header
				sig:byte(3),  -- Header
				sig:byte(4),  -- Header
				command,      -- Command
				0,            -- status
				flags,        -- flags
				flags2,       -- flags2
				0,            -- extra (pid_high)
				0,            -- extra (signature)
				0,            -- extra (unused)
				smb['tid'],   -- tid
				0,            -- pid
				smb['uid'],   -- uid
				0             -- mid
			)

	return header
end

--- Converts a string containing the parameters section into the encoded parameters string. 
-- The encoding is simple:
-- * (1 byte)   The number of 2-byte values in the parameters section
-- * (variable) The parameter section
-- This is automatically done by <code>smb_send</code>. 
-- 
-- @param parameters The parameters section. 
-- @return The encoded parameters. 
local function smb_encode_parameters(parameters)
	return bin.pack("<CA", string.len(parameters) / 2, parameters)
end

--- Converts a string containing the data section into the encoded data string. 
-- The encoding is simple:
-- * (2 bytes)  The number of bytes in the data section
-- * (variable) The data section
-- This is automatically done by <code>smb_send</code>. 
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
--@param smb        The SMB object associated with the connection
--@param header     The header, encoded with <code>smb_get_header</code>.
--@param parameters The parameters.
--@param data       The data.
--@return (result, err) If result is false, err is the error message. Otherwise, err is
--        undefined
function smb_send(smb, header, parameters, data)
    local encoded_parameters = smb_encode_parameters(parameters)
    local encoded_data       = smb_encode_data(data)
    local len = string.len(header) + string.len(encoded_parameters) + string.len(encoded_data)
    local out = bin.pack(">I<AAA", len, header, encoded_parameters, encoded_data)

	stdnse.print_debug(3, "SMB: Sending SMB packet (len: %d)", string.len(out))
    return smb['socket']:send(out)
end

--- Reads the next packet from the socket, and parses it into the header, parameters, 
--  and data.
--
--@param smb The SMB object associated with the connection
--@return (status, header, parameters, data) If status is true, the header, 
--        parameters, and data are all the raw arrays (with the lengths already
--        removed). If status is false, header contains an error message and parameters/
--        data are undefined. 
function smb_read(smb)
	local status, result
	local pos, netbios_length, length, header, parameter_length, parameters, data_length, data

	-- Receive the response -- we make sure to receive at least 4 bytes, the length of the NetBIOS length
	-- [TODO] set the timeout length per jah's strategy:
	--   http://seclists.org/nmap-dev/2008/q3/0702.html
	smb['socket']:set_timeout(5000)
	status, result = smb['socket']:receive_bytes(4);

	-- Make sure the connection is still alive
	if(status ~= true) then
		return false, "SMB: Failed to receive bytes: " .. result
	end

	-- The length of the packet is 4 bytes of big endian (for our purposes).
	-- The NetBIOS header is 24 bits, big endian
	pos, netbios_length   = bin.unpack(">I", result)
	if(netbios_length == nil) then
		return false, "SMB: SMB server didn't comply with standards (incorrect data was returned) [1]"
	end
	-- Make the length 24 bits
	netbios_length = bit.band(netbios_length, 0x00FFFFFF)

	-- The total length is the netbios_length, plus 4 (for the length itself)
	length = netbios_length + 4

	-- If we haven't received enough bytes, try and get the rest (fragmentation!)
	if(#result < length) then
		local new_result
		status, new_result = smb['socket']:receive_bytes(netbios_length)

		stdnse.print_debug(1, "SMB: Received a fragmented packet, attempting to receive the rest of it (got %d bytes, need %d)", #result, length)

		-- Make sure the connection is still alive
		if(status ~= true) then
			return false, "SMB: Failed to receive bytes: " .. result
		end

		-- Append the new data to the old stuff
		result = result .. new_result
		stdnse.print_debug(1, "SMB: Finished receiving fragmented packet (got %d bytes, needed %d)", #result, length)
	end

	if(#result ~= length) then
		stdnse.print_debug(1, "SMB: Received wrong number of bytes, there will likely be issues (recieved %d, expected %d)", #result, length)
		return false, string.format("Didn't receive the expected number of bytes; recieved %d, expected %d. This will almost certainly cause some errors.", #result, length)
	end

	-- The header is 32 bytes.
	pos, header   = bin.unpack("<A32", result, pos)
	if(header == nil) then
		return false, "SMB: SMB server didn't comply with standards (incorrect data was returned) [2]"
	end

	-- The parameters length is a 1-byte value.
	pos, parameter_length = bin.unpack("<C",     result, pos)
	if(parameter_length == nil) then
		return false, "SMB: SMB server didn't comply with standards (incorrect data was returned) [3]"
	end

	-- Double the length parameter, since parameters are two-byte values. 
	pos, parameters       = bin.unpack(string.format("<A%d", parameter_length*2), result, pos)
	if(parameters == nil) then
		return false, "SMB: SMB server didn't comply with standards (incorrect data was returned) [4]"
	end

	-- The data length is a 2-byte value. 
	pos, data_length      = bin.unpack("<S",     result, pos)
	if(data_length == nil) then
		return false, "SMB: SMB server didn't comply with standards (incorrect data was returned) [5]"
	end

	-- Read that many bytes of data.
	pos, data             = bin.unpack(string.format("<A%d", data_length),        result, pos)
	if(data == nil) then
		return false, "SMB: SMB server didn't comply with standards (incorrect data was returned) [6]"
	end

	stdnse.print_debug(3, "SMB: Received %d bytes", string.len(result))
	return true, header, parameters, data
end

--- Sends out <code>SMB_COM_NEGOTIATE</code>, which is typically the first SMB packet sent out. 
-- Sends the following:
-- * List of known protocols
--
-- Receives:
-- * The prefered dialect
-- * The security mode
-- * Max number of multiplexed connectiosn, virtual circuits, and buffer sizes
-- * The server's system time and timezone
-- * The "encryption key" (aka, the server challenge)
-- * The capabilities
-- * The server and domain names
--
--@param smb    The SMB object associated with the connection
--@return (status, result) If status is false, result is an error message. Otherwise, result is
--        nil and the following elements are added to <code>smb</code>:
--      * 'security_mode'    Whether or not to use cleartext passwords, message signatures, etc.
--      * 'max_mpx'          Maximum number of multiplexed connections
--      * 'max_vc'           Maximum number of virtual circuits
--      * 'max_buffer'       Maximum buffer size
--      * 'max_raw_buffer'   Maximum buffer size for raw connections (considered obsolete)
--      * 'session_key'      A value that's basically just echoed back
--      * 'capabilities'     The server's capabilities
--      * 'time'             The server's time (in UNIX-style seconds since 1970)
--      * 'date'             The server's date in a user-readable format
--      * 'timezone'         The server's timezone, in hours from UTC
--      * 'timezone_str'     The server's timezone, as a string
--      * 'server_challenge' A random string used for challenge/response
--      * 'domain'           The server's primary domain
--      * 'server'           The server's name
function negotiate_protocol(smb)
	local header, parameters, data
	local pos
	local header1, header2, header3, ehader4, command, status, flags, flags2, pid_high, signature, unused, pid, mid
	local dialect, security_mode, max_mpx, max_vc, max_buffer, max_raw_buffer, session_key, capabilities, time, timezone, key_length
	local server_challenge, date, timezone_str
	local domain, server

	header     = smb_encode_header(smb, command_codes['SMB_COM_NEGOTIATE'])

	-- Parameters are blank
	parameters = ""

	-- Data is a list of strings, terminated by a blank one. 
	data       = bin.pack("<CzCz", 2, "NT LM 0.12", 2, "")

	-- Send the negotiate request
	stdnse.print_debug(2, "SMB: Sending SMB_COM_NEGOTIATE")
	result, err = smb_send(smb, header, parameters, data)
	if(status == false) then
		return false, err
	end

	-- Read the result
	status, header, parameters, data = smb_read(smb)
	if(status ~= true) then
		return false, header
	end

	-- Parse out the header
	pos, header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid = bin.unpack("<CCCCCICSSlSSSSS", header)

	-- Check if we fell off the packet (if that happened, the last parameter will be nil)
	if(mid == nil) then
		return false, "SMB: SMB server didn't comply with standards (incorrect data was returned) [7]"
	end

	-- Parse the parameter section
	pos, dialect = bin.unpack("<S", parameters)

	-- Check if we ran off the packet
	if(dialect == nil) then
		return false, "SMB: SMB server didn't comply with standards (incorrect data was returned) [8]"
	end
	-- Check if the server didn't like our requested protocol
	if(dialect ~= 0) then
		return false, string.format("Server negotiated an unknown protocol (#%d) -- aborting", dialect)
	end

	pos, security_mode, max_mpx, max_vc, max_buffer, max_raw_buffer, session_key, capabilities, time, timezone, key_length = bin.unpack("<CSSIIIILsC", parameters, pos)

	-- Some broken implementations of SMB don't send these variables
	if(time == nil) then
		time = 0
	end
	if(timezone == nil) then
		timezone = 0
	end
	if(key_length == nil) then
		key_length = 0
	end

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
	server = ""

	pos, ch, dummy = bin.unpack("<CC", data, pos)
	while ch ~= nil and ch ~= 0 do
		domain = domain .. string.char(ch)
		pos, ch, dummy = bin.unpack("<CC", data, pos)
	end

	-- Get the server name as a Unicode string
	pos, ch, dummy = bin.unpack("<CC", data, pos)
	while ch ~= nil and ch ~= 0 do
		server = server .. string.char(ch)
		pos, ch, dummy = bin.unpack("<CC", data, pos)
	end

	-- Fill out smb variables
	smb['security_mode']    = security_mode
	smb['max_mpx']          = max_mpx
	smb['max_vc']           = max_vc
	smb['max_buffer']       = max_buffer
	smb['max_raw_buffer']   = max_raw_buffer
	smb['session_key']      = session_key
	smb['capabilities']     = capabilities
	smb['time']             = time
	smb['date']             = date
	smb['timezone']         = timezone
	smb['timezone_str']     = timezone_str
	smb['server_challenge'] = server_challenge
	smb['domain']           = domain
	smb['server']           = server

	return true
end

---Determines which hash type is going to be used, based on the function parameters, the registry, and 
-- the nmap arguments (in that order).
--
--@param hash_type [optional] The function parameter version, which will override all others if set. 
--@return The highest priority hash type that's set.
local function get_hash_type(hash_type)
	
	if(hash_type ~= nil) then
		stdnse.print_debug(2, "SMB: Using logon type passed as a parameter: %s", hash_type)
	else
		if(nmap.registry.args.smbtype ~= nil) then
			hash_type = nmap.registry.args.smbtype
			stdnse.print_debug(2, "SMB: Using logon type passed as an nmap parameter: %s", hash_type)
		else
			hash_type = "ntlm"
			stdnse.print_debug(2, "SMB: Using default logon type: %s", hash_type)
		end
	end

	return string.lower(hash_type)
end


---Determines which username is going to be used, based on the function parameters, the registry, and 
-- the nmap arguments (in that order).
--
--@param username [optional] The function parameter version, which will override all others if set. 
--@return The highest priority username that's set.
-- TODO: Get username from the registry
local function get_username(username)

	if(username ~= nil) then
		stdnse.print_debug(2, "SMB: Using username passed as a parameter: %s", username)
	else
		if(nmap.registry.args.smbusername ~= nil) then
			username = nmap.registry.args.smbusername
			stdnse.print_debug(2, "SMB: Using username passed as an nmap parameter (smbusername): %s", username)
		elseif(nmap.registry.args.smbuser ~= nil) then
			username = nmap.registry.args.smbuser
			stdnse.print_debug(2, "SMB: Using username passed as an nmap parameter (smbuser): %s", username)
		else
			username = nil
			stdnse.print_debug(2, "SMB: Couldn't find a username to use, not logging in")
		end
	end

	return username
end

---Determines which domain is going to be used, based on the function parameters, the registry, and 
-- the nmap arguments (in that order).
--
--@param domain [optional] The function parameter version, which will override all others if set. 
--@return The highest priority domain that's set.
local function get_domain(domain)

	if(domain ~= nil) then
		stdnse.print_debug(2, "SMB: Using domain passed as a parameter: %s", domain)
	else
		if(nmap.registry.args.smbdomain ~= nil) then
			domain = nmap.registry.args.smbdomain
			stdnse.print_debug(2, "SMB: Using domain passed as an nmap parameter: %s", domain)
		else
			domain = ""
			stdnse.print_debug(2, "SMB: Couldn't find domain to use, using blank")
		end
	end

	return domain
end

---Generate the Lanman and NTLM password hashes. The password itself is taken from the function parameters,
-- the registry, and the nmap arguments (in that order). If no password is set, then the password hash
-- is used (which is read from all the usual places). If neither is set, then a blank password is used. 
--
-- The output passwords are hashed based on the hash type. 
--
--@param username The username, which is used for v2 passwords. 
--@param domain The username, which is used for v2 passwords. 
--@param password [optional] The overriding password. 
--@param password_hash [optional] The overriding password hash. Shouldn't be set if password is set. 
--@param challenge The server challenge.
--@param hash_type The way in which to hash the password. 
--@return (lm_response, ntlm_response) The two strings that can be sent directly back to the server. 
local function get_password_response(username, domain, password, password_hash, challenge, hash_type)

	local lm_hash   = nil
	local ntlm_hash = nil

	-- Check if there's a password set
	if(password ~= nil) then
		stdnse.print_debug(2, "SMB: Using password passed as a parameter")
	else
		if(nmap.registry.args.smbpassword ~= nil) then
			password = nmap.registry.args.smbpassword
			stdnse.print_debug(2, "SMB: Using password passed as an nmap parameter (smbpassword)")
		elseif(nmap.registry.args.smbpass ~= nil) then
			password = nmap.registry.args.smbpass
			stdnse.print_debug(2, "SMB: Using password passed as an nmap parameter (smbpass)")
		else
			password = nil
			stdnse.print_debug(2, "SMB: Couldn't find password to use, checking for a useable hash")
		end
	end

	-- If we got a password, hash it, otherwise, try getting a hash from the standard places
	if(password ~= nil) then
		-- Check if the password is blank; don't bother hashing a blank password
		if(password == "") then
			return "", ""
		end

		status, lm_hash   = lm_create_hash(password)
		status, ntlm_hash = ntlm_create_hash(password)
	else
		local hashes = nil

		if(nmap.registry.args.smbhash ~= nil) then
			hashes = nmap.registry.args.smbhash

			if(string.find(hashes, "^" .. string.rep("%x%x", 16) .. "$")) then
				stdnse.print_debug(2, "SMB: Found a 16-byte hex string")
				lm_hash   = bin.pack("H", hashes:sub(1, 32))
				ntlm_hash = bin.pack("H", hashes:sub(1, 32))
			elseif(string.find(hashes, "^" .. string.rep("%x%x", 32) .. "$")) then
				stdnse.print_debug(2, "SMB: Found a 32-byte hex string")
				lm_hash   = bin.pack("H", hashes:sub(1, 32))
				ntlm_hash = bin.pack("H", hashes:sub(33, 64))
			elseif(string.find(hashes, "^" .. string.rep("%x%x", 16) .. "." .. string.rep("%x%x", 16) .. "$")) then
				stdnse.print_debug(2, "SMB: Found two 16-byte hex strings")
				lm_hash   = bin.pack("H", hashes:sub(1, 32))
				ntlm_hash = bin.pack("H", hashes:sub(34, 65))
			else
				stdnse.print_debug(1, "SMB: ERROR: Hash(es) provided in an invalid format (should be 32, 64, or 65 hex characters)")
				lm_hash = nil
				ntlm_hash = nil
			end
		end
	end

	-- At this point, we should have a good lm_hash and ntlm_hash if we're getting one
	if(lm_hash == nil or ntlm_hash == nil) then
		stdnse.print_debug(2, "SMB: Couldn't determine which password to use, using a blank one")
		return "", ""
	end

	-- Output what we've got so far
	stdnse.print_debug(2, "SMB: Lanman hash: %s", stdnse.tohex(lm_hash))
	stdnse.print_debug(2, "SMB: NTLM   hash: %s", stdnse.tohex(ntlm_hash))
			
	-- Hash the password the way the user wants
	if(hash_type == "v1") then
		-- LM and NTLM are hashed with their respective algorithms
		stdnse.print_debug(2, "SMB: Creating v1 response")
		status, lm_response   = lm_create_response(lm_hash, challenge)
		status, ntlm_response = ntlm_create_response(ntlm_hash, challenge)
	elseif(hash_type == "lm") then
		-- LM is hashed with its algorithm, NTLM is blank
		stdnse.print_debug(2, "SMB: Creating LMv1 response")
		status, lm_response   = lm_create_response(lm_hash, challenge)
		        ntlm_response = ""
	elseif(hash_type == "ntlm") then
		-- LM and NTLM both use the NTLM algorithm
		stdnse.print_debug(2, "SMB: Creating NTLMv1 response")
		status, lm_response   = ntlm_create_response(ntlm_hash, challenge)
		status, ntlm_response = ntlm_create_response(ntlm_hash, challenge)
	elseif(hash_type == "v2") then
		-- LM and NTLM are hashed with their respective v2 algorithms
		stdnse.print_debug(2, "SMB: Creating v2 response")
		status, lm_response   = lmv2_create_response(ntlm_hash, username, domain, challenge)
		status, ntlm_response = ntlmv2_create_response(ntlm_hash, username, domain, challenge, 24)
	elseif(hash_type == "lmv2") then
		-- LM is hashed with its v2 algorithm, NTLM is blank
		stdnse.print_debug(2, "SMB: Creating LMv2 response")
		status, lm_response   = lmv2_create_response(ntlm_hash, username, domain, challenge)
		        ntlm_response = ""
	else
		-- Default to NTLMv1
		stdnse.print_debug(1, "SMB: Invalid login type specified, using default (NTLM)")
		status, lm_response   = ntlm_create_response(ntlm_hash, challenge)
		status, ntlm_response = ntlm_create_response(ntlm_hash, challenge)
	end

	stdnse.print_debug(2, "SMB: Lanman response: %s", stdnse.tohex(lm_response))
	stdnse.print_debug(2, "SMB: NTLM   response: %s", stdnse.tohex(ntlm_response))

	return lm_response, ntlm_response
end

---Retrieves an array of logins to use, based on the various sources that logins can come from. Only one 
-- username/password pair are used, since it's very easy to lock out accounts on SMB servers. The first place
-- checked is the parameters passed to this function -- if they're set, that's what's used. If not, the registry
-- is checked (to see if another script set a username/password). If that fails, Nmap's arguments are checked. 
-- If that fails, no username/password is returned. 
--
-- In addition to the username/password pair, the 'guest' account may be returned with a blank password, and
-- the anonymous account (blank username/password) is returned. 
--
--@param ip            The IP of the host, which is used to look up the password in the registry.
--@param challenge     The challenge string sent by the server. 
--@param username      [optional] The username to override with. 
--@param domain        [optional] The domain to override with. 
--@param password      [optional] The password to override with. 
--@param password_hash [optional] The password hash to override this (shouldn't be used along with password). 
--@param hash_type     [optional] The type of hash to override with. 
--@return An array of tables, each of which contain a 'username', 'domain', 'lanman', 'ntlm'. 
local function get_logins(ip, challenge, username, domain, password, password_hash, hash_type)

	local response = {}

	-- If we don't have OpenSSL, don't bother with any of this
	if(have_ssl == true) then
		-- We choose *one* username to try, here. First, see if the user set a username
		-- in the function parameters, then in the registry [TODO], then as an nmap 
		-- parameter, then disable it. 
	
		-- If a username was found, look for a domain and password
		username = get_username(username)
		domain   = get_domain(domain)
		hash_type = get_hash_type(hash_type)

		if(username ~= nil) then
			lm_response, ntlm_response = get_password_response(username, domain, password, password_hash, challenge, hash_type)

			if(lm_response ~= nil and ntlm_response ~= nil) then
				local data = {}
				data['username'] = username
				data['domain']   = domain
				data['lanman']   = lm_response
				data['ntlm']     = ntlm_response
				response[#response + 1] = data
			end

			if(lm_response == nil) then
				lm_response = ""
			end
			if(ntlm_response == nil) then
				ntlm_response = ""
			end

		end
	else
		stdnse.print_debug(1, "SMB: ERROR: Couldn't find OpenSSL library, only checking Guest and/or Anonymous accounts")
	end

	local data
	-- Add guest account
	stdnse.print_debug(2, "SMB: Going to try guest account before attempting anonymous")

	data = {}
	data['username'] = 'guest'
	data['domain'] = ''
	data['lanman'] = ''
	data['ntlm'] = ''
	response[#response + 1] = data

	-- Add the anonymous account
	data = {}
	data['username'] = ''
	data['domain'] = ''
	data['lanman'] = ''
	data['ntlm'] = ''
	response[#response + 1] = data

	return response
end

--- Sends out SMB_COM_SESSION_SETUP_ANDX, which attempts to log a user in. 
-- Sends the following:
-- * Negotiated parameters (multiplexed connections, virtual circuit, capabilities)
-- * Passwords (plaintext, unicode, lanman, ntlm, lmv2, ntlmv2, etc)
-- * Account name
-- * OS (I just send "Nmap")
-- * Native LAN Manager (no clue what that is, but it seems to be ignored)
--
-- Receives the following:
-- * User ID
-- * Server OS
--
--@param smb          The SMB object associated with the connection
--@param username     [optional] Overrides the account name to use. Will use Nmap parameters or registry by 
--                    default, or NULL session if it isn't set anywhere
--@param domain       [optional] Overrides the domain to use. 
--@param password     [optional] Overrides the password to use. Will use Nmap parameters or registry by default.
--@param hash_type    [optional] Overrides the hash type to use (can be v1, LM, NTLM, LMv2, v2). Default is 'NTLM'.
--@return (status, result) If status is false, result is an error message. Otherwise, result is nil and the following
--        elements are added to the smb table:
--    *  'uid'         The UserID for the session
--    *  'is_guest'    If set, the username wasn't found so the user was automatically logged in as the guest account
--    *  'os'          The operating system
--    *  'lanmanager'  The servers's LAN Manager
function start_session(smb, username, domain, password, password_hash, hash_type)
	local i
	local status, result
	local header, parameters, data
	local pos
	local header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid 
	local andx_command, andx_reserved, andx_offset, action
	local os, lanmanager, domain
	local logins = get_logins(smb['ip'], smb['server_challenge'], username, domain, password, password_hash, hash_type)

	header     = smb_encode_header(smb, command_codes['SMB_COM_SESSION_SETUP_ANDX'])

	-- Loop through the credentials returned by get_logins() (there should be 2 or 3)
	for i = 1, #logins, 1 do
		-- Parameters
		parameters = bin.pack("<CCSSSSISSII", 
					0xFF,               -- ANDX -- no further commands
					0x00,               -- ANDX -- Reserved (0)
					0x0000,             -- ANDX -- next offset
					0x1000,             -- Max buffer size
					0x0001,             -- Max multiplexes
					0x0000,             -- Virtual circuit num
					smb['session_key'], -- The session key
					#logins[i]['lanman'], -- ANSI/Lanman password length
					#logins[i]['ntlm'],   -- Unicode/NTLM password length
					0,                  -- Reserved
	                0x00000050          -- Capabilities
				)
	
		-- Data is a list of strings, terminated by a blank one. 
		data       = bin.pack("<AAzzzz", 
					logins[i]['lanman'],   -- ANSI/Lanman password
					logins[i]['ntlm'],     -- Unicode/NTLM password
					logins[i]['username'], -- Account
					logins[i]['domain'],   -- Domain
					"Nmap",                -- OS
					"Native Lanman"        -- Native LAN Manager
				)
		-- Send the session setup request
		stdnse.print_debug(2, "SMB: Sending SMB_COM_SESSION_SETUP_ANDX")
		result, err = smb_send(smb, header, parameters, data)
		if(result == false) then
			return false, err
		end
	
		-- Read the result
		status, header, parameters, data = smb_read(smb)
		if(status ~= true) then
			return false, header
		end
	
		-- Check if we were allowed in
		pos, header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid = bin.unpack("<CCCCCICSSlSSSSS", header)

		if(mid == nil) then
			return false, "SMB: SMB server didn't comply with standards (incorrect data was returned) [9]"
		end

		-- Check if we're successful
		if(status == 0) then

			-- Parse the parameters
			pos, andx_command, andx_reserved, andx_offset, action = bin.unpack("<CCSS", parameters)
			if(action == nil) then
				return false, "SMB: SMB server didn't comply with standards (incorrect data was returned) [10]"
			end

			-- Parse the data
			pos, os, lanmanager, domain = bin.unpack("<zzz", data)
		
			-- Fill in the smb object and smb string
			smb['uid']        = uid
			smb['is_guest']   = bit.band(action, 1)
			smb['os']         = os
			smb['lanmanager'] = lanmanager

			-- Check if they're using an un-supported system [TODO: once I sort this out, remove the warning]
			if(os == nil or lanmanager == nil or domain == nil) then
				stdnse.print_debug(1, "SMB: WARNING: the server is using a non-standard SMB implementation; your mileage may vary (%s)", smb['ip'])
			elseif(os == "Unix" or string.sub(lanmanager, 1, 5) == "Samba") then
				stdnse.print_debug(1, "SMB: WARNING: the server appears to be Unix; your mileage may vary.")
			end

			-- Check if they were logged in as a guest
			if(smb['is_guest'] == 1) then
				stdnse.print_debug(1, "SMB: Login as %s\\%s failed, but was given guest access (username may be wrong, or system may only allow guest)", logins[i]['domain'], string_or_blank(logins[i]['username']))
			else
				stdnse.print_debug(1, "SMB: Login as %s\\%s succeeded", logins[i]['domain'], string_or_blank(logins[i]['username']))
			end
		
			return true

		else
			-- This username failed, print a warning and keep going
			stdnse.print_debug(1, "SMB: Login as %s\\%s failed (%s), trying next login", logins[i]['domain'], string_or_blank(logins[i]['username']), get_status_name(status))
		end
	end

	stdnse.print_debug(1, "SMB: ERROR: All logins failed, sorry it didn't work out!")
	return false, get_status_name(status)

end
 
--- Sends out SMB_COM_SESSION_TREE_CONNECT_ANDX, which attempts to connect to a share. 
-- Sends the following:
-- * Password (for share-level security, which we don't support)
-- * Share name
-- * Share type (or "?????" if it's unknown, that's what we do)
--
-- Receives the following:
-- * Tree ID
--
--@param smb    The SMB object associated with the connection
--@param path   The path to connect (eg, "\\servername\C$")
--@return (status, result) If status is false, result is an error message. Otherwise, result is a 
--        table with the following elements:
--      * 'tid'         The TreeID for the session
function tree_connect(smb, path)
	local header, parameters, data
	local pos
	local header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, pid, mid 
	local andx_command, andx_reserved, andx_offset, action

	header = smb_encode_header(smb, command_codes['SMB_COM_TREE_CONNECT_ANDX'])
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
	stdnse.print_debug(2, "SMB: Sending SMB_COM_TREE_CONNECT_ANDX")
	result, err = smb_send(smb, header, parameters, data)
	if(result == false) then
		return false, err
	end

	-- Read the result
	status, header, parameters, data = smb_read(smb)
	if(status ~= true) then
		return false, header
	end

	-- Check if we were allowed in
	pos, header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid = bin.unpack("<CCCCCICSSlSSSSS", header)
	if(mid == nil) then
		return false, "SMB: SMB server didn't comply with standards (incorrect data was returned) [11]"
	end

	if(status ~= 0) then
		return false, get_status_name(status)
	end

	smb['tid'] = tid

	return true
	
end

--- Disconnects a tree session. Should be called before logging off and disconnecting. 
--@param smb    The SMB object associated with the connection
--@return (status, result) If status is false, result is an error message. If status is true, 
--              the disconnect was successful. 
function tree_disconnect(smb)
	local header
	local header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, pid, mid 

	header = smb_encode_header(smb, command_codes['SMB_COM_TREE_DISCONNECT'])

	-- Send the tree disconnect request
	stdnse.print_debug(2, "SMB: Sending SMB_COM_TREE_DISCONNECT")
	result, err = smb_send(smb, header, "", "")
	if(result == false) then
		return false, err
	end

	-- Read the result
	status, header, parameters, data = smb_read(smb)
	if(status ~= true) then
		return false, header
	end

	-- Check if there was an error
	pos, header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid = bin.unpack("<CCCCCICSSlSSSSS", header)
	if(mid == nil) then
		return false, "SMB: SMB server didn't comply with standards (incorrect data was returned) [12]"
	end
	if(status ~= 0) then
		return false, get_status_name(status)
	end

	smb['tid'] = 0

	return true
	
end

---Logs off the current user. Strictly speaking this isn't necessary, but it's the polite thing to do. 
--
--@param smb    The SMB object associated with the connection
--@return (status, result) If statis is false, result is an error message. If status is true, 
--              the logoff was successful. 
function logoff(smb)
	local header, parameters
	local header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, pid, mid 

	header = smb_encode_header(smb, command_codes['SMB_COM_LOGOFF_ANDX'])

	-- Parameters are a blank ANDX block
	parameters = bin.pack("<CCS", 
					0xFF,   -- ANDX no further commands
					0x00,   -- ANDX reserved
					0x0000  -- ANDX offset
	             )

	-- Send the tree disconnect request
	stdnse.print_debug(2, "SMB: Sending SMB_COM_LOGOFF_ANDX")
	result, err = smb_send(smb, header, parameters, "")
	if(result == false) then
		return false, err
	end

	-- Read the result
	status, header, parameters, data = smb_read(smb)
	if(status ~= true) then
		return false, header
	end

	-- Check if there was an error
	pos, header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid = bin.unpack("<CCCCCICSSlSSSSS", header)
	if(mid == nil) then
		return false, "SMB: SMB server didn't comply with standards (incorrect data was returned) [13]"
	end
	if(status ~= 0) then
		return false, get_status_name(status)
	end

	smb['uid'] = 0

	return true
	
end

--- This sends a SMB request to open or create a file. 
--  Most of the parameters I pass here are used directly from a packetlog, especially the various permissions fields and flags. 
--  I might make this more adjustable in the future, but this has been working for me. 
--
--@param smb    The SMB object associated with the connection
--@param path   The path of the file or pipe to open
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table
--        containing a lot of different elements, the most important one being 'fid', the handle to the opened file. 
function create_file(smb, path)
	local header, parameters, data
	local pos
	local header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, pid, mid 
	local andx_command, andx_reserved, andx_offset
	local oplock_level, fid, create_action, created, last_access, last_write, last_change, attributes, allocation_size, end_of_file, filetype, ipc_state, is_directory

	header = smb_encode_header(smb, command_codes['SMB_COM_NT_CREATE_ANDX'])
	parameters = bin.pack("<CCSCSIIILIIIIIC", 
					0xFF,   -- ANDX no further commands
					0x00,   -- ANDX reserved
					0x0000, -- ANDX offset
					0x00,   -- Reserved
					string.len(path), -- Path length
					0x00000016,       -- Create flags
					0x00000000,       -- Root FID
					0x0002019F,       -- Access mask
					0x0000000000000000, -- Allocation size
					0x00000000,         -- File attributes
					0x00000003,         -- Share attributes
					0x00000001,         -- Disposition
					0x00400040,         -- Create options
					0x00000002,         -- Impersonation
					0x01                -- Security flags
				)

	data = bin.pack("z", path)

	-- Send the create file
	stdnse.print_debug(2, "SMB: Sending SMB_COM_NT_CREATE_ANDX")
	result, err = smb_send(smb, header, parameters, data)
	if(result == false) then
		return false, err
	end

	-- Read the result
	status, header, parameters, data = smb_read(smb)
	if(status ~= true) then
		return false, header
	end

	-- Check if we were allowed in
	pos, header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid = bin.unpack("<CCCCCICSSlSSSSS", header)
	if(mid == nil) then
		return false, "SMB: SMB server didn't comply with standards (incorrect data was returned) [14]"
	end
	if(status ~= 0) then
		return false, get_status_name(status)
	end

	-- Parse the parameters
	pos, andx_command, andx_reserved, andx_offset, oplock_level, fid, create_action, created, last_access, last_write, last_change, attributes, allocation_size, end_of_file, filetype, ipc_state, is_directory = bin.unpack("<CCSCSILLLLILLSSC", parameters)
	if(is_directory == nil) then
		return false, "SMB: SMB server didn't comply with standards (incorrect data was returned) [15]"
	end

	-- Fill in the smb string
	smb['oplock_level']    = oplock_level
	smb['fid']             = fid
	smb['create_action']   = create_action
	smb['created']         = created
	smb['last_access']     = last_access
	smb['last_write']      = last_write
	smb['last_change']     = last_change
	smb['attributes']      = attributes
	smb['allocation_size'] = allocation_size
	smb['end_of_file']     = end_of_file
	smb['filetype']        = filetype
	smb['ipc_state']       = ipc_state
	smb['is_directory']    = is_directory
	
	return true
	
end

---This is the core of making MSRPC calls. It sends out a MSRPC packet with the given parameters and data. 
-- Don't confuse these parameters and data with SMB's concepts of parameters and data -- they are completely
-- different. In fact, these parameters and data are both sent in the SMB packet's 'data' section.
--
-- It is probably best to think of this as another protocol layer. This function will wrap SMB stuff around a 
-- MSRPC call, make the call, then unwrap the SMB stuff from it before returning. 
--
--@param smb    The SMB object associated with the connection
--@param func   The function to call. The only one I've tested is 0x26, named pipes. 
--@param function_parameters The parameter data to pass to the function. This is untested, since none of the
--       transactions I've done have required parameters. 
--@param function_data   The data to send with the packet. This is basically the next protocol layer
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table 
--        containing 'parameters' and 'data', representing the parameters and data returned by the server. 
function send_transaction(smb, func, function_parameters, function_data)
	local header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, pid, mid 
	local header, parameters, data
	local parameters_offset, data_offset
	local total_word_count, total_data_count, reserved1, parameter_count, parameter_offset, parameter_displacement, data_count, data_offset, data_displacement, setup_count, reserved2
	local response = {}

	-- Header is 0x20 bytes long (not counting NetBIOS header).
	header = smb_encode_header(smb, command_codes['SMB_COM_TRANSACTION']) -- 0x25 = SMB_COM_TRANSACTION

	-- 0x20 for SMB header, 0x01 for parameters header, 0x20 for parameters length, 0x02 for data header, 0x07 for "\PIPE\"
	parameters_offset = 0x20 + 0x01 + 0x20 + 0x02 + 0x07
	data_offset       = 0x20 + 0x01 + 0x20 + 0x02 + 0x07 + string.len(function_parameters)

	-- Parameters are 0x20 bytes long. 
	parameters = bin.pack("<SSSSCCSISSSSSCCSS",
					string.len(function_parameters), -- Total parameter count. 
					string.len(function_data),       -- Total data count. 
					0x000,                           -- Max parameter count.
					0x400,                           -- Max data count.
					0x00,                            -- Max setup count.
					0x00,                            -- Reserved.
					0x0000,                          -- Flags (0x0000 = 2-way transaction, don't disconnect TIDs).
					0x00000000,                      -- Timeout (0x00000000 = return immediately).
					0x0000,                          -- Reserved.
					string.len(function_parameters), -- Parameter bytes.
					parameters_offset,               -- Parameter offset.
					string.len(function_data),       -- Data bytes.
					data_offset,                     -- Data offset.
					0x02,                            -- Number of 'setup' words (only ever seen '2').
					0x00,                            -- Reserved.
					func,                            -- Function to call.
					smb['fid']                       -- Handle to open file
				)

	-- \PIPE\ is 0x07 bytes long. 
	data = bin.pack("<z", "\\PIPE\\");
	data = data .. function_parameters;
	data = data .. function_data

	-- Send the transaction request
	stdnse.print_debug(2, "SMB: Sending SMB_COM_TRANSACTION")
	result, err = smb_send(smb, header, parameters, data)
	if(result == false) then
		return false, err
	end

	-- Read the result
	status, header, parameters, data = smb_read(smb)
	if(status ~= true) then
		return false, header
	end

	-- Check if it worked
	pos, header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid = bin.unpack("<CCCCCICSSlSSSSS", header)
	if(mid == nil) then
		return false, "SMB: SMB server didn't comply with standards (incorrect data was returned) [16]"
	end
	if(status ~= 0) then
		if(status_names[status] == nil) then
			return false, string.format("Unknown SMB error: 0x%08x\n", status)
		else
			return false, status_names[status]
		end
	end

	-- Parse the parameters
	pos, total_word_count, total_data_count, reserved1, parameter_count, parameter_offset, parameter_displacement, data_count, data_offset, data_displacement, setup_count, reserved2 = bin.unpack("<SSSSSSSSSCC", parameters)
	if(reserved2 == nil) then
		return false, "SMB: SMB server didn't comply with standards (incorrect data was returned) [17]"
	end

	-- Convert the parameter/data offsets into something more useful (the offset into the data section)
	-- - 0x20 for the header, - 0x01 for the length. 
	parameter_offset = parameter_offset - 0x20 - 0x01 - string.len(parameters) - 0x02;
	-- - 0x20 for the header, - 0x01 for parameter length, the parameter length, and - 0x02 for the data length. 
	data_offset = data_offset - 0x20 - 0x01 - string.len(parameters) - 0x02;

	-- I'm not sure I entirely understand why the '+1' is here, but I think it has to do with the string starting at '1' and not '0'.
	function_parameters = string.sub(data, parameter_offset + 1, parameter_offset + parameter_count)
	function_data       = string.sub(data, data_offset      + 1, data_offset      + data_count)

	response['parameters'] = function_parameters
	response['data']       = function_data

	return true, response
end





command_codes = 
{
	SMB_COM_CREATE_DIRECTORY          = 0x00,
	SMB_COM_DELETE_DIRECTORY          = 0x01,
	SMB_COM_OPEN                      = 0x02,
	SMB_COM_CREATE                    = 0x03,
	SMB_COM_CLOSE                     = 0x04,
	SMB_COM_FLUSH                     = 0x05,
	SMB_COM_DELETE                    = 0x06,
	SMB_COM_RENAME                    = 0x07,
	SMB_COM_QUERY_INFORMATION         = 0x08,
	SMB_COM_SET_INFORMATION           = 0x09,
	SMB_COM_READ                      = 0x0A,
	SMB_COM_WRITE                     = 0x0B,
	SMB_COM_LOCK_BYTE_RANGE           = 0x0C,
	SMB_COM_UNLOCK_BYTE_RANGE         = 0x0D,
	SMB_COM_CREATE_TEMPORARY          = 0x0E,
	SMB_COM_CREATE_NEW                = 0x0F,
	SMB_COM_CHECK_DIRECTORY           = 0x10,
	SMB_COM_PROCESS_EXIT              = 0x11,
	SMB_COM_SEEK                      = 0x12,
	SMB_COM_LOCK_AND_READ             = 0x13,
	SMB_COM_WRITE_AND_UNLOCK          = 0x14,
	SMB_COM_READ_RAW                  = 0x1A,
	SMB_COM_READ_MPX                  = 0x1B,
	SMB_COM_READ_MPX_SECONDARY        = 0x1C,
	SMB_COM_WRITE_RAW                 = 0x1D,
	SMB_COM_WRITE_MPX                 = 0x1E,
	SMB_COM_WRITE_MPX_SECONDARY       = 0x1F,
	SMB_COM_WRITE_COMPLETE            = 0x20,
	SMB_COM_QUERY_SERVER              = 0x21,
	SMB_COM_SET_INFORMATION2          = 0x22,
	SMB_COM_QUERY_INFORMATION2        = 0x23,
	SMB_COM_LOCKING_ANDX              = 0x24,
	SMB_COM_TRANSACTION               = 0x25,
	SMB_COM_TRANSACTION_SECONDARY     = 0x26,
	SMB_COM_IOCTL                     = 0x27,
	SMB_COM_IOCTL_SECONDARY           = 0x28,
	SMB_COM_COPY                      = 0x29,
	SMB_COM_MOVE                      = 0x2A,
	SMB_COM_ECHO                      = 0x2B,
	SMB_COM_WRITE_AND_CLOSE           = 0x2C,
	SMB_COM_OPEN_ANDX                 = 0x2D,
	SMB_COM_READ_ANDX                 = 0x2E,
	SMB_COM_WRITE_ANDX                = 0x2F,
	SMB_COM_NEW_FILE_SIZE             = 0x30,
	SMB_COM_CLOSE_AND_TREE_DISC       = 0x31,
	SMB_COM_TRANSACTION2              = 0x32,
	SMB_COM_TRANSACTION2_SECONDARY    = 0x33,
	SMB_COM_FIND_CLOSE2               = 0x34,
	SMB_COM_FIND_NOTIFY_CLOSE         = 0x35,
	SMB_COM_TREE_CONNECT              = 0x70,
	SMB_COM_TREE_DISCONNECT           = 0x71,
	SMB_COM_NEGOTIATE                 = 0x72,
	SMB_COM_SESSION_SETUP_ANDX        = 0x73,
	SMB_COM_LOGOFF_ANDX               = 0x74,
	SMB_COM_TREE_CONNECT_ANDX         = 0x75,
	SMB_COM_QUERY_INFORMATION_DISK    = 0x80,
	SMB_COM_SEARCH                    = 0x81,
	SMB_COM_FIND                      = 0x82,
	SMB_COM_FIND_UNIQUE               = 0x83,
	SMB_COM_FIND_CLOSE                = 0x84,
	SMB_COM_NT_TRANSACT               = 0xA0,
	SMB_COM_NT_TRANSACT_SECONDARY     = 0xA1,
	SMB_COM_NT_CREATE_ANDX            = 0xA2,
	SMB_COM_NT_CANCEL                 = 0xA4,
	SMB_COM_NT_RENAME                 = 0xA5,
	SMB_COM_OPEN_PRINT_FILE           = 0xC0,
	SMB_COM_WRITE_PRINT_FILE          = 0xC1,
	SMB_COM_CLOSE_PRINT_FILE          = 0xC2,
	SMB_COM_GET_PRINT_QUEUE           = 0xC3,
	SMB_COM_READ_BULK                 = 0xD8,
	SMB_COM_WRITE_BULK                = 0xD9,
	SMB_COM_WRITE_BULK_DATA           = 0xDA,
	SMB_NO_FURTHER_COMMANDS           = 0xFF
}

for i, v in pairs(command_codes) do
	command_names[v] = i
end



status_codes = 
{
	NT_STATUS_OK = 0x0000,
	NT_STATUS_WERR_BADFILE           = 0x00000002,
	NT_STATUS_WERR_ACCESS_DENIED     = 0x00000005,
	NT_STATUS_WERR_INVALID_NAME      = 0x0000007b,
	NT_STATUS_WERR_UNKNOWN_LEVEL     = 0x0000007c,
	NT_STATUS_NO_MORE_ITEMS          = 0x00000103,
	NT_STATUS_MORE_ENTRIES           = 0x00000105,
	NT_STATUS_SOME_NOT_MAPPED        = 0x00000107,
	DOS_STATUS_UNKNOWN_ERROR         = 0x00010001,
	DOS_STATUS_UNKNOWN_ERROR_2       = 0x00010002,
	DOS_STATUS_DIRECTORY_NOT_FOUND   = 0x00030001,
	DOS_STATUS_ACCESS_DENIED         = 0x00050001,
	DOS_STATUS_INVALID_FID           = 0x00060001,
	DOS_STATUS_INVALID_NETWORK_NAME  = 0x00060002,
	NT_STATUS_BUFFER_OVERFLOW = 0x80000005,
	NT_STATUS_UNSUCCESSFUL = 0xc0000001,
	NT_STATUS_NOT_IMPLEMENTED = 0xc0000002,
	NT_STATUS_INVALID_INFO_CLASS = 0xc0000003,
	NT_STATUS_INFO_LENGTH_MISMATCH = 0xc0000004,
	NT_STATUS_ACCESS_VIOLATION = 0xc0000005,
	NT_STATUS_IN_PAGE_ERROR = 0xc0000006,
	NT_STATUS_PAGEFILE_QUOTA = 0xc0000007,
	NT_STATUS_INVALID_HANDLE = 0xc0000008,
	NT_STATUS_BAD_INITIAL_STACK = 0xc0000009,
	NT_STATUS_BAD_INITIAL_PC = 0xc000000a,
	NT_STATUS_INVALID_CID = 0xc000000b,
	NT_STATUS_TIMER_NOT_CANCELED = 0xc000000c,
	NT_STATUS_INVALID_PARAMETER = 0xc000000d,
	NT_STATUS_NO_SUCH_DEVICE = 0xc000000e,
	NT_STATUS_NO_SUCH_FILE = 0xc000000f,
	NT_STATUS_INVALID_DEVICE_REQUEST = 0xc0000010,
	NT_STATUS_END_OF_FILE = 0xc0000011,
	NT_STATUS_WRONG_VOLUME = 0xc0000012,
	NT_STATUS_NO_MEDIA_IN_DEVICE = 0xc0000013,
	NT_STATUS_UNRECOGNIZED_MEDIA = 0xc0000014,
	NT_STATUS_NONEXISTENT_SECTOR = 0xc0000015,
	NT_STATUS_MORE_PROCESSING_REQUIRED = 0xc0000016,
	NT_STATUS_NO_MEMORY = 0xc0000017,
	NT_STATUS_CONFLICTING_ADDRESSES = 0xc0000018,
	NT_STATUS_NOT_MAPPED_VIEW = 0xc0000019,
	NT_STATUS_UNABLE_TO_FREE_VM = 0xc000001a,
	NT_STATUS_UNABLE_TO_DELETE_SECTION = 0xc000001b,
	NT_STATUS_INVALID_SYSTEM_SERVICE = 0xc000001c,
	NT_STATUS_ILLEGAL_INSTRUCTION = 0xc000001d,
	NT_STATUS_INVALID_LOCK_SEQUENCE = 0xc000001e,
	NT_STATUS_INVALID_VIEW_SIZE = 0xc000001f,
	NT_STATUS_INVALID_FILE_FOR_SECTION = 0xc0000020,
	NT_STATUS_ALREADY_COMMITTED = 0xc0000021,
	NT_STATUS_ACCESS_DENIED = 0xc0000022,
	NT_STATUS_BUFFER_TOO_SMALL = 0xc0000023,
	NT_STATUS_OBJECT_TYPE_MISMATCH = 0xc0000024,
	NT_STATUS_NONCONTINUABLE_EXCEPTION = 0xc0000025,
	NT_STATUS_INVALID_DISPOSITION = 0xc0000026,
	NT_STATUS_UNWIND = 0xc0000027,
	NT_STATUS_BAD_STACK = 0xc0000028,
	NT_STATUS_INVALID_UNWIND_TARGET = 0xc0000029,
	NT_STATUS_NOT_LOCKED = 0xc000002a,
	NT_STATUS_PARITY_ERROR = 0xc000002b,
	NT_STATUS_UNABLE_TO_DECOMMIT_VM = 0xc000002c,
	NT_STATUS_NOT_COMMITTED = 0xc000002d,
	NT_STATUS_INVALID_PORT_ATTRIBUTES = 0xc000002e,
	NT_STATUS_PORT_MESSAGE_TOO_LONG = 0xc000002f,
	NT_STATUS_INVALID_PARAMETER_MIX = 0xc0000030,
	NT_STATUS_INVALID_QUOTA_LOWER = 0xc0000031,
	NT_STATUS_DISK_CORRUPT_ERROR = 0xc0000032,
	NT_STATUS_OBJECT_NAME_INVALID = 0xc0000033,
	NT_STATUS_OBJECT_NAME_NOT_FOUND = 0xc0000034,
	NT_STATUS_OBJECT_NAME_COLLISION = 0xc0000035,
	NT_STATUS_HANDLE_NOT_WAITABLE = 0xc0000036,
	NT_STATUS_PORT_DISCONNECTED = 0xc0000037,
	NT_STATUS_DEVICE_ALREADY_ATTACHED = 0xc0000038,
	NT_STATUS_OBJECT_PATH_INVALID = 0xc0000039,
	NT_STATUS_OBJECT_PATH_NOT_FOUND = 0xc000003a,
	NT_STATUS_OBJECT_PATH_SYNTAX_BAD = 0xc000003b,
	NT_STATUS_DATA_OVERRUN = 0xc000003c,
	NT_STATUS_DATA_LATE_ERROR = 0xc000003d,
	NT_STATUS_DATA_ERROR = 0xc000003e,
	NT_STATUS_CRC_ERROR = 0xc000003f,
	NT_STATUS_SECTION_TOO_BIG = 0xc0000040,
	NT_STATUS_PORT_CONNECTION_REFUSED = 0xc0000041,
	NT_STATUS_INVALID_PORT_HANDLE = 0xc0000042,
	NT_STATUS_SHARING_VIOLATION = 0xc0000043,
	NT_STATUS_QUOTA_EXCEEDED = 0xc0000044,
	NT_STATUS_INVALID_PAGE_PROTECTION = 0xc0000045,
	NT_STATUS_MUTANT_NOT_OWNED = 0xc0000046,
	NT_STATUS_SEMAPHORE_LIMIT_EXCEEDED = 0xc0000047,
	NT_STATUS_PORT_ALREADY_SET = 0xc0000048,
	NT_STATUS_SECTION_NOT_IMAGE = 0xc0000049,
	NT_STATUS_SUSPEND_COUNT_EXCEEDED = 0xc000004a,
	NT_STATUS_THREAD_IS_TERMINATING = 0xc000004b,
	NT_STATUS_BAD_WORKING_SET_LIMIT = 0xc000004c,
	NT_STATUS_INCOMPATIBLE_FILE_MAP = 0xc000004d,
	NT_STATUS_SECTION_PROTECTION = 0xc000004e,
	NT_STATUS_EAS_NOT_SUPPORTED = 0xc000004f,
	NT_STATUS_EA_TOO_LARGE = 0xc0000050,
	NT_STATUS_NONEXISTENT_EA_ENTRY = 0xc0000051,
	NT_STATUS_NO_EAS_ON_FILE = 0xc0000052,
	NT_STATUS_EA_CORRUPT_ERROR = 0xc0000053,
	NT_STATUS_FILE_LOCK_CONFLICT = 0xc0000054,
	NT_STATUS_LOCK_NOT_GRANTED = 0xc0000055,
	NT_STATUS_DELETE_PENDING = 0xc0000056,
	NT_STATUS_CTL_FILE_NOT_SUPPORTED = 0xc0000057,
	NT_STATUS_UNKNOWN_REVISION = 0xc0000058,
	NT_STATUS_REVISION_MISMATCH = 0xc0000059,
	NT_STATUS_INVALID_OWNER = 0xc000005a,
	NT_STATUS_INVALID_PRIMARY_GROUP = 0xc000005b,
	NT_STATUS_NO_IMPERSONATION_TOKEN = 0xc000005c,
	NT_STATUS_CANT_DISABLE_MANDATORY = 0xc000005d,
	NT_STATUS_NO_LOGON_SERVERS = 0xc000005e,
	NT_STATUS_NO_SUCH_LOGON_SESSION = 0xc000005f,
	NT_STATUS_NO_SUCH_PRIVILEGE = 0xc0000060,
	NT_STATUS_PRIVILEGE_NOT_HELD = 0xc0000061,
	NT_STATUS_INVALID_ACCOUNT_NAME = 0xc0000062,
	NT_STATUS_USER_EXISTS = 0xc0000063,
	NT_STATUS_NO_SUCH_USER = 0xc0000064,
	NT_STATUS_GROUP_EXISTS = 0xc0000065,
	NT_STATUS_NO_SUCH_GROUP = 0xc0000066,
	NT_STATUS_MEMBER_IN_GROUP = 0xc0000067,
	NT_STATUS_MEMBER_NOT_IN_GROUP = 0xc0000068,
	NT_STATUS_LAST_ADMIN = 0xc0000069,
	NT_STATUS_WRONG_PASSWORD = 0xc000006a,
	NT_STATUS_ILL_FORMED_PASSWORD = 0xc000006b,
	NT_STATUS_PASSWORD_RESTRICTION = 0xc000006c,
	NT_STATUS_LOGON_FAILURE = 0xc000006d,
	NT_STATUS_ACCOUNT_RESTRICTION = 0xc000006e,
	NT_STATUS_INVALID_LOGON_HOURS = 0xc000006f,
	NT_STATUS_INVALID_WORKSTATION = 0xc0000070,
	NT_STATUS_PASSWORD_EXPIRED = 0xc0000071,
	NT_STATUS_ACCOUNT_DISABLED = 0xc0000072,
	NT_STATUS_NONE_MAPPED = 0xc0000073,
	NT_STATUS_TOO_MANY_LUIDS_REQUESTED = 0xc0000074,
	NT_STATUS_LUIDS_EXHAUSTED = 0xc0000075,
	NT_STATUS_INVALID_SUB_AUTHORITY = 0xc0000076,
	NT_STATUS_INVALID_ACL = 0xc0000077,
	NT_STATUS_INVALID_SID = 0xc0000078,
	NT_STATUS_INVALID_SECURITY_DESCR = 0xc0000079,
	NT_STATUS_PROCEDURE_NOT_FOUND = 0xc000007a,
	NT_STATUS_INVALID_IMAGE_FORMAT = 0xc000007b,
	NT_STATUS_NO_TOKEN = 0xc000007c,
	NT_STATUS_BAD_INHERITANCE_ACL = 0xc000007d,
	NT_STATUS_RANGE_NOT_LOCKED = 0xc000007e,
	NT_STATUS_DISK_FULL = 0xc000007f,
	NT_STATUS_SERVER_DISABLED = 0xc0000080,
	NT_STATUS_SERVER_NOT_DISABLED = 0xc0000081,
	NT_STATUS_TOO_MANY_GUIDS_REQUESTED = 0xc0000082,
	NT_STATUS_GUIDS_EXHAUSTED = 0xc0000083,
	NT_STATUS_INVALID_ID_AUTHORITY = 0xc0000084,
	NT_STATUS_AGENTS_EXHAUSTED = 0xc0000085,
	NT_STATUS_INVALID_VOLUME_LABEL = 0xc0000086,
	NT_STATUS_SECTION_NOT_EXTENDED = 0xc0000087,
	NT_STATUS_NOT_MAPPED_DATA = 0xc0000088,
	NT_STATUS_RESOURCE_DATA_NOT_FOUND = 0xc0000089,
	NT_STATUS_RESOURCE_TYPE_NOT_FOUND = 0xc000008a,
	NT_STATUS_RESOURCE_NAME_NOT_FOUND = 0xc000008b,
	NT_STATUS_ARRAY_BOUNDS_EXCEEDED = 0xc000008c,
	NT_STATUS_FLOAT_DENORMAL_OPERAND = 0xc000008d,
	NT_STATUS_FLOAT_DIVIDE_BY_ZERO = 0xc000008e,
	NT_STATUS_FLOAT_INEXACT_RESULT = 0xc000008f,
	NT_STATUS_FLOAT_INVALID_OPERATION = 0xc0000090,
	NT_STATUS_FLOAT_OVERFLOW = 0xc0000091,
	NT_STATUS_FLOAT_STACK_CHECK = 0xc0000092,
	NT_STATUS_FLOAT_UNDERFLOW = 0xc0000093,
	NT_STATUS_INTEGER_DIVIDE_BY_ZERO = 0xc0000094,
	NT_STATUS_INTEGER_OVERFLOW = 0xc0000095,
	NT_STATUS_PRIVILEGED_INSTRUCTION = 0xc0000096,
	NT_STATUS_TOO_MANY_PAGING_FILES = 0xc0000097,
	NT_STATUS_FILE_INVALID = 0xc0000098,
	NT_STATUS_ALLOTTED_SPACE_EXCEEDED = 0xc0000099,
	NT_STATUS_INSUFFICIENT_RESOURCES = 0xc000009a,
	NT_STATUS_DFS_EXIT_PATH_FOUND = 0xc000009b,
	NT_STATUS_DEVICE_DATA_ERROR = 0xc000009c,
	NT_STATUS_DEVICE_NOT_CONNECTED = 0xc000009d,
	NT_STATUS_DEVICE_POWER_FAILURE = 0xc000009e,
	NT_STATUS_FREE_VM_NOT_AT_BASE = 0xc000009f,
	NT_STATUS_MEMORY_NOT_ALLOCATED = 0xc00000a0,
	NT_STATUS_WORKING_SET_QUOTA = 0xc00000a1,
	NT_STATUS_MEDIA_WRITE_PROTECTED = 0xc00000a2,
	NT_STATUS_DEVICE_NOT_READY = 0xc00000a3,
	NT_STATUS_INVALID_GROUP_ATTRIBUTES = 0xc00000a4,
	NT_STATUS_BAD_IMPERSONATION_LEVEL = 0xc00000a5,
	NT_STATUS_CANT_OPEN_ANONYMOUS = 0xc00000a6,
	NT_STATUS_BAD_VALIDATION_CLASS = 0xc00000a7,
	NT_STATUS_BAD_TOKEN_TYPE = 0xc00000a8,
	NT_STATUS_BAD_MASTER_BOOT_RECORD = 0xc00000a9,
	NT_STATUS_INSTRUCTION_MISALIGNMENT = 0xc00000aa,
	NT_STATUS_INSTANCE_NOT_AVAILABLE = 0xc00000ab,
	NT_STATUS_PIPE_NOT_AVAILABLE = 0xc00000ac,
	NT_STATUS_INVALID_PIPE_STATE = 0xc00000ad,
	NT_STATUS_PIPE_BUSY = 0xc00000ae,
	NT_STATUS_ILLEGAL_FUNCTION = 0xc00000af,
	NT_STATUS_PIPE_DISCONNECTED = 0xc00000b0,
	NT_STATUS_PIPE_CLOSING = 0xc00000b1,
	NT_STATUS_PIPE_CONNECTED = 0xc00000b2,
	NT_STATUS_PIPE_LISTENING = 0xc00000b3,
	NT_STATUS_INVALID_READ_MODE = 0xc00000b4,
	NT_STATUS_IO_TIMEOUT = 0xc00000b5,
	NT_STATUS_FILE_FORCED_CLOSED = 0xc00000b6,
	NT_STATUS_PROFILING_NOT_STARTED = 0xc00000b7,
	NT_STATUS_PROFILING_NOT_STOPPED = 0xc00000b8,
	NT_STATUS_COULD_NOT_INTERPRET = 0xc00000b9,
	NT_STATUS_FILE_IS_A_DIRECTORY = 0xc00000ba,
	NT_STATUS_NOT_SUPPORTED = 0xc00000bb,
	NT_STATUS_REMOTE_NOT_LISTENING = 0xc00000bc,
	NT_STATUS_DUPLICATE_NAME = 0xc00000bd,
	NT_STATUS_BAD_NETWORK_PATH = 0xc00000be,
	NT_STATUS_NETWORK_BUSY = 0xc00000bf,
	NT_STATUS_DEVICE_DOES_NOT_EXIST = 0xc00000c0,
	NT_STATUS_TOO_MANY_COMMANDS = 0xc00000c1,
	NT_STATUS_ADAPTER_HARDWARE_ERROR = 0xc00000c2,
	NT_STATUS_INVALID_NETWORK_RESPONSE = 0xc00000c3,
	NT_STATUS_UNEXPECTED_NETWORK_ERROR = 0xc00000c4,
	NT_STATUS_BAD_REMOTE_ADAPTER = 0xc00000c5,
	NT_STATUS_PRINT_QUEUE_FULL = 0xc00000c6,
	NT_STATUS_NO_SPOOL_SPACE = 0xc00000c7,
	NT_STATUS_PRINT_CANCELLED = 0xc00000c8,
	NT_STATUS_NETWORK_NAME_DELETED = 0xc00000c9,
	NT_STATUS_NETWORK_ACCESS_DENIED = 0xc00000ca,
	NT_STATUS_BAD_DEVICE_TYPE = 0xc00000cb,
	NT_STATUS_BAD_NETWORK_NAME = 0xc00000cc,
	NT_STATUS_TOO_MANY_NAMES = 0xc00000cd,
	NT_STATUS_TOO_MANY_SESSIONS = 0xc00000ce,
	NT_STATUS_SHARING_PAUSED = 0xc00000cf,
	NT_STATUS_REQUEST_NOT_ACCEPTED = 0xc00000d0,
	NT_STATUS_REDIRECTOR_PAUSED = 0xc00000d1,
	NT_STATUS_NET_WRITE_FAULT = 0xc00000d2,
	NT_STATUS_PROFILING_AT_LIMIT = 0xc00000d3,
	NT_STATUS_NOT_SAME_DEVICE = 0xc00000d4,
	NT_STATUS_FILE_RENAMED = 0xc00000d5,
	NT_STATUS_VIRTUAL_CIRCUIT_CLOSED = 0xc00000d6,
	NT_STATUS_NO_SECURITY_ON_OBJECT = 0xc00000d7,
	NT_STATUS_CANT_WAIT = 0xc00000d8,
	NT_STATUS_PIPE_EMPTY = 0xc00000d9,
	NT_STATUS_CANT_ACCESS_DOMAIN_INFO = 0xc00000da,
	NT_STATUS_CANT_TERMINATE_SELF = 0xc00000db,
	NT_STATUS_INVALID_SERVER_STATE = 0xc00000dc,
	NT_STATUS_INVALID_DOMAIN_STATE = 0xc00000dd,
	NT_STATUS_INVALID_DOMAIN_ROLE = 0xc00000de,
	NT_STATUS_NO_SUCH_DOMAIN = 0xc00000df,
	NT_STATUS_DOMAIN_EXISTS = 0xc00000e0,
	NT_STATUS_DOMAIN_LIMIT_EXCEEDED = 0xc00000e1,
	NT_STATUS_OPLOCK_NOT_GRANTED = 0xc00000e2,
	NT_STATUS_INVALID_OPLOCK_PROTOCOL = 0xc00000e3,
	NT_STATUS_INTERNAL_DB_CORRUPTION = 0xc00000e4,
	NT_STATUS_INTERNAL_ERROR = 0xc00000e5,
	NT_STATUS_GENERIC_NOT_MAPPED = 0xc00000e6,
	NT_STATUS_BAD_DESCRIPTOR_FORMAT = 0xc00000e7,
	NT_STATUS_INVALID_USER_BUFFER = 0xc00000e8,
	NT_STATUS_UNEXPECTED_IO_ERROR = 0xc00000e9,
	NT_STATUS_UNEXPECTED_MM_CREATE_ERR = 0xc00000ea,
	NT_STATUS_UNEXPECTED_MM_MAP_ERROR = 0xc00000eb,
	NT_STATUS_UNEXPECTED_MM_EXTEND_ERR = 0xc00000ec,
	NT_STATUS_NOT_LOGON_PROCESS = 0xc00000ed,
	NT_STATUS_LOGON_SESSION_EXISTS = 0xc00000ee,
	NT_STATUS_INVALID_PARAMETER_1 = 0xc00000ef,
	NT_STATUS_INVALID_PARAMETER_2 = 0xc00000f0,
	NT_STATUS_INVALID_PARAMETER_3 = 0xc00000f1,
	NT_STATUS_INVALID_PARAMETER_4 = 0xc00000f2,
	NT_STATUS_INVALID_PARAMETER_5 = 0xc00000f3,
	NT_STATUS_INVALID_PARAMETER_6 = 0xc00000f4,
	NT_STATUS_INVALID_PARAMETER_7 = 0xc00000f5,
	NT_STATUS_INVALID_PARAMETER_8 = 0xc00000f6,
	NT_STATUS_INVALID_PARAMETER_9 = 0xc00000f7,
	NT_STATUS_INVALID_PARAMETER_10 = 0xc00000f8,
	NT_STATUS_INVALID_PARAMETER_11 = 0xc00000f9,
	NT_STATUS_INVALID_PARAMETER_12 = 0xc00000fa,
	NT_STATUS_REDIRECTOR_NOT_STARTED = 0xc00000fb,
	NT_STATUS_REDIRECTOR_STARTED = 0xc00000fc,
	NT_STATUS_STACK_OVERFLOW = 0xc00000fd,
	NT_STATUS_NO_SUCH_PACKAGE = 0xc00000fe,
	NT_STATUS_BAD_FUNCTION_TABLE = 0xc00000ff,
	NT_STATUS_DIRECTORY_NOT_EMPTY = 0xc0000101,
	NT_STATUS_FILE_CORRUPT_ERROR = 0xc0000102,
	NT_STATUS_NOT_A_DIRECTORY = 0xc0000103,
	NT_STATUS_BAD_LOGON_SESSION_STATE = 0xc0000104,
	NT_STATUS_LOGON_SESSION_COLLISION = 0xc0000105,
	NT_STATUS_NAME_TOO_LONG = 0xc0000106,
	NT_STATUS_FILES_OPEN = 0xc0000107,
	NT_STATUS_CONNECTION_IN_USE = 0xc0000108,
	NT_STATUS_MESSAGE_NOT_FOUND = 0xc0000109,
	NT_STATUS_PROCESS_IS_TERMINATING = 0xc000010a,
	NT_STATUS_INVALID_LOGON_TYPE = 0xc000010b,
	NT_STATUS_NO_GUID_TRANSLATION = 0xc000010c,
	NT_STATUS_CANNOT_IMPERSONATE = 0xc000010d,
	NT_STATUS_IMAGE_ALREADY_LOADED = 0xc000010e,
	NT_STATUS_ABIOS_NOT_PRESENT = 0xc000010f,
	NT_STATUS_ABIOS_LID_NOT_EXIST = 0xc0000110,
	NT_STATUS_ABIOS_LID_ALREADY_OWNED = 0xc0000111,
	NT_STATUS_ABIOS_NOT_LID_OWNER = 0xc0000112,
	NT_STATUS_ABIOS_INVALID_COMMAND = 0xc0000113,
	NT_STATUS_ABIOS_INVALID_LID = 0xc0000114,
	NT_STATUS_ABIOS_SELECTOR_NOT_AVAILABLE = 0xc0000115,
	NT_STATUS_ABIOS_INVALID_SELECTOR = 0xc0000116,
	NT_STATUS_NO_LDT = 0xc0000117,
	NT_STATUS_INVALID_LDT_SIZE = 0xc0000118,
	NT_STATUS_INVALID_LDT_OFFSET = 0xc0000119,
	NT_STATUS_INVALID_LDT_DESCRIPTOR = 0xc000011a,
	NT_STATUS_INVALID_IMAGE_NE_FORMAT = 0xc000011b,
	NT_STATUS_RXACT_INVALID_STATE = 0xc000011c,
	NT_STATUS_RXACT_COMMIT_FAILURE = 0xc000011d,
	NT_STATUS_MAPPED_FILE_SIZE_ZERO = 0xc000011e,
	NT_STATUS_TOO_MANY_OPENED_FILES = 0xc000011f,
	NT_STATUS_CANCELLED = 0xc0000120,
	NT_STATUS_CANNOT_DELETE = 0xc0000121,
	NT_STATUS_INVALID_COMPUTER_NAME = 0xc0000122,
	NT_STATUS_FILE_DELETED = 0xc0000123,
	NT_STATUS_SPECIAL_ACCOUNT = 0xc0000124,
	NT_STATUS_SPECIAL_GROUP = 0xc0000125,
	NT_STATUS_SPECIAL_USER = 0xc0000126,
	NT_STATUS_MEMBERS_PRIMARY_GROUP = 0xc0000127,
	NT_STATUS_FILE_CLOSED = 0xc0000128,
	NT_STATUS_TOO_MANY_THREADS = 0xc0000129,
	NT_STATUS_THREAD_NOT_IN_PROCESS = 0xc000012a,
	NT_STATUS_TOKEN_ALREADY_IN_USE = 0xc000012b,
	NT_STATUS_PAGEFILE_QUOTA_EXCEEDED = 0xc000012c,
	NT_STATUS_COMMITMENT_LIMIT = 0xc000012d,
	NT_STATUS_INVALID_IMAGE_LE_FORMAT = 0xc000012e,
	NT_STATUS_INVALID_IMAGE_NOT_MZ = 0xc000012f,
	NT_STATUS_INVALID_IMAGE_PROTECT = 0xc0000130,
	NT_STATUS_INVALID_IMAGE_WIN_16 = 0xc0000131,
	NT_STATUS_LOGON_SERVER_CONFLICT = 0xc0000132,
	NT_STATUS_TIME_DIFFERENCE_AT_DC = 0xc0000133,
	NT_STATUS_SYNCHRONIZATION_REQUIRED = 0xc0000134,
	NT_STATUS_DLL_NOT_FOUND = 0xc0000135,
	NT_STATUS_OPEN_FAILED = 0xc0000136,
	NT_STATUS_IO_PRIVILEGE_FAILED = 0xc0000137,
	NT_STATUS_ORDINAL_NOT_FOUND = 0xc0000138,
	NT_STATUS_ENTRYPOINT_NOT_FOUND = 0xc0000139,
	NT_STATUS_CONTROL_C_EXIT = 0xc000013a,
	NT_STATUS_LOCAL_DISCONNECT = 0xc000013b,
	NT_STATUS_REMOTE_DISCONNECT = 0xc000013c,
	NT_STATUS_REMOTE_RESOURCES = 0xc000013d,
	NT_STATUS_LINK_FAILED = 0xc000013e,
	NT_STATUS_LINK_TIMEOUT = 0xc000013f,
	NT_STATUS_INVALID_CONNECTION = 0xc0000140,
	NT_STATUS_INVALID_ADDRESS = 0xc0000141,
	NT_STATUS_DLL_INIT_FAILED = 0xc0000142,
	NT_STATUS_MISSING_SYSTEMFILE = 0xc0000143,
	NT_STATUS_UNHANDLED_EXCEPTION = 0xc0000144,
	NT_STATUS_APP_INIT_FAILURE = 0xc0000145,
	NT_STATUS_PAGEFILE_CREATE_FAILED = 0xc0000146,
	NT_STATUS_NO_PAGEFILE = 0xc0000147,
	NT_STATUS_INVALID_LEVEL = 0xc0000148,
	NT_STATUS_WRONG_PASSWORD_CORE = 0xc0000149,
	NT_STATUS_ILLEGAL_FLOAT_CONTEXT = 0xc000014a,
	NT_STATUS_PIPE_BROKEN = 0xc000014b,
	NT_STATUS_REGISTRY_CORRUPT = 0xc000014c,
	NT_STATUS_REGISTRY_IO_FAILED = 0xc000014d,
	NT_STATUS_NO_EVENT_PAIR = 0xc000014e,
	NT_STATUS_UNRECOGNIZED_VOLUME = 0xc000014f,
	NT_STATUS_SERIAL_NO_DEVICE_INITED = 0xc0000150,
	NT_STATUS_NO_SUCH_ALIAS = 0xc0000151,
	NT_STATUS_MEMBER_NOT_IN_ALIAS = 0xc0000152,
	NT_STATUS_MEMBER_IN_ALIAS = 0xc0000153,
	NT_STATUS_ALIAS_EXISTS = 0xc0000154,
	NT_STATUS_LOGON_NOT_GRANTED = 0xc0000155,
	NT_STATUS_TOO_MANY_SECRETS = 0xc0000156,
	NT_STATUS_SECRET_TOO_LONG = 0xc0000157,
	NT_STATUS_INTERNAL_DB_ERROR = 0xc0000158,
	NT_STATUS_FULLSCREEN_MODE = 0xc0000159,
	NT_STATUS_TOO_MANY_CONTEXT_IDS = 0xc000015a,
	NT_STATUS_LOGON_TYPE_NOT_GRANTED = 0xc000015b,
	NT_STATUS_NOT_REGISTRY_FILE = 0xc000015c,
	NT_STATUS_NT_CROSS_ENCRYPTION_REQUIRED = 0xc000015d,
	NT_STATUS_DOMAIN_CTRLR_CONFIG_ERROR = 0xc000015e,
	NT_STATUS_FT_MISSING_MEMBER = 0xc000015f,
	NT_STATUS_ILL_FORMED_SERVICE_ENTRY = 0xc0000160,
	NT_STATUS_ILLEGAL_CHARACTER = 0xc0000161,
	NT_STATUS_UNMAPPABLE_CHARACTER = 0xc0000162,
	NT_STATUS_UNDEFINED_CHARACTER = 0xc0000163,
	NT_STATUS_FLOPPY_VOLUME = 0xc0000164,
	NT_STATUS_FLOPPY_ID_MARK_NOT_FOUND = 0xc0000165,
	NT_STATUS_FLOPPY_WRONG_CYLINDER = 0xc0000166,
	NT_STATUS_FLOPPY_UNKNOWN_ERROR = 0xc0000167,
	NT_STATUS_FLOPPY_BAD_REGISTERS = 0xc0000168,
	NT_STATUS_DISK_RECALIBRATE_FAILED = 0xc0000169,
	NT_STATUS_DISK_OPERATION_FAILED = 0xc000016a,
	NT_STATUS_DISK_RESET_FAILED = 0xc000016b,
	NT_STATUS_SHARED_IRQ_BUSY = 0xc000016c,
	NT_STATUS_FT_ORPHANING = 0xc000016d,
	NT_STATUS_PARTITION_FAILURE = 0xc0000172,
	NT_STATUS_INVALID_BLOCK_LENGTH = 0xc0000173,
	NT_STATUS_DEVICE_NOT_PARTITIONED = 0xc0000174,
	NT_STATUS_UNABLE_TO_LOCK_MEDIA = 0xc0000175,
	NT_STATUS_UNABLE_TO_UNLOAD_MEDIA = 0xc0000176,
	NT_STATUS_EOM_OVERFLOW = 0xc0000177,
	NT_STATUS_NO_MEDIA = 0xc0000178,
	NT_STATUS_NO_SUCH_MEMBER = 0xc000017a,
	NT_STATUS_INVALID_MEMBER = 0xc000017b,
	NT_STATUS_KEY_DELETED = 0xc000017c,
	NT_STATUS_NO_LOG_SPACE = 0xc000017d,
	NT_STATUS_TOO_MANY_SIDS = 0xc000017e,
	NT_STATUS_LM_CROSS_ENCRYPTION_REQUIRED = 0xc000017f,
	NT_STATUS_KEY_HAS_CHILDREN = 0xc0000180,
	NT_STATUS_CHILD_MUST_BE_VOLATILE = 0xc0000181,
	NT_STATUS_DEVICE_CONFIGURATION_ERROR = 0xc0000182,
	NT_STATUS_DRIVER_INTERNAL_ERROR = 0xc0000183,
	NT_STATUS_INVALID_DEVICE_STATE = 0xc0000184,
	NT_STATUS_IO_DEVICE_ERROR = 0xc0000185,
	NT_STATUS_DEVICE_PROTOCOL_ERROR = 0xc0000186,
	NT_STATUS_BACKUP_CONTROLLER = 0xc0000187,
	NT_STATUS_LOG_FILE_FULL = 0xc0000188,
	NT_STATUS_TOO_LATE = 0xc0000189,
	NT_STATUS_NO_TRUST_LSA_SECRET = 0xc000018a,
	NT_STATUS_NO_TRUST_SAM_ACCOUNT = 0xc000018b,
	NT_STATUS_TRUSTED_DOMAIN_FAILURE = 0xc000018c,
	NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE = 0xc000018d,
	NT_STATUS_EVENTLOG_FILE_CORRUPT = 0xc000018e,
	NT_STATUS_EVENTLOG_CANT_START = 0xc000018f,
	NT_STATUS_TRUST_FAILURE = 0xc0000190,
	NT_STATUS_MUTANT_LIMIT_EXCEEDED = 0xc0000191,
	NT_STATUS_NETLOGON_NOT_STARTED = 0xc0000192,
	NT_STATUS_ACCOUNT_EXPIRED = 0xc0000193,
	NT_STATUS_POSSIBLE_DEADLOCK = 0xc0000194,
	NT_STATUS_NETWORK_CREDENTIAL_CONFLICT = 0xc0000195,
	NT_STATUS_REMOTE_SESSION_LIMIT = 0xc0000196,
	NT_STATUS_EVENTLOG_FILE_CHANGED = 0xc0000197,
	NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT = 0xc0000198,
	NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT = 0xc0000199,
	NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT = 0xc000019a,
	NT_STATUS_DOMAIN_TRUST_INCONSISTENT = 0xc000019b,
	NT_STATUS_FS_DRIVER_REQUIRED = 0xc000019c,
	NT_STATUS_NO_USER_SESSION_KEY = 0xc0000202,
	NT_STATUS_USER_SESSION_DELETED = 0xc0000203,
	NT_STATUS_RESOURCE_LANG_NOT_FOUND = 0xc0000204,
	NT_STATUS_INSUFF_SERVER_RESOURCES = 0xc0000205,
	NT_STATUS_INVALID_BUFFER_SIZE = 0xc0000206,
	NT_STATUS_INVALID_ADDRESS_COMPONENT = 0xc0000207,
	NT_STATUS_INVALID_ADDRESS_WILDCARD = 0xc0000208,
	NT_STATUS_TOO_MANY_ADDRESSES = 0xc0000209,
	NT_STATUS_ADDRESS_ALREADY_EXISTS = 0xc000020a,
	NT_STATUS_ADDRESS_CLOSED = 0xc000020b,
	NT_STATUS_CONNECTION_DISCONNECTED = 0xc000020c,
	NT_STATUS_CONNECTION_RESET = 0xc000020d,
	NT_STATUS_TOO_MANY_NODES = 0xc000020e,
	NT_STATUS_TRANSACTION_ABORTED = 0xc000020f,
	NT_STATUS_TRANSACTION_TIMED_OUT = 0xc0000210,
	NT_STATUS_TRANSACTION_NO_RELEASE = 0xc0000211,
	NT_STATUS_TRANSACTION_NO_MATCH = 0xc0000212,
	NT_STATUS_TRANSACTION_RESPONDED = 0xc0000213,
	NT_STATUS_TRANSACTION_INVALID_ID = 0xc0000214,
	NT_STATUS_TRANSACTION_INVALID_TYPE = 0xc0000215,
	NT_STATUS_NOT_SERVER_SESSION = 0xc0000216,
	NT_STATUS_NOT_CLIENT_SESSION = 0xc0000217,
	NT_STATUS_CANNOT_LOAD_REGISTRY_FILE = 0xc0000218,
	NT_STATUS_DEBUG_ATTACH_FAILED = 0xc0000219,
	NT_STATUS_SYSTEM_PROCESS_TERMINATED = 0xc000021a,
	NT_STATUS_DATA_NOT_ACCEPTED = 0xc000021b,
	NT_STATUS_NO_BROWSER_SERVERS_FOUND = 0xc000021c,
	NT_STATUS_VDM_HARD_ERROR = 0xc000021d,
	NT_STATUS_DRIVER_CANCEL_TIMEOUT = 0xc000021e,
	NT_STATUS_REPLY_MESSAGE_MISMATCH = 0xc000021f,
	NT_STATUS_MAPPED_ALIGNMENT = 0xc0000220,
	NT_STATUS_IMAGE_CHECKSUM_MISMATCH = 0xc0000221,
	NT_STATUS_LOST_WRITEBEHIND_DATA = 0xc0000222,
	NT_STATUS_CLIENT_SERVER_PARAMETERS_INVALID = 0xc0000223,
	NT_STATUS_PASSWORD_MUST_CHANGE = 0xc0000224,
	NT_STATUS_NOT_FOUND = 0xc0000225,
	NT_STATUS_NOT_TINY_STREAM = 0xc0000226,
	NT_STATUS_RECOVERY_FAILURE = 0xc0000227,
	NT_STATUS_STACK_OVERFLOW_READ = 0xc0000228,
	NT_STATUS_FAIL_CHECK = 0xc0000229,
	NT_STATUS_DUPLICATE_OBJECTID = 0xc000022a,
	NT_STATUS_OBJECTID_EXISTS = 0xc000022b,
	NT_STATUS_CONVERT_TO_LARGE = 0xc000022c,
	NT_STATUS_RETRY = 0xc000022d,
	NT_STATUS_FOUND_OUT_OF_SCOPE = 0xc000022e,
	NT_STATUS_ALLOCATE_BUCKET = 0xc000022f,
	NT_STATUS_PROPSET_NOT_FOUND = 0xc0000230,
	NT_STATUS_MARSHALL_OVERFLOW = 0xc0000231,
	NT_STATUS_INVALID_VARIANT = 0xc0000232,
	NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND = 0xc0000233,
	NT_STATUS_ACCOUNT_LOCKED_OUT = 0xc0000234,
	NT_STATUS_HANDLE_NOT_CLOSABLE = 0xc0000235,
	NT_STATUS_CONNECTION_REFUSED = 0xc0000236,
	NT_STATUS_GRACEFUL_DISCONNECT = 0xc0000237,
	NT_STATUS_ADDRESS_ALREADY_ASSOCIATED = 0xc0000238,
	NT_STATUS_ADDRESS_NOT_ASSOCIATED = 0xc0000239,
	NT_STATUS_CONNECTION_INVALID = 0xc000023a,
	NT_STATUS_CONNECTION_ACTIVE = 0xc000023b,
	NT_STATUS_NETWORK_UNREACHABLE = 0xc000023c,
	NT_STATUS_HOST_UNREACHABLE = 0xc000023d,
	NT_STATUS_PROTOCOL_UNREACHABLE = 0xc000023e,
	NT_STATUS_PORT_UNREACHABLE = 0xc000023f,
	NT_STATUS_REQUEST_ABORTED = 0xc0000240,
	NT_STATUS_CONNECTION_ABORTED = 0xc0000241,
	NT_STATUS_BAD_COMPRESSION_BUFFER = 0xc0000242,
	NT_STATUS_USER_MAPPED_FILE = 0xc0000243,
	NT_STATUS_AUDIT_FAILED = 0xc0000244,
	NT_STATUS_TIMER_RESOLUTION_NOT_SET = 0xc0000245,
	NT_STATUS_CONNECTION_COUNT_LIMIT = 0xc0000246,
	NT_STATUS_LOGIN_TIME_RESTRICTION = 0xc0000247,
	NT_STATUS_LOGIN_WKSTA_RESTRICTION = 0xc0000248,
	NT_STATUS_IMAGE_MP_UP_MISMATCH = 0xc0000249,
	NT_STATUS_INSUFFICIENT_LOGON_INFO = 0xc0000250,
	NT_STATUS_BAD_DLL_ENTRYPOINT = 0xc0000251,
	NT_STATUS_BAD_SERVICE_ENTRYPOINT = 0xc0000252,
	NT_STATUS_LPC_REPLY_LOST = 0xc0000253,
	NT_STATUS_IP_ADDRESS_CONFLICT1 = 0xc0000254,
	NT_STATUS_IP_ADDRESS_CONFLICT2 = 0xc0000255,
	NT_STATUS_REGISTRY_QUOTA_LIMIT = 0xc0000256,
	NT_STATUS_PATH_NOT_COVERED = 0xc0000257,
	NT_STATUS_NO_CALLBACK_ACTIVE = 0xc0000258,
	NT_STATUS_LICENSE_QUOTA_EXCEEDED = 0xc0000259,
	NT_STATUS_PWD_TOO_SHORT = 0xc000025a,
	NT_STATUS_PWD_TOO_RECENT = 0xc000025b,
	NT_STATUS_PWD_HISTORY_CONFLICT = 0xc000025c,
	NT_STATUS_PLUGPLAY_NO_DEVICE = 0xc000025e,
	NT_STATUS_UNSUPPORTED_COMPRESSION = 0xc000025f,
	NT_STATUS_INVALID_HW_PROFILE = 0xc0000260,
	NT_STATUS_INVALID_PLUGPLAY_DEVICE_PATH = 0xc0000261,
	NT_STATUS_DRIVER_ORDINAL_NOT_FOUND = 0xc0000262,
	NT_STATUS_DRIVER_ENTRYPOINT_NOT_FOUND = 0xc0000263,
	NT_STATUS_RESOURCE_NOT_OWNED = 0xc0000264,
	NT_STATUS_TOO_MANY_LINKS = 0xc0000265,
	NT_STATUS_QUOTA_LIST_INCONSISTENT = 0xc0000266,
	NT_STATUS_FILE_IS_OFFLINE = 0xc0000267,
	NT_STATUS_DS_NO_MORE_RIDS = 0xc00002a8,
	NT_STATUS_NOT_A_REPARSE_POINT = 0xc0000275,
	NT_STATUS_NO_SUCH_JOB = 0xc000EDE
}

for i, v in pairs(status_codes) do
	status_names[v] = i
end

