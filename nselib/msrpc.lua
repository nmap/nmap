--- Call various MSRPC functions.
-- \n\n
-- By making heavy use of the smb library, this library will call various MSRPC 
--  functions. The functions used here can be access over TCP ports 445 and 139, 
--  with an established session. A NULL session (the default) will work for some 
--  functions and operating systems (or configurations), but not for others. \n
--\n
-- To make use of these function calls, a SMB session with the server has to be
-- established. This can be done manually with the 'smb' library, or the function
-- start_smb() can be called. \n
--\n
-- Next, the interface has to be bound. The bind() function will take care of that. \n
--\n
-- After that, you're free to call any function that's part of that interface. In
-- other words, if you bind to the SAMR interface, you can only call the samr_
-- functions.\n
--\n
-- Although functions can be called in any order, many functions depend on the
-- value returned by other functions. I indicate those in the function comments, 
-- so keep an eye out. \n
--\n
-- Something to note is that these functions, for the most part, return a whole ton
-- of stuff in an array. I basically wrote them to return every possible value
-- they get their hands on. I don't expect that most of them will be used, and I'm 
-- not going to document them all in the function header; rather, I will document
-- the elements in the table that are more useful, you'll have to look at the actual
-- code (or the table) to see what else is available. \n
--
--@author Ron Bowes <ron@skullsecurity.net>
--@copyright See nmap's COPYING for licence
-----------------------------------------------------------------------
module(... or "msrpc", package.seeall)

require 'bit'
require 'bin'
require 'netbios'
require 'smb'
require 'stdnse'

-- The path, UUID, and version for SAMR
SAMR_PATH       = "\\samr"
SAMR_UUID       = bin.pack("CCCCCCCCCCCCCCCC", 0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xac)
SAMR_VERSION    = 0x01

-- The path, UUID, and version for SRVSVC
SRVSVC_PATH     = "\\srvsvc"
SRVSVC_UUID     = bin.pack("CCCCCCCCCCCCCCCC", 0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88)
SRVSVC_VERSION  = 0x03

-- The path, UUID, and version for LSA
LSA_PATH        = "\\lsarpc"
LSA_UUID        = bin.pack("CCCCCCCCCCCCCCCC", 0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab)
LSA_VERSION     = 0

-- This is the only transfer syntax I've seen in the wild, not that I've looked hard. It seems to work well. 
TRANSFER_SYNTAX = bin.pack("CCCCCCCCCCCCCCCC", 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60)

-- The 'referent_id' value is ignored, as far as I can tell, so this value is passed for it. No, it isn't random. :)
REFERENT_ID = 0x50414d4e

-- A few error codes
STATUS_SOME_NOT_MAPPED        = 0x00000107
STATUS_INVALID_PARAMETER      = 0xC000000D
STATUS_ACCESS_DENIED          = 0xC0000022 
STATUS_BUFFER_TOO_SMALL       = 0xC0000023
STATUS_NONE_MAPPED            = 0xC0000073
STATUS_INSUFFICIENT_RESOURCES = 0xC000009A
STATUS_MORE_ENTRIES           = 0x00000105
STATUS_TOO_MANY_CONTEXT_IDS   = 0xC000015A

---Convert the return status of a function into a string. This isn't nearly an 
-- exhaustive list, if I decide to go all out then I'll probably move this into
-- its own library. 
--@param status the status to convert
--@return The string equivalent to the status. 
local function status_to_string(status)
	if(status == STATUS_ACCESS_DENIED) then
		return "STATUS_ACCESS_DENIED"
	elseif(status == STATUS_MORE_ENTRIES) then
		return "STATUS_MORE_ENTRIES"
	elseif(status == STATUS_TOO_MANY_CONTEXT_IDS) then
		return "STATUS_TOO_MANY_CONTEXT_IDS"
	elseif(status == STATUS_INSUFFICIENT_RESOURCES) then
		return "STATUS_INSUFFICIENT_RESOURCES"
	elseif(status == STATUS_BUFFER_TOO_SMALL) then
		return "STATUS_BUFFER_TOO_SMALL"
	elseif(status == STATUS_INVALID_PARAMETER) then
		return "STATUS_INVALID_PARAMETER"
	elseif(status == STATUS_SOME_NOT_MAPPED) then
		return "STATUS_SOME_NOT_MAPPED"
	elseif(status == STATUS_NONE_MAPPED) then
		return "STATUS_NONE_MAPPED"
	else
		return string.format("STATUS_UNKNOWN_ERROR (0x%08x)", status)
	end
end

--- Convert a string to fake unicode (ascii with null characters between them), optionally add a null terminator, 
--  and optionally align it to 4-byte boundaries. This is frequently used in MSRPC calls, so I put it here, but
--  it might be a good idea to move this function (and the converse one below) into a separate library. 
--@param string The string to convert. 
--@param do_null [optional]  Add a null-terminator to the unicode string. Default false. 
--@param do_align [optional] Align the string to a multiple of 4 bytes. Default false. 
--@return The unicode version of the string. 
local function string_to_unicode(string, do_null, do_align)
	local i
	local result = ""

	if(do_null == nil) then
		do_null = false
	end
	if(do_align == nil) then
		do_align = false
	end

	-- Loop through the string, adding each character followed by a char(0)
	for i = 1, string.len(string), 1 do
		result = result .. string.sub(string, i, i) .. string.char(0)
	end

	-- Add a null, if the caller requestd it
	if(do_null == true) then
		result = result .. string.char(0) .. string.char(0)
	end

	-- Align it to a multiple of 4, if necessary
	if(do_align) then
		if(string.len(result) % 4 ~= 0) then
			result = result .. string.char(0) .. string.char(0)
		end
	end

	return result
end

--- Read a unicode string from a buffer, similar to how bin.unpack() would, optionally eat the null terminator, 
--  and optionally align it to 4-byte boundaries. 
--@param buffer   The buffer to read from, typically the full 'arguments' value for MSRPC
--@param pos      The position in the buffer to start (just like bin.unpack())
--@param length   The number of ascii characters that will be read (including the null, if do_null is set). 
--@param do_null  [optional] Remove a null terminator from the string as the last character. Default false. 
--@param do_align [optional] Ensure that the number of bytes removed is a multiple of 4. 
--@return (pos, string) The new position and the string read, again imitating bin.unpack(). 
local function unicode_to_string(buffer, pos, length, do_null, do_align)
	local i, ch, dummy
	local string = ""

stdnse.print_debug(5, "MSRPC: Entering unicode_to_string(pos = %d, length = %d)", pos, length)

	if(do_null == nil) then
		do_null = false
	end
	if(do_align == nil) then
		do_align = false
	end

	if(do_null == true) then
		length = length - 1
	end

	for j = 1, length, 1 do

		pos, ch, dummy = bin.unpack("<CC", buffer, pos)
		string = string .. string.char(ch)
	end

	if(do_null == true) then
		pos = pos + 2 -- Eat the null terminator
	end

	if(do_align) then
		if(do_null == true and ((length + 1) % 2) == 1) then
			pos = pos + 2
		end

		if(do_null == false and (length % 2) == 1) then
			pos = pos + 2
		end
	end

stdnse.print_debug(5, "MSRPC: Exiting unicode_to_string()", i, count)

	return pos, string
end

---Convert a SID object to the standard string representation (S-<rev>-<auth>-<subauths...>). 
--
--@param sid A SID object. 
--@return A string representing the SID. 
function sid_to_string(sid)
	local i
	local str

	local authority = bit.bor(bit.lshift(sid['authority_high'], 32), sid['authority'])

	str = string.format("S-%u-%u", sid['revision'], sid['authority'])

	for i = 1, sid['count'], 1 do
		str = str .. string.format("-%u", sid['subauthorities'][i])
	end

	return str
end


--- This is a wrapper around the SMB class, designed to get SMB going quickly in a script. This will
--  connect to the SMB server, negotiate the protocol, open a session, connect to the IPC$ share, and
--  open the named pipe given by 'path'. When this successfully returns, the socket can be immediately 
--  used for MSRPC. 
--
--@param host The host object. 
--@param path The path to the named pipe; for example, msrpc.SAMR_PATH or msrpc.SRVSVC_PATH. 
--@return (status, socket, uid, tid, fid, negotiate_result, session_result, tree_result, create_result) 
--        if status is false, socket is an error message. Otherwise, the rest of the results are 
--        returned. 
function start_smb(host, path)
	local status, socket, negotiate_result, session_result, tree_result, create_result

	-- Begin the SMB session
    status, socket = smb.start(host)
    if(status == false) then
        return false, socket
    end

	-- Negotiate the protocol
    status, negotiate_result = smb.negotiate_protocol(socket)
    if(status == false) then
        smb.stop(socket)   
        return false, negotiate_result
    end

    -- Start up a null session
    status, session_result = smb.start_session(socket, "", negotiate_result['session_key'], negotiate_result['capabilities'])
    if(status == false) then
        smb.stop(socket)   
        return false, session_result
    end

    -- Connect to IPC$ share
    status, tree_result = smb.tree_connect(socket, "IPC$", session_result['uid'])
    if(status == false) then
        smb.stop(socket, session_result['uid'])   
        return false, tree_result
    end

    -- Try to connect to requested pipe
    status, create_result = smb.create_file(socket, path, session_result['uid'], tree_result['tid'])
    if(status == false) then
        smb.stop(socket, session_result['uid'], tree_result['tid'])   
        return false, create_result
    end

	-- Return everything
	return true, socket, session_result['uid'], tree_result['tid'], create_result['fid'], negotiate_result, session_result, tree_result, create_result
end

--- A wrapper around the smb.stop() function. I only created it to add symmetry, so the code uses
--  the same class to start/stop the session. In the future, this may be expanded to close
--  handles before exiting. 
--
--@param socket The socket to close. 
--@param uid    The UserID, which will be logged off before closing the socket. 
--@param tid    The TreeID, which will be disconnected before closing the socket. 
function stop_smb(socket, uid, tid)
	smb.stop(socket, uid, tid)
end

--- Bind to a MSRPC interface. Two common interfaces are SAML and SRVSVC, and can be found as
--  constants at the top of this file. Once this function has successfully returned, any MSRPC
--  call can be made (provided it doesn't depend on results from other MSRPC calls). 
--
--@param socket The socket in the appropriate state
--@param interface_uuid The interface to bind to. There are constants defined for these (SAMR_UUID, 
--       etc.)
--@param interface_version The interface version to use. There are constants at the top (SAMR_VERSION, 
--       etc.)
--@param transfer_syntax The transfer syntax to use. I don't really know what this is, but the value
--       was always the same on my tests. You can use the constant at the top (TRANSFER_SYNTAX), or
--       just set this parameter to 'nil'. 
--@param uid The UserID we're sending the packets as
--@param tid The TreeID we're sending the packets to
--@param fid The FileID we're sending the packets to
--@return (status, result) If status is false, result is an error message. Otherwise, result is a 
--        table of values, none of which are especially useful. 
function bind(socket, interface_uuid, interface_version, transfer_syntax, uid, tid, fid)
	local i
	local status, result
	local parameters, data
	local pos, align
	local response = {}

	stdnse.print_debug(2, "MSRPC: Sending Bind() request")

	-- Use the only transfer_syntax value I know of. 
	if(transfer_syntax == nil) then
		transfer_syntax = TRANSFER_SYNTAX
	end

	data = bin.pack("<CCCC>I<SSISSICCCC",
				0x05, -- Version (major)
				0x00, -- Version (minor)
				0x0B, -- Packet type (0x0B = bind)
				0x03, -- Packet flags (0x03 = first frag + last frag)
				0x10000000, -- Data representation (big endian)
				0x0048,     -- Frag length
				0x0000,     -- Auth length
				0x41414141, -- Call ID (I use 'AAAA' because it's easy to recognize)
				0x10b8,     -- Max transmit frag
				0x10b8,     -- Max receive frag
				0x00000000, -- Assoc group
				0x01,       -- Number of items
				0x00,       -- Padding/alignment
				0x00,       -- Padding/alignment
				0x00        -- Padding/alignment
			)

	data = data .. bin.pack("<SCCASSAI",
				0x0000,            -- Context ID
				0x01,              -- Number of transaction items. */
				0x00,              -- Padding/alignment
				interface_uuid,    -- Interface (eg. SRVSVC UUID: 4b324fc8-1670-01d3-1278-5a47bf6ee188)
				interface_version, -- Interface version (major)
				0x0000,            -- Interface version (minor)
				transfer_syntax,   -- Transfer syntax
				2                  -- Syntax version
			)

	status, result = smb.send_transaction(socket, 0x0026, "", data, uid, tid, fid)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(2, "MSRPC: Received Bind() response")

	-- Make these easier to access. 
	parameters = result['parameters']
	data = result['data']

	-- Extract the first part from the resposne
	pos, response['version_major'], response['version_minor'], response['packet_type'], response['packet_flags'], response['data_representation'], response['frag_length'], response['auth_length'], response['call_id'] = bin.unpack("<CCCC>I<SSI", data)

	-- Check if the packet tyep was a fault
	if(response['packet_type'] == 0x03) then -- MSRPC_FAULT
		return false, "Bind() returned a fault (packet type)"
	end
	-- Check if the flags indicate DID_NOT_EXECUTE
	if(bit.band(response['packet_flags'], 0x20) == 0x20) then
		return false, "Bind() returned a fault (flags)"
	end
	-- Check if it requested authorization (I've never seen this, but wouldn't know how to handle it)
	if(response['auth_length'] ~= 0) then
		return false, "Bind() returned an 'auth length', which we don't know how to deal with"
	end
	-- Check if the packet was fragmented (I've never seen this, but wouldn't know how to handle it)
	if(bit.band(response['packet_flags'], 0x03) ~= 0x03) then
		return false, "Bind() returned a fragmented packet, which we don't know how to handle"
	end
	-- Check if the wrong message type was returned
	if(response['packet_type'] ~= 0x0c) then
		return false, "Bind() returned an unexpected packet type (not BIND_ACK)"
	end
	-- Ensure the proper call_id was echoed back (if this is wrong, it's likely because our read is out of sync, not a bad server)
	if(response['call_id'] ~= 0x41414141) then
		return false, "MSRPC call returned an incorrect 'call_id' value"
	end

	-- If we made it this far, then we have a valid Bind() response. Pull out some more parameters. 
	pos, response['max_transmit_frag'], response['max_receive_frag'], response['assoc_group'], response['secondary_address_length'] = bin.unpack("SSIS", data, pos)

	-- Read the secondary address
	pos, response['secondary_address'] = bin.unpack(string.format("<A%d", response['secondary_address_length']), data, pos)
	pos = pos + ((4 - ((pos - 1) % 4)) % 4); -- Alignment -- don't ask how I came up with this, it was a lot of drawing

	-- Read the number of results
	pos, response['num_results'] = bin.unpack("<C", data, pos)
	pos = pos + ((4 - ((pos - 1) % 4)) % 4); -- Alignment

	-- Verify we got back what we expected
	if(response['num_results'] ~= 1) then
		return false, "Bind() returned the incorrect number of result"
	end

	-- Read in the last bits
	pos, response['ack_result'], response['align'], response['transfer_syntax'], response['syntax_version'] = bin.unpack("<SSA16I", data, pos)

	return true, response
end

--- Call a MSRPC function on the remote sever, with the given opnum and arguments. I opted to make this a local function
--  for design reasons -- scripts shouldn't be directly calling a function, if a function I haven't written is needed, it
--  ought to be added to this file. \n
--\n
-- Anyways, this function takes the opnum and marshalled arguments, and passes it down to the SMB layer. The SMB layer sends
-- out a SMB_COM_TRANSACTION packet, and parses the response. Once the SMB stuff has been stripped off the response, it's 
-- passed down here, cleaned up some more, and returned to the caller. \n
--\n
-- There's a reason that SMB is sometimes considered to be between layer 4 and 7 on the OSI model. :)\n
--
--@param socket    The socket, in the correct state (SMB has been started, and bind() has been called). 
--@param opnum     The operating number (ie, the function). Find this in the MSRPC documentation or with a packet logger. 
--@param arguments The marshalled arguments to pass to the function. Currently, marshalling is all done manually. 
--@param uid       The UserID we're sending the packets as
--@param tid       The TreeID we're sending the packets to
--@param fid       The FileID we're sending the packets to
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'arguments', which are the values returned by the server. 
local function call_function(socket, opnum, arguments, uid, tid, fid)
	local i
	local status, result
	local parameters, data
	local pos, align
	local response = {}

	data = bin.pack("<CCCC>I<SSIISSA",
				0x05,        -- Version (major)
				0x00,        -- Version (minor)
				0x00,        -- Packet type (0x00 = request)
				0x03,        -- Packet flags (0x03 = first frag + last frag)
				0x10000000,  -- Data representation (big endian)
				0x18 + string.len(arguments), -- Frag length (0x18 = the size of this data)
				0x0000,      -- Auth length
				0x41414141,  -- Call ID (I use 'AAAA' because it's easy to recognize)
				0x00000100,  -- Alloc hint
				0x0000,      -- Context ID
				opnum,       -- Opnum
				arguments
			)

	stdnse.print_debug(3, "MSRPC: Calling function 0x%02x with %d bytes of arguments", string.len(arguments), opnum)

	-- Pass the information up to the smb layer
	status, result = smb.send_transaction(socket, 0x0026, "", data, uid, tid, fid)
	if(status ~= true) then
		return false, result
	end

	-- Make these easier to access. 
	parameters = result['parameters']
	data       = result['data']

	-- Extract the first part from the resposne
	pos, response['version_major'], response['version_minor'], response['packet_type'], response['packet_flags'], response['data_representation'], response['frag_length'], response['auth_length'], response['call_id'] = bin.unpack("<CCCC>I<SSI", data)

	-- Check if there was an error
	if(response['packet_type'] == 0x03) then -- MSRPC_FAULT
		return false, "MSRPC call returned a fault (packet type)"
	end
	if(bit.band(response['packet_flags'], 0x20) == 0x20) then
		return false, "MSRPC call returned a fault (flags)"
	end
	if(response['auth_length'] ~= 0) then
		return false, "MSRPC call returned an 'auth length', which we don't know how to deal with"
	end
	if(bit.band(response['packet_flags'], 0x03) ~= 0x03) then
		return false, "MSRPC call returned a fragmented packet, which we don't know how to handle"
	end
	if(response['packet_type'] ~= 0x02) then
		return false, "MSRPC call returned an unexpected packet type (not RESPONSE)"
	end
	if(response['call_id'] ~= 0x41414141) then
		return false, "MSRPC call returned an incorrect 'call_id' value"
	end

	-- Extract some more
	pos, response['alloc_hint'], response['context_id'], response['cancel_count'], align = bin.unpack("<ISCC", data, pos)

	-- Rest is the arguments
	response['arguments'] = string.sub(data, pos)
	stdnse.print_debug(3, "MSRPC: Function call successful, %d bytes of returned argumenst", string.len(response['arguments']))

	return true, response

end

---Call the MSRPC function netshareenumall() on the remote system. This function basically returns a list of all the shares
-- on the system. 
--
--@param socket The socket, with a proper MSRPC connection
--@param server The IP or Hostname of the server (seems to be ignored but it's a good idea to have it)
--@param uid    The UserID we're sending the packets as
--@param tid    The TreeID we're sending the packets to
--@param fid    The FileID we're sending the packets to
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'shares', which is a list of the system's shares. 
function srvsvc_netshareenumall(socket, server, uid, tid, fid)
	local i, j
	local status, result
	local arguments
	local pos, align

	local level
	local ctr, referent, count, max_count

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling NetShareEnumAll()")
	server = "\\\\" .. server

-- [in]   [string,charset(UTF16)] uint16 *server_unc
	arguments = bin.pack("<IIIIA",
					REFERENT_ID,            -- Referent ID
					string.len(server) + 1, -- Max count
					0,                      -- Offset
					string.len(server) + 1, -- Actual count
					string_to_unicode(server, true, true)
				)

-- [in,out]   uint32 level
	arguments = arguments .. bin.pack("<I", 0)

-- [in,out,switch_is(level)] srvsvc_NetShareCtr ctr
	arguments = arguments .. bin.pack("<IIII",
					0,          -- Pointer to Ctr
					REFERENT_ID, -- Referent ID
					0,          -- Count
					0           -- Pointer to array
				)

-- [out]  uint32 totalentries
-- [in,out]   uint32 *resume_handle*
	arguments = arguments .. bin.pack("<II", 
					REFERENT_ID, -- Referent ID
					0            -- Resume handle
				)


	-- Do the call
	status, result = call_function(socket, 0x0F, arguments, uid, tid, fid)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(2, "MSRPC: NetShareEnumAll() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']

-- [in]   [string,charset(UTF16)] uint16 *server_unc
-- [in,out]   uint32 level
	pos = 5

-- [in,out,switch_is(level)] srvsvc_NetShareCtr ctr
	local ctr, referent_id, count, max_count
	pos, ctr, referent_id, count, referent_id, max_count = bin.unpack("<IIIII", arguments, pos)
	stdnse.print_debug(5, "MSRPC: NetShareEnumAll: %d entries", count)

	for i = 1, count, 1 do
		pos, referent_id = bin.unpack("<I", arguments, pos)
	end

	-- Initialize the 'shares' part of response
	response['shares'] = {}
	for i = 1, count, 1 do
		local max_size, offset_actual_size
		local share = ""

		pos, max_size, offset, actual_size = bin.unpack("<III", arguments, pos)
		stdnse.print_debug(5, "MSRPC: NetShareEnumAll() entry: max_size = %d, offset = %d, actual_size = %d", max_size, offset, actual_size)

		pos, share = unicode_to_string(arguments, pos, actual_size, true, true)
		stdnse.print_debug(5, "MSRPC: NetShareEnumAll() entry: Name = %s", share)
		response['shares'][#response['shares'] + 1] = share
	end

-- [out]  uint32 totalentries
	pos = pos + 4

-- [in,out]   uint32 *resume_handle
	pos = pos + 4

	-- The return value
	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet"
	end
	if(response['return'] ~= 0) then
		return false, status_to_string(response['return']) .. " (srvsvc.netshareenumall)"
	end

	return true, response
end

---Call the connect4() function, to obtain a "connect handle". This must be done before calling many 
-- of the SAMR functions. 
--
--@param socket The socket, with a proper MSRPC connection
--@param server The IP or Hostname of the server (seems to be ignored but it's a good idea to have it)
--@param uid    The UserID we're sending the packets as
--@param tid    The TreeID we're sending the packets to
--@param fid    The FileID we're sending the packets to
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'connect_handle', which is required to call other functions. 
function samr_connect4(socket, server, uid, tid, fid)
	local i, j
	local status, result
	local arguments
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling Connect4()")

	server = "\\\\" .. server

-- [in,string,charset(UTF16)] uint16 *system_name,
	arguments = bin.pack("<IIIIA",
					REFERENT_ID,            -- Referent ID
					string.len(server) + 1, -- Max count
					0,                      -- Offset
					string.len(server) + 1, -- Actual count
					string_to_unicode(server, true, true)
				)
	
-- [in] uint32 unknown,
	arguments = arguments .. bin.pack("<I", 0x02)

-- [in] samr_ConnectAccessMask access_mask,
	arguments = arguments .. bin.pack("<I", 0x30)
-- [out,ref]  policy_handle *connect_handle


	-- Do the call
	status, result = call_function(socket, 0x3E, arguments, uid, tid, fid)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(2, "MSRPC: Connect4() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']

-- [in,string,charset(UTF16)] uint16 *system_name,
-- [in] uint32 unknown,
-- [in] samr_ConnectAccessMask access_mask,
-- [out,ref]  policy_handle *connect_handle
	pos, response['connect_handle'], response['return'] = bin.unpack("<A20I", arguments)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet"
	end
	if(response['return'] ~= 0) then
		return false, status_to_string(response['return']) .. " (samr.connect4)"
	end

	return true, response
end

---Call the enumdomains() function, which returns a list of all domains in use by the system. 
--
--@param socket         The socket, with a proper MSRPC connection
--@param connect_handle The connect_handle, returned by samr_connect4()
--@param uid            The UserID we're sending the packets as
--@param tid            The TreeID we're sending the packets to
--@param fid            The FileID we're sending the packets to
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'domains', which is a list of the domains. 
function samr_enumdomains(socket, connect_handle, uid, tid, fid)
	local i, j
	local status, result
	local arguments
	local result
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling EnumDomains()")

--		[in,ref]      policy_handle *connect_handle,
	arguments = bin.pack("<A", connect_handle)
	
--		[in,out,ref]  uint32 *resume_handle,
	arguments = arguments .. bin.pack("<I", 0)
--		[in]          uint32 buf_size,
	arguments = arguments .. bin.pack("<I", 0x2000)
--		[out]         samr_SamArray *sam,
--		[out]         uint32 num_entries


	-- Do the call
	status, result = call_function(socket, 0x06, arguments, uid, tid, fid)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(2, "MSRPC: EnumDomains() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']

--		[in,ref]      policy_handle *connect_handle,
--		[in,out,ref]  uint32 *resume_handle,
	pos, result['resume_handle'] = bin.unpack("<I", arguments)
--		[in]          uint32 buf_size,
--		[out]         samr_SamArray *sam,
	local referent_id, count, max_count
	pos, referent_id, count, referent_id, max_count = bin.unpack("<IIII", arguments, pos)
	for i = 1, count, 1 do
		local index, name_length, name_size, referent_id
		pos, index, name_length, name_size, referent_id = bin.unpack("<ISSI", arguments, pos)
	end

	response['domains'] = {}
	for i = 1, count, 1 do
		local max_size, offset_actual_size
		local domain = ""

		pos, max_size, offset, actual_size = bin.unpack("<III", arguments, pos)
		pos, domain = unicode_to_string(arguments, pos, actual_size, false, true)
		response['domains'][#response['domains'] + 1] = domain
	end
	
--		[out]         uint32 num_entries
	pos, response['num_entries'] = bin.unpack("<I", arguments, pos)

	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet"
	end
	if(response['return'] ~= 0) then
		return false, status_to_string(response['return']) .. " (samr.enumdomains)"
	end

	return true, response
end

---Call the LookupDomain() function, which converts a domain's name into its sid, which is
-- required to do operations on the domain. 
--
--@param socket         The socket, with a proper MSRPC connection
--@param connect_handle The connect_handle, returned by samr_connect4()
--@param domain         The name of the domain (all domain names can be obtained with samr_enumdomains())
--@param uid            The UserID we're sending the packets as
--@param tid            The TreeID we're sending the packets to
--@param fid            The FileID we're sending the packets to
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'sid', which is required to call other functions. 
function samr_lookupdomain(socket, connect_handle, domain, uid, tid, fid)
	local i, j
	local status, result
	local arguments
	local pos, align
	local referent_id

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling LookupDomain()")

--		[in,ref]  policy_handle *connect_handle,		
	arguments = bin.pack("<A", connect_handle)

--		[in,ref]  lsa_String *domain_name,
	arguments = arguments .. bin.pack("<SSIIIIA", 
					string.len(domain) * 2, -- Name length
					string.len(domain) * 2, -- Name size
					REFERENT_ID,            -- Referent ID
					string.len(domain),     -- Max count
					0,                      -- Offset
					string.len(domain),     -- Actual count
					string_to_unicode(domain, false, false)
				)
--		[out]     dom_sid2 *sid


	-- Do the call
	status, result = call_function(socket, 0x05, arguments, uid, tid, fid)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(2, "MSRPC: LookupDomain() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']


--		[in,ref]  policy_handle *connect_handle,
--		[in,ref]  lsa_String *domain_name,
--		[out]     dom_sid2 *sid
	response['sid'] = {}
	-- Note that the authority is big endian
	pos, referent_id, response['sid']['count'], response['sid']['revision'], response['sid']['count'], response['sid']['authority_high'], response['sid']['authority'] = bin.unpack("<IICC>SI<", arguments)
	response['sid']['subauthorities'] = {}
	for i = 1, response['sid']['count'], 1 do
		pos, response['sid']['subauthorities'][i] = bin.unpack("<I", arguments, pos)
	end

	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet"
	end
	if(response['return'] ~= 0) then
		return false, status_to_string(response['return']) .. " (samr.lookupdomain)"
	end

	return true, response
end

---Call OpenDomain(), which returns a handle to the domain identified by the given sid. 
-- This is required before calling certain functions. 
--
--@param socket         The socket, with a proper MSRPC connection
--@param connect_handle The connect_handle, returned by samr_connect4()
--@param sid            The sid for the domain, returned by samr_lookupdomain()
--@param uid            The UserID we're sending the packets as
--@param tid            The TreeID we're sending the packets to
--@param fid            The FileID we're sending the packets to
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'domain_handle', which is used to call other functions. 
function samr_opendomain(socket, connect_handle, sid, uid, tid, fid)
	local i, j
	local status, result
	local arguments
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling OpenDomain()")

--		[in,ref]      policy_handle *connect_handle,
	arguments = bin.pack("<A", connect_handle)

--		[in]          samr_DomainAccessMask access_mask,
	arguments = arguments .. bin.pack("<I", 0x305)

--		[in,ref]      dom_sid2 *sid,
	-- Note that the "authority" is big endian
	arguments = arguments .. bin.pack("<ICC>SI<", sid['count'], sid['revision'], sid['count'], sid['authority_high'], sid['authority'])
	for i = 1, sid['count'], 1 do
		arguments = arguments .. bin.pack("<I", sid['subauthorities'][i])
	end

--		[out,ref]     policy_handle *domain_handle


	-- Do the call
	status, result = call_function(socket, 0x07, arguments, uid, tid, fid)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(2, "MSRPC: OpenDomain() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']


--		[in,ref]      policy_handle *connect_handle,
--		[in]          samr_DomainAccessMask access_mask,
--		[in,ref]      dom_sid2 *sid,
--		[out,ref]     policy_handle *domain_handle
	pos, response['domain_handle'], response['return'] = bin.unpack("<A20I", arguments)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet"
	end
	if(response['return'] ~= 0) then
		return false, status_to_string(response['return']) .. " (samr.opendomain)"
	end
	
	return true, response
end

---Call EnumDomainUsers(), which returns a list of users only. To get more information about the users, the 
-- QueryDisplayInfo() function can be used. 
function samr_enumdomainusers(socket, domain_handle, uid, tid, fid)
	local i, j
	local status, result
	local arguments
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling EnumDomainUsers()")

--		[in,ref]      policy_handle *domain_handle,
	arguments = bin.pack("<A", domain_handle)

--		[in,out,ref]  uint32 *resume_handle,
	arguments = arguments .. bin.pack("<I", 0)

--		[in]          samr_AcctFlags acct_flags,
	arguments = arguments .. bin.pack("<I", 0)

--		[in]          uint32 max_size,
	arguments = arguments .. bin.pack("<I", 0x0400)

--		[out]         samr_SamArray *sam,
--		[out]         uint32 num_entries


	-- Do the call
	status, result = call_function(socket, 0x0d, arguments, uid, tid, fid)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(2, "MSRPC: EnumDomainUsers() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']

--		[in,ref]      policy_handle *domain_handle,
--		[in,out,ref]  uint32 *resume_handle,
	pos, response['resume_handle'] = bin.unpack("<I", arguments)

--		[in]          samr_AcctFlags acct_flags,
--		[in]          uint32 max_size,
--		[out]         samr_SamArray *sam,
	local referent_id, count, max_count

	pos, referent_id, count, referent_id, max_count = bin.unpack("<IIII", arguments, pos)
	for i = 1, count, 1 do
		local rid, name_len, name_size
		pos, rid, name_len, name_size, referent_id = bin.unpack("<ISSI", arguments, pos)
	end

	response['names'] = {}
	for i = 1, count, 1 do
		local max_count, offset, actual_count
		pos, max_count, offset, actual_count = bin.unpack("<III", arguments, pos)
		pos, response['names'][#response['names'] + 1]   = unicode_to_string(arguments, pos, actual_count, false, true)
	end
--		[out]         uint32 num_entries
	pos, response['num_entries'] = bin.unpack("<I", arguments, pos)

	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet"
	end
	if(response['return'] ~= 0) then
		return false, status_to_string(response['return']) .. " (samr.enumdomainusers)"
	end
	
	return true, response

end

---Call QueryDisplayInfo(), which returns a list of users with accounts on the system, as well as extra information about
-- them (their full name and description). \n
--\n
-- I found in testing that trying to get all the users at once is a mistake, it returns ERR_BUFFER_OVERFLOW, so instead I'm 
-- only reading one user at a time, in a loop. So one call to this will actually send out a number of packets equal to the 
-- number of users on the system. \n
--
--@param socket         The socket, with a proper MSRPC connection
--@param domain_handle  The domain handle, returned by samr_opendomain()
--@param uid            The UserID we're sending the packets as
--@param tid            The TreeID we're sending the packets to
--@param fid            The FileID we're sending the packets to
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful ones being 'names', a list of all the usernames, and 'details', a further list of tables with the elements
--        'name', 'fullname', and 'description' (note that any of them can be nil if the server didn't return a value). Finally,
--        'flags' is the numeric flags for the user, while 'flags_list' is an array of strings, representing the flags.
function samr_querydisplayinfo(socket, domain_handle, uid, tid, fid)
	local i, j
	local status, result
	local arguments
	local pos, align
	local function_return

	local response = {}
	response['names'] = {}
	response['details'] = {}

	-- This loop is because, in my testing, if I asked for all the results at once, it would blow up (ERR_BUFFER_OVERFLOW). So, instead,
	-- I put a little loop here and grab the names individually. 
	i = 0
	repeat
		stdnse.print_debug(2, "MSRPC: Calling QueryDisplayInfo() [index = %d]", i)

--		[in,ref]    policy_handle *domain_handle,
		arguments = bin.pack("<A", domain_handle)

--		[in]        uint16 level,
		arguments = arguments .. bin.pack("<SS", 
					0x0001, -- Level
					0x0000  -- Padding
				)

--		[in]        uint32 start_idx,
		arguments = arguments .. bin.pack("<I", i)

--		[in]        uint32 max_entries,
		arguments = arguments .. bin.pack("<I", 1)

--		[in]        uint32 buf_size,
		arguments = arguments .. bin.pack("<I", 0)

--		[out]       uint32 total_size,
--		[out]       uint32 returned_size,
--		[out,switch_is(level)] samr_DispInfo info


		-- Do the call
		status, result = call_function(socket, 0x28, arguments, uid, tid, fid)
		if(status ~= true) then
			return false, result
		end
	
		stdnse.print_debug(2, "MSRPC: QueryDisplayInfo() returned successfully", i)

		-- Make arguments easier to use
		arguments = result['arguments']

--		[in,ref]    policy_handle *domain_handle,
--		[in]        uint16 level,
--		[in]        uint32 start_idx,
--		[in]        uint32 max_entries,
--		[in]        uint32 buf_size,
--		[out]       uint32 total_size,
		pos = 5
--		[out]       uint32 returned_size,
		pos = pos + 4
--		[out,switch_is(level)] samr_DispInfo info
		local info, padding, count, referent_id, max_count, index
		local name_length, name_size, name_ptr, fullname_length, fullname_size, fullname_ptr, description_length, description_size, description_ptr
		local queryresult = {}

		pos, info, padding, count, referent_id, max_count, index = bin.unpack("<SSIIII", arguments, pos)
		pos, queryresult['rid'], queryresult['flags'] = bin.unpack("<II", arguments, pos)

		-- Convert the flags to something more useable
		queryresult['flags_list'] = {}
		if(bit.band(queryresult['flags'], 0x00000010) ~= 0) then queryresult['flags_list'][#queryresult['flags_list'] + 1] = "Normal account" end
		if(bit.band(queryresult['flags'], 0x00000001) ~= 0) then queryresult['flags_list'][#queryresult['flags_list'] + 1] = "Disabled" end
		if(bit.band(queryresult['flags'], 0x00000004) ~= 0) then queryresult['flags_list'][#queryresult['flags_list'] + 1] = "Password not required" end
		if(bit.band(queryresult['flags'], 0x00000200) ~= 0) then queryresult['flags_list'][#queryresult['flags_list'] + 1] = "Password doesn't expire" end
		if(bit.band(queryresult['flags'], 0x00000002) ~= 0) then queryresult['flags_list'][#queryresult['flags_list'] + 1] = "Home directory required (HOMDIRREQ)" end
		if(bit.band(queryresult['flags'], 0x00000008) ~= 0) then queryresult['flags_list'][#queryresult['flags_list'] + 1] = "Temporary duplicate account (ACB_TEMPDUP)" end
		if(bit.band(queryresult['flags'], 0x00000020) ~= 0) then queryresult['flags_list'][#queryresult['flags_list'] + 1] = "MNS login account (ACB_MNS)" end
		if(bit.band(queryresult['flags'], 0x00000040) ~= 0) then queryresult['flags_list'][#queryresult['flags_list'] + 1] = "Interdomain trust account" end
		if(bit.band(queryresult['flags'], 0x00000080) ~= 0) then queryresult['flags_list'][#queryresult['flags_list'] + 1] = "Workstation trust account" end
		if(bit.band(queryresult['flags'], 0x00000100) ~= 0) then queryresult['flags_list'][#queryresult['flags_list'] + 1] = "Server trust account" end
		if(bit.band(queryresult['flags'], 0x00000400) ~= 0) then queryresult['flags_list'][#queryresult['flags_list'] + 1] = "Account auto locked (ACB_AUTOLOCK)" end
		if(bit.band(queryresult['flags'], 0x00000800) ~= 0) then queryresult['flags_list'][#queryresult['flags_list'] + 1] = "Encrypted text password allowed (ACB_ENC_TXT_PWD_ALLOWED?)" end
		if(bit.band(queryresult['flags'], 0x00001000) ~= 0) then queryresult['flags_list'][#queryresult['flags_list'] + 1] = "Smartcard required" end
		if(bit.band(queryresult['flags'], 0x00002000) ~= 0) then queryresult['flags_list'][#queryresult['flags_list'] + 1] = "Trusted for delegation" end
		if(bit.band(queryresult['flags'], 0x00004000) ~= 0) then queryresult['flags_list'][#queryresult['flags_list'] + 1] = "Not delegated" end
		if(bit.band(queryresult['flags'], 0x00008000) ~= 0) then queryresult['flags_list'][#queryresult['flags_list'] + 1] = "Use DES key only" end
		if(bit.band(queryresult['flags'], 0x00010000) ~= 0) then queryresult['flags_list'][#queryresult['flags_list'] + 1] = "Don't require preauth" end
		if(bit.band(queryresult['flags'], 0x00020000) ~= 0) then queryresult['flags_list'][#queryresult['flags_list'] + 1] = "Password is expired" end
		if(bit.band(queryresult['flags'], 0x00080000) ~= 0) then queryresult['flags_list'][#queryresult['flags_list'] + 1] = "No auth data required" end

		pos, name_length, name_size, name_ptr, fullname_length, fullname_size, fullname_ptr, description_length, description_size, description_ptr = bin.unpack("<SSISSISSI", arguments, pos)
	
		if(name_ptr ~= 0) then
			local length, offset, count
			pos, length, offset, count = bin.unpack("<III", arguments, pos)
			pos, queryresult['name']   = unicode_to_string(arguments, pos, length, false, true)
		end

		if(fullname_ptr ~= 0) then
			local length, offset, count
			pos, length, offset, count = bin.unpack("<III", arguments, pos)
			pos, queryresult['fullname']   = unicode_to_string(arguments, pos, length, false, true)
		end

		if(description_ptr ~= 0) then
			local length, offset, count
			pos, length, offset, count = bin.unpack("<III", arguments, pos)
			pos, queryresult['description']   = unicode_to_string(arguments, pos, length, false, true)
		end

		-- Add the array to the return value
		response['details'][i + 1] = queryresult
		-- Add the name, as well (to make it easier for scripts to just grab a list of names)
		response['names'][#response['names'] + 1] = queryresult['name']

		-- Get the return value
		pos, function_returned = bin.unpack("<I", arguments, pos)
		if(function_returned == nil) then
			return false, "Read off the end of the packet"
		end
		if(function_returned ~= 0 and function_returned ~= STATUS_MORE_ENTRIES) then
			return false, status_to_string(function_returned) .. " (samr.querydisplayall)"
		end

		-- Increment the index (very important!)
		i = i + 1

	-- Keep looping as long as there are more entries. 
	until function_returned ~= 0x00000105 -- STATUS_MORE_ENTRIES
	
	return true, response
end

---Call QueryDomainInfo2(), which grabs various data about a domain. 
--
--@param socket         The socket, with a proper MSRPC connection
--@param domain_handle  The domain_handle, returned by samr_opendomain()
--@param level          The level, which determines which type of information to query for. See the @return section
--                      for details. 
--@param uid            The UserID we're sending the packets as
--@param tid            The TreeID we're sending the packets to
--@param fid            The FileID we're sending the packets to
--@param response       [optional] A 'result' to add the entries to. This lets us call this function multiple times, 
--                      for multiple levels, and keep the results in one place. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, 
--        and the values that are returned are dependent on the 'level' settings:\n
--        Level 1:\n
--         'min_password_length' (in characters)\n
--         'password_history_length' (in passwords)\n
--         'password_properties'\n
--         'password_properties_list' (array of strings)\n
--         'max_password_age' (in days)\n
--         'min_password_age' (in days)\n
--        Level 8\n
--         'create_time' (1/10ms since 1601)\n
--         'create_date' (string)\n
--        Level 12\n
--         'lockout_duration' (in minutes)\n
--         'lockout_window' (in minutes)\n
--         'lockout_threshold' (in attempts)\n
function samr_querydomaininfo2(socket, domain_handle, level, uid, tid, fid, response)
	local i, j
	local status, result
	local arguments
	local pos, align

	if(response == nil) then
		response = {}
	end

	stdnse.print_debug(2, "MSRPC: Calling QueryDomainInfo2()")

--		[in,ref]      policy_handle *domain_handle,
	arguments = bin.pack("<A", domain_handle)

--		[in]          uint16 level,
	arguments = arguments .. bin.pack("<S", level) -- 0 = padding/alignment

--		[out,switch_is(level)] samr_DomainInfo *info

	-- Do the call
	status, result = call_function(socket, 0x2e, arguments, uid, tid, fid)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(2, "MSRPC: QueryDomainInfo2() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']

--		[in,ref]      policy_handle *domain_handle,
--		[in]          uint16 level,
--		[out,switch_is(level)] samr_DomainInfo *info
	if(level == 1) then
		local referent_id, info

		-- Note that password ages are signed values (we don't use signed values often)
		pos, referent_id, info, align, response['min_password_length'], response['password_history_length'], response['password_properties'], response['max_password_age'], response['min_password_age'] = bin.unpack("<ISSSSIll", arguments)

		-- Parse out the flags
		response['password_properties_list'] = {}
		if(bit.band(response['password_properties'], 0x00000001) == 0x00000001) then
			response['password_properties_list'][#response['password_properties_list'] + 1] = "Password complexity requirements exist"
		else
			response['password_properties_list'][#response['password_properties_list'] + 1] = "Password complexity requirements do not exist"
		end
		if(bit.band(response['password_properties'], 0x00000002) == 0x00000002) then
			response['password_properties_list'][#response['password_properties_list'] + 1] = "DOMAIN_PASSWORD_NO_ANON_CHANGE"
		end
		if(bit.band(response['password_properties'], 0x00000004) == 0x00000004) then
			response['password_properties_list'][#response['password_properties_list'] + 1] = "DOMAIN_PASSWORD_NO_CLEAR_CHANGE"
		end
		if(bit.band(response['password_properties'], 0x00000008) == 0x00000008) then
			response['password_properties_list'][#response['password_properties_list'] + 1] = "Administrator account can be locked out"
		else
			response['password_properties_list'][#response['password_properties_list'] + 1] = "Administrator account cannot be locked out"
		end
		if(bit.band(response['password_properties'], 0x00000010) == 0x00000010) then
			response['password_properties_list'][#response['password_properties_list'] + 1] = "Passwords can be stored in reversible encryption"
		end
		if(bit.band(response['password_properties'], 0x00000020) == 0x00000020) then
			response['password_properties_list'][#response['password_properties_list'] + 1] = "DOMAIN_REFUSE_PASSWORD_CHANGE"
		end

		-- Make the max/min ages saner
		response['max_password_age'] = response['max_password_age'] / -864000000000
		response['min_password_age'] = response['min_password_age'] / -864000000000
	elseif(level == 8) then
		local referent_id, info, sequence_num
	
		pos, referent_id, info, align, response['sequence_num'], response['create_time'] = bin.unpack("<ISSLL", arguments)
		response['create_date'] = os.date("%Y-%m-%d %H:%M:%S", (response['create_time'] / 10000000) - 11644473600)
	elseif(level == 12) then
		local referent_id, info

		-- Note that the lockout duration/window are signed values
		pos, referent_id, info, align, response['lockout_duration'], response['lockout_window'], response['lockout_threshold'], align = bin.unpack("<ISSllSS", arguments)
		response['lockout_duration'] = response['lockout_duration'] / -600000000
		response['lockout_window'] = response['lockout_window'] / -600000000
	else
		return false, string.format("Don't know how to parse the requested level (%d)", level)
	end

	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet"
	end
	if(response['return'] ~= 0) then
		return false, status_to_string(response['return']) .. " (samr.querydomaininfo2)"
	end
	
	return true, response
end

---Call the close() function, which closes a handle of any type (for example, domain_handle or connect_handle)
--@param socket The socket, with a proper MSRPC connection
--@param handle The handle to close
--@param uid    The UserID we're sending the packets as
--@param tid    The TreeID we're sending the packets to
--@param fid    The FileID we're sending the packets to
--@return (status, result) If status is false, result is an error message. Otherwise, result is potentially
--        a table of values, none of which are likely to be used. 
function samr_close(socket, handle, uid, tid, fid)
	local i, j
	local status, result
	local arguments
	local pos, align
	local response = {}


	stdnse.print_debug(2, "MSRPC: Calling Close()")

--		[in,out,ref]  policy_handle *handle
	arguments = bin.pack("<A", handle)

	-- Do the call
	status, result = call_function(socket, 0x01, arguments, uid, tid, fid)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(2, "MSRPC: Close() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']

--		[in,out,ref]  policy_handle *handle
	pos, response['handle'] = bin.unpack("<A16", arguments)

	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet"
	end
	if(response['return'] ~= 0) then
		return false, status_to_string(response['return']) .. " (samr.close)"
	end
	
	return true, response
end

---Call the LsarOpenPolicy2() function, to obtain a "policy handle". This must be done before calling many 
-- of the LSA functions. 
--
--@param socket The socket, with a proper MSRPC connection
--@param server The IP or Hostname of the server (seems to be ignored but it's a good idea to have it)
--@param uid    The UserID we're sending the packets as
--@param tid    The TreeID we're sending the packets to
--@param fid    The FileID we're sending the packets to
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'policy_handle', which is required to call other functions. 
function lsa_openpolicy2(socket, server, uid, tid, fid)
	local i, j
	local status, result
	local arguments
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling LsarOpenPolicy2()")

--		[in,unique]      [string,charset(UTF16)] uint16 *system_name,

	arguments = bin.pack("<IIIIA",
					REFERENT_ID,            -- Referent ID
					string.len(server) + 1, -- Max count
					0,                      -- Offset
					string.len(server) + 1, -- Actual count
					string_to_unicode(server, true, true)
				)

--		[in]  lsa_ObjectAttribute *attr,
	arguments = arguments .. bin.pack("<IIIIIIISCC", 
					24,                     -- "Attributes" length
					0,                      -- LSPTR pointer
					0,                      -- NAME pointer
					0,                      -- Attributes
					0,                      -- LSA_SECURITY_DESCRIPTOR pointer
					REFERENT_ID,            -- QoS pointer
					12,                     -- Length of QoS pointer
					2,                      -- Impersonation level
					1,                      -- Context tracking
					0                       -- Effective only
				)

--		[in]      uint32 access_mask,
	arguments = arguments .. bin.pack("<I", 0x00000800)

--		[out] policy_handle *handle	

	-- Do the call
	status, result = call_function(socket, 0x2C, arguments, uid, tid, fid)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(2, "MSRPC: LsarOpenPolicy2() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']

--		[in,unique]      [string,charset(UTF16)] uint16 *system_name,
--		[in]  lsa_ObjectAttribute *attr,
--		[in]      uint32 access_mask,
--		[out] policy_handle *handle	
	pos, response['policy_handle'], response['return'] = bin.unpack("<A20I", arguments)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet"
	end
	if(response['return'] ~= 0) then
		return false, status_to_string(response['return']) .. " (lsa.openpolicy2)"
	end

	return true, response
end

---Call the LsarLookupNames2() function, to convert the server's name into a sid. 
--
--@param socket The socket, with a proper MSRPC connection
--@param policy_handle The policy handle returned by lsa_openpolicy2()
--@param names  An array of names to look up. To get a SID, only one of the names needs to be valid. 
--@param uid    The UserID we're sending the packets as
--@param tid    The TreeID we're sending the packets to
--@param fid    The FileID we're sending the packets to
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values. 
--        The most useful result is 'domains', which is a list of domains known to the server. And, for each of the
--        domains, there is a 'name' entry, which is a string, and a 'sid' entry, which is yet another object which
--        can be passed to functions that understand SIDs. 
function lsa_lookupnames2(socket, policy_handle, names, uid, tid, fid)
	local i, j
	local status, result
	local arguments
	local result
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling LsarLookupNames2()")


--		[in]     policy_handle *handle,
	arguments = bin.pack("<A", policy_handle)

--		[in,range(0,1000)] uint32 num_names,
	arguments = arguments .. bin.pack("<I", #names)

--		[in,size_is(num_names)]  lsa_String names[],
	arguments = arguments .. bin.pack("<I", #names) -- Max count

	for i = 1, #names, 1 do
		arguments = arguments .. bin.pack("<SSI", 
							string.len(names[i]) * 2,  -- Name length
							string.len(names[i]) * 2,  -- Name size
							REFERENT_ID                -- Referent ID
						)
	end

	for i = 1, #names, 1 do
		arguments = arguments .. bin.pack("<IIIA", 
							string.len(names[i]),                    -- Max count
							0,                                       -- Offset
							string.len(names[i]),                    -- Actual count
							string_to_unicode(names[i], false, true) -- Account
						)
	end

--		[out,unique]        lsa_RefDomainList *domains,
--		[in,out] lsa_TransSidArray2 *sids,
	arguments = arguments .. bin.pack("<II",
							1,   -- Count
							0    -- Translated sids pointer
						)

--		[in]         lsa_LookupNamesLevel level,
	arguments = arguments .. bin.pack("<SS", 
							1,   -- Level
							0    -- Padding/alignment
						)

--		[in,out] uint32 *count,
	arguments = arguments .. bin.pack("<I", 0)

--		[in]         uint32 unknown1,
	arguments = arguments .. bin.pack("<I", 0)

--		[in]         uint32 unknown2
	arguments = arguments .. bin.pack("<I", 2)



	-- Do the call
	status, result = call_function(socket, 0x3a, arguments, uid, tid, fid)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(2, "MSRPC: LsarLookupNames2() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']


--		[in]     policy_handle *handle,
--		[in,range(0,1000)] uint32 num_names,
--		[in,size_is(num_names)]  lsa_String names[],
--		[out,unique]        lsa_RefDomainList *domains,
	local referent_id, count, max_count
	pos, referent_id, count, referent_id, max_count = bin.unpack("<IIII", arguments)

	if(max_count ~= 0) then

		pos, max_count = bin.unpack("<I", arguments, pos)

		for i = 1, count, 1 do
			local length, size, referent_id
			pos, length, size, referent_id, referent_id = bin.unpack("<SSII", arguments, pos)
		end
	
		response['domains'] = {}
		for i = 1, count, 1 do
			response['domains'][i] = {}
			response['domains'][i]['sid'] = {}
	
			-- The name
			local max_count, offset, actual_count, sid_count
			pos, max_count, offset, actual_count = bin.unpack("<III", arguments, pos)
			pos, response['domains'][i]['name'] = unicode_to_string(arguments, pos, actual_count, false, true)
	
			-- The SID
			local sid = {}
			-- Note that the authority is big endian
			pos, sid['count'], sid['revision'], sid['count'], sid['authority_high'], sid['authority'] = bin.unpack("<ICC>SI<", arguments, pos)
			sid['subauthorities'] = {}
			for i = 1, sid['count'], 1 do
				pos, sid['subauthorities'][i] = bin.unpack("<I", arguments, pos)
			end
			response['domains'][i]['sid'] = sid
		
		end
	end

--		[in,out] lsa_TransSidArray2 *rids,
	local count, referent_id, max_count

	pos, count, referent_id, max_count = bin.unpack("<III", arguments, pos)

	response['users'] = {}
	for i = 1, count, 1 do
		response['users'][i] = {}
		response['users'][i]['name'] = names[i]

		pos, response['users'][i]['type'], align, response['users'][i]['rid'], response['users'][i]['index'], response['users'][i]['unknown'] = bin.unpack("<SSIII", arguments, pos)
	end
	
--		[in]         lsa_LookupNamesLevel level,
--		[in,out] uint32 *count,
	local count
	pos, count = bin.unpack("<I", arguments, pos)
--		[in]         uint32 unknown1,
--		[in]         uint32 unknown2


	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet"
	end
	if(response['return'] == STATUS_NONE_MAPPED) then
		return false, "Couldn't find any names the host recognized"
	end

	if(response['return'] ~= 0 and response['return'] ~= STATUS_SOME_NOT_MAPPED) then
		return false, status_to_string(response['return']) .. " (lsa.lookupnames2)"
	end

	return true, response
end

---Call the LsarLookupSids2() function, to convert a list of SIDs to their names
--
--@param socket The socket, with a proper MSRPC connection
--@param policy_handle The policy handle returned by lsa_openpolicy2()
--@param sid    The SID object for the server
--@param rids   The RIDs of users to look up
--@param uid    The UserID we're sending the packets as
--@param tid    The TreeID we're sending the packets to
--@param fid    The FileID we're sending the packets to
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values. 
--        The element 'domains' is identical to the lookupnames2() element called 'domains'. The element 'names' is a 
--        list of strings, for the usernames (not necessary a 1:1 mapping with the RIDs), and the element 'details' is
--        a table containing more information about each name, even if the name wasn't found (this one is a 1:1 mapping
--        with the RIDs). 
function lsa_lookupsids2(socket, policy_handle, sid, rids, uid, tid, fid)
	local i, j
	local status, result
	local arguments
	local result
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling LsarLookupSids2()")

--		[in]     policy_handle *handle,
	arguments = bin.pack("<A", policy_handle)
	
--		[in]     lsa_SidArray *sids,
	arguments = arguments .. bin.pack("<I", #rids) -- count
	arguments = arguments .. bin.pack("<I", REFERENT_ID)
	arguments = arguments .. bin.pack("<I", #rids) -- max_count

	for i = 1, #rids, 1 do
		arguments = arguments .. bin.pack("<I", REFERENT_ID)
	end

	for i = 1, #rids, 1 do
		arguments = arguments .. bin.pack("I<CC>SI<", sid['count'] + 1, sid['revision'], sid['count'] + 1, sid['authority_high'], sid['authority'])
		for j = 1, sid['count'], 1 do
			arguments = arguments .. bin.pack("<I", sid['subauthorities'][j])
		end
		arguments = arguments .. bin.pack("<I", rids[i])
	end

--		[out,unique]        lsa_RefDomainList *domains,
--		[in,out] lsa_TransNameArray2 *names,
	arguments = arguments .. bin.pack("<II", 0, 0)

--		[in]         uint16 level,
	arguments = arguments .. bin.pack("<SS", 1, 0)

--		[in,out] uint32 *count,
	arguments = arguments .. bin.pack("<I", 0)

--		[in]         uint32 unknown1,
	arguments = arguments .. bin.pack("<I", 0)

--		[in]         uint32 unknown2
	arguments = arguments .. bin.pack("<I", 2)


	-- Do the call
	status, result = call_function(socket, 0x39, arguments, uid, tid, fid)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(2, "MSRPC: LsarLookupSids2() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']


--		[in]     policy_handle *handle,
--		[in]     lsa_SidArray *sids,
--		[out,unique]        lsa_RefDomainList *domains,
	local referent_id, count, max_count
	pos, referent_id, count, referent_id, max_count = bin.unpack("<IIII", arguments)

	stdnse.print_debug(5, "MSRPC: LsarLookupSids2(): Processing domains")
	response['domains'] = {}
	if(max_count ~= 0) then

		pos, max_count = bin.unpack("<I", arguments, pos)

		for i = 1, count, 1 do
			local length, size, referent_id
			pos, length, size, referent_id, referent_id = bin.unpack("<SSII", arguments, pos)
		end
	
		response['domains'] = {}
		for i = 1, count, 1 do
			response['domains'][i] = {}
			response['domains'][i]['sid'] = {}
	
			-- The name
			local max_count, offset, actual_count, sid_count
			pos, max_count, offset, actual_count = bin.unpack("<III", arguments, pos)
stdnse.print_debug(5, "MSRPC: LsarLookupSids2(): C")
			pos, response['domains'][i]['name'] = unicode_to_string(arguments, pos, actual_count, false, true)
stdnse.print_debug(5, "MSRPC: LsarLookupSids2(): D")
	
			-- The SID
			local sid = {}
			-- Note that the authority is big endian
			pos, sid['count'], sid['revision'], sid['count'], sid['authority_high'], sid['authority'] = bin.unpack("<ICC>SI<", arguments, pos)
			sid['subauthorities'] = {}
			for i = 1, sid['count'], 1 do
				pos, sid['subauthorities'][i] = bin.unpack("<I", arguments, pos)
			end
			response['domains'][i]['sid'] = sid
		
		end
	end

--		[in,out] lsa_TransNameArray2 *names,
	local count, referent_id, max_count

	pos, count, referent_id, max_count = bin.unpack("<III", arguments, pos)

	stdnse.print_debug(5, "MSRPC: LsarLookupSids2(): Processing %d name headers", count)
	response['details'] = {}
	for i = 1, count, 1 do
		local name_length, name_size, referent_id
		response['details'][i] = {}
		pos, response['details'][i]['type'], align, name_length, name_size, referent_id, response['details'][i]['index'], response['details'][i]['unknown'] = bin.unpack("<SSSSIII", arguments, pos)
	end

	stdnse.print_debug(5, "MSRPC: LsarLookupSids2(): Processing %d name values", count)
	response['names'] = {}
	for i = 1, count, 1 do
		if(response['details'][i]['type'] == 1) then -- 1 = user acount, 6 = deleted account, 8 = not found
			local max_count, offset, actual_count
------------------

			pos, max_count, offset, actual_count = bin.unpack("<III", arguments, pos)
			pos, response['names'][#response['names'] + 1]   = unicode_to_string(arguments, pos, actual_count, false, true)
			response['details'][i]['name'] = response['names'][#response['names']]
		end
	end

--		[in]         uint16 level,
--		[in,out] uint32 *count,
	local count
	pos, count = bin.unpack("<I", arguments, pos)

--		[in]         uint32 unknown1,
--		[in]         uint32 unknown2

	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet"
	end
	if(response['return'] ~= 0 and response['return'] ~= STATUS_SOME_NOT_MAPPED and response['return'] ~= STATUS_NONE_MAPPED) then
		return false, status_to_string(response['return']) .. " (lsa.lookupnames2)"
	end

	stdnse.print_debug(5, "MSRPC: LsarLookupSids2(): Returning")
	return true, response

end

---Call the close() function, which closes a session created with a lsa_openpolicy()-style function
--@param socket The socket, with a proper MSRPC connection
--@param handle The handle to close
--@param uid    The UserID we're sending the packets as
--@param tid    The TreeID we're sending the packets to
--@param fid    The FileID we're sending the packets to
--@return (status, result) If status is false, result is an error message. Otherwise, result is potentially
--        a table of values, none of which are likely to be used. 
function lsa_close(socket, handle, uid, tid, fid)
	local i, j
	local status, result
	local arguments
	local pos, align
	local response = {}


	stdnse.print_debug(2, "MSRPC: Calling LsaClose()")

--		[in,out]     policy_handle *handle
	arguments = bin.pack("<A", handle)

	-- Do the call
	status, result = call_function(socket, 0x00, arguments, uid, tid, fid)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(2, "MSRPC: LsaClose() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']

--		[in,out]     policy_handle *handle
	pos, response['handle'] = bin.unpack("<A16", arguments)

	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet"
	end
	if(response['return'] ~= 0) then
		return false, status_to_string(response['return']) .. " (lsa.close)"
	end
	
	return true, response
end
