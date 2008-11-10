--- Call various MSRPC functions.
--
-- This library gives support for calling various MSRPC functions, making heavy
-- use of the <code>smb</code> library.
-- The functions used here can be accessed over TCP ports 445 and 139, 
--  with an established session. A NULL session (the default) will work for some 
--  functions and operating systems (or configurations), but not for others. 
--
-- To make use of these function calls, a SMB session with the server has to be
-- established. This can be done manually with the <code>smb</code> library, or the function
-- <code>start_smb</code> can be called. 
--
-- Next, the interface has to be bound. The <code>bind</code> function will take care of that. 
--
-- After that, you're free to call any function that's part of that interface. In
-- other words, if you bind to the SAMR interface, you can only call the samr_
-- functions, for lsa_ functions, bind to the LSA interface, etc.
--
-- Although functions can be called in any order, many functions depend on the
-- value returned by other functions. I indicate those in the function comments, 
-- so keep an eye out.
--
-- Something to note is that these functions, for the most part, return a whole ton
-- of stuff in a table. I basically wrote them to return every possible value
-- they get their hands on. I don't expect that most of them will be used, and I'm 
-- not going to document them all in the function header; rather, I will document
-- the elements in the table that are more useful, you'll have to look at the actual
-- code (or the table) to see what else is available.
--
-- When implementing this, I used Wireshark's output significantly, as well as Samba's
-- "idl" files for reference:
--  http://websvn.samba.org/cgi-bin/viewcvs.cgi/branches/SAMBA_4_0/source/librpc/idl/ 
-- I'm not a lawyer, but I don't expect that this is a breach of Samba's copyright -- 
-- if it is, please talk to me and I'll make arrangements to re-license this or to 
-- remove references to Samba. 
--
--@author Ron Bowes <ron@skullsecurity.net>
--@copyright Same as Nmap--See http://nmap.org/book/man-legal.html
-----------------------------------------------------------------------
module(... or "msrpc", package.seeall)

require 'bit'
require 'bin'
require 'netbios'
require 'smb'
require 'stdnse'

-- The path, UUID, and version for SAMR
SAMR_PATH       = "\\samr"
SAMR_UUID       = string.char(0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xac)
SAMR_VERSION    = 0x01

-- The path, UUID, and version for SRVSVC
SRVSVC_PATH     = "\\srvsvc"
SRVSVC_UUID     = string.char(0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88)
SRVSVC_VERSION  = 0x03

-- The path, UUID, and version for LSA
LSA_PATH        = "\\lsarpc"
LSA_UUID        = string.char(0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab)
LSA_VERSION     = 0

-- The path, UUID, and version for WINREG
WINREG_PATH     = "\\winreg"
WINREG_UUID     = string.char(0x01, 0xd0, 0x8c, 0x33, 0x44, 0x22, 0xf1, 0x31, 0xaa, 0xaa, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03)
WINREG_VERSION  = 1

-- This is the only transfer syntax I've seen in the wild, not that I've looked hard. It seems to work well. 
TRANSFER_SYNTAX = string.char(0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60)

-- The 'referent_id' value is ignored, as far as I can tell, so this value is passed for it. No, it isn't random. :)
REFERENT_ID = 0x50414d4e

--- Convert a string to fake unicode (ascii with null characters between them), optionally add a null terminator, 
--  and optionally align it to 4-byte boundaries. This is frequently used in MSRPC calls, so I put it here, but
--  it might be a good idea to move this function (and the converse one below) into a separate library. 
--
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

--- Read a unicode string from a buffer, similar to how <code>bin.unpack</code> would, optionally eat the null terminator, 
--  and optionally align it to 4-byte boundaries. 
--
--@param buffer   The buffer to read from, typically the full 'arguments' value for MSRPC
--@param pos      The position in the buffer to start (just like <code>bin.unpack</code>)
--@param length   The number of ascii characters that will be read (including the null, if do_null is set). 
--@param do_null  [optional] Remove a null terminator from the string as the last character. Default false. 
--@param do_align [optional] Ensure that the number of bytes removed is a multiple of 4. 
--@return (pos, string) The new position and the string read, again imitating <code>bin.unpack</code>. If there was an 
--                attempt to read off the end of the string, then 'nil' is returned for both parameters. 
local function unicode_to_string(buffer, pos, length, do_null, do_align)
	local i, ch, dummy
	local string = ""

	stdnse.print_debug(3, "MSRPC: Entering unicode_to_string(pos = %d, length = %d)", pos, length)

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

		if(ch == nil or dummy == nil) then
			stdnse.print_debug(1, "Error: ran off the end of a string in unicode_to_string(), this likely means we are reading a packet incorrectly. Please report! (pos = %d, j = %d, length = %d)", pos, j, length)
			return nil, nil
		else
			string = string .. string.char(ch)
		end
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

	stdnse.print_debug(3, "MSRPC: Exiting unicode_to_string()", i, count)

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

---Convert a SID string in the standard representation to the equivalent table. 
--
--This code is sensible, but a little obtuse -- I'm open to suggestions on how to improve it.
--
--@param sid A SID string
--@return A table representing the SID
function string_to_sid(sid)
	local i
	local pos, pos_next
	local result = {}


	if(string.find(sid, "^S-") == nil) then
		return nil
	end
	if(string.find(sid, "-%d+$") == nil) then
		return nil
	end

	pos = 3

	pos_next = string.find(sid, "-", pos)
	result['revision'] = string.sub(sid, pos, pos_next - 1)

	pos = pos_next + 1
	pos_next = string.find(sid, "-", pos)
	result['authority_high'] = bit.rshift(string.sub(sid, pos, pos_next - 1), 32)
	result['authority']      = bit.band(string.sub(sid, pos, pos_next - 1), 0xFFFFFFFF)

	result['subauthorities'] = {}
	i = 1
	repeat
		pos = pos_next + 1
		pos_next = string.find(sid, "-", pos)
		if(pos_next == nil) then
			result['subauthorities'][i] = string.sub(sid, pos)
		else
			result['subauthorities'][i] = string.sub(sid, pos, pos_next - 1)
		end
		i = i + 1
	until pos_next == nil
	result['count'] = i - 1

	return result
end


--- This is a wrapper around the SMB class, designed to get SMB going quickly for MSRPC calls. This will
--  connect to the SMB server, negotiate the protocol, open a session, connect to the IPC$ share, and
--  open the named pipe given by 'path'. When this successfully returns, the 'smbstate' table can be immediately 
--  used for MSRPC (the <code>bind</code> function should be called right after). 
--
-- Note that the smbstate table is the same one used in the SMB files (obviously), so it will contain
-- the various responses/information places in there by SMB functions. 
--
--@param host The host object. 
--@param path The path to the named pipe; for example, msrpc.SAMR_PATH or msrpc.SRVSVC_PATH. 
--@return (status, smbstate) if status is false, smbstate is an error message. Otherwise, smbstate is
--        required for all further calls. 
function start_smb(host, path)
	local smbstate
	local status, err

	-- Begin the SMB session
    status, smbstate = smb.start(host)
    if(status == false) then
        return false, smbstate
    end

	-- Negotiate the protocol
    status, err = smb.negotiate_protocol(smbstate)
    if(status == false) then
        smb.stop(smbstate)   
        return false, err
    end

    -- Start up a null session
    status, err = smb.start_session(smbstate)
    if(status == false) then
        smb.stop(smbstate)   
        return false, err
    end

    -- Connect to IPC$ share
    status, err = smb.tree_connect(smbstate, "IPC$")
    if(status == false) then
        smb.stop(smbstate)   
        return false, err
    end

    -- Try to connect to requested pipe
    status, err = smb.create_file(smbstate, path)
    if(status == false) then
        smb.stop(smbstate)   
        return false, err
    end

	-- Return everything
	return true, smbstate
end

--- A wrapper around the <code>smb.stop</code> function. I only created it to add symmetry, so client code
--  doesn't have to call both msrpc and smb functions.
--
--@param state The SMB state table. 
function stop_smb(state)
	smb.stop(state)
end

--- Bind to a MSRPC interface. Two common interfaces are SAML and SRVSVC, and can be found as
--  constants at the top of this file. Once this function has successfully returned, any MSRPC
--  call can be made (provided it doesn't depend on results from other MSRPC calls). 
--
--@param smbstate The SMB state table
--@param interface_uuid The interface to bind to. There are constants defined for these (<code>SAMR_UUID</code>, 
--       etc.)
--@param interface_version The interface version to use. There are constants at the top (<code>SAMR_VERSION</code>, 
--       etc.)
--@param transfer_syntax The transfer syntax to use. I don't really know what this is, but the value
--       was always the same on my tests. You can use the constant at the top (<code>TRANSFER_SYNTAX</code>), or
--       just set this parameter to 'nil'. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a 
--        table of values, none of which are especially useful. 
function bind(smbstate, interface_uuid, interface_version, transfer_syntax)
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

	status, result = smb.send_transaction(smbstate, 0x0026, "", data)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: Received Bind() response")

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

	-- If we made it this far, then we have a valid <code>Bind</code> response. Pull out some more parameters. 
	pos, response['max_transmit_frag'], response['max_receive_frag'], response['assoc_group'], response['secondary_address_length'] = bin.unpack("SSIS", data, pos)

	-- Read the secondary address
	pos, response['secondary_address'] = bin.unpack(string.format("<A%d", response['secondary_address_length']), data, pos)
	pos = pos + ((4 - ((pos - 1) % 4)) % 4); -- Alignment -- don't ask how I came up with this, it was a lot of drawing, and there's probably a far better way

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
--  ought to be added to this file. 
--
-- Anyways, this function takes the opnum and marshalled arguments, and passes it down to the SMB layer. The SMB layer sends
-- out a <code>SMB_COM_TRANSACTION</code> packet, and parses the response. Once the SMB stuff has been stripped off the response, it's 
-- passed down here, cleaned up some more, and returned to the caller.
--
-- There's a reason that SMB is sometimes considered to be between layer 4 and 7 on the OSI model. :)
--
--@param smbstate  The SMB state table (after <code>bind</code> has been called). 
--@param opnum     The operating number (ie, the function). Find this in the MSRPC documentation or with a packet logger. 
--@param arguments The marshalled arguments to pass to the function. Currently, marshalling is all done manually. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'arguments', which are the values returned by the server. 
local function call_function(smbstate, opnum, arguments)
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
	status, result = smb.send_transaction(smbstate, 0x0026, "", data)
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

---Call the MSRPC function <code>netshareenumall</code> on the remote system. This function basically returns a list of all the shares
-- on the system. 
--
--@param smbstate The SMB state table
--@param server   The IP or Hostname of the server (seems to be ignored but it's a good idea to have it)
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'shares', which is a list of the system's shares. 
function srvsvc_netshareenumall(smbstate, server)
	local i, j
	local status, result
	local arguments
	local pos, align

	local level
	local ctr, referent, count, max_count

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling NetShareEnumAll() [%s]", smbstate['ip'])
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
	status, result = call_function(smbstate, 0x0F, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: NetShareEnumAll() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']

-- [in]   [string,charset(UTF16)] uint16 *server_unc
-- [in,out]   uint32 level
	pos = 5

-- [in,out,switch_is(level)] srvsvc_NetShareCtr ctr
	local ctr, referent_id, count, max_count
	pos, ctr, referent_id, count, referent_id, max_count = bin.unpack("<IIIII", arguments, pos)
	stdnse.print_debug(3, "MSRPC: NetShareEnumAll: %d entries", count)

	for i = 1, count, 1 do
		pos, referent_id = bin.unpack("<I", arguments, pos)
	end

	-- Initialize the 'shares' part of response
	response['shares'] = {}
	for i = 1, count, 1 do
		local max_size, offset_actual_size
		local share = ""

		pos, max_size, offset, actual_size = bin.unpack("<III", arguments, pos)
		stdnse.print_debug(3, "MSRPC: NetShareEnumAll() entry: max_size = %d, offset = %d, actual_size = %d", max_size, offset, actual_size)

		pos, share = unicode_to_string(arguments, pos, actual_size, true, true)
		if(pos == nil) then
			return false, "Read off the end of the packet (srvsvc.netshareenumall)"
		end

		stdnse.print_debug(3, "MSRPC: NetShareEnumAll() entry: Name = %s", share)
		response['shares'][#response['shares'] + 1] = share
	end

-- [out]  uint32 totalentries
	pos = pos + 4

-- [in,out]   uint32 *resume_handle
	pos = pos + 4

	-- The return value
	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet (srvsvc.netshareenumall)"
	end
	if(response['return'] ~= 0) then
		return false, smb.get_status_name(response['return']) .. " (srvsvc.netshareenumall)"
	end

	return true, response
end

---Call the MSRPC function <code>netsharegetinfo</code> on the remote system. This function retrieves extra information about a share
-- on the system. 
--
--@param smbstate The SMB state table
--@param server   The IP or Hostname of the server (seems to be ignored but it's a good idea to have it)
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'shares', which is a list of the system's shares. 
function srvsvc_netsharegetinfo(smbstate, server, share, level)
	local i, j
	local status, result
	local arguments
	local pos, align

	local response = {}

	server = "\\\\" .. server

--		[in]   [string,charset(UTF16)] uint16 *server_unc,
	arguments = bin.pack("<IIIIA",
					REFERENT_ID,            -- Referent ID
					string.len(server) + 1, -- Max count
					0,                      -- Offset
					string.len(server) + 1, -- Actual count
					string_to_unicode(server, true, true)
				)

--		[in]   [string,charset(UTF16)] uint16 share_name[],
	arguments = arguments .. bin.pack("<IIIA",
					string.len(share) + 1, -- Max count
					0,                     -- Offset
					string.len(share) + 1, -- Actual count
					string_to_unicode(share, true, true)
				)

--		[in]   uint32 level,
	arguments = arguments .. bin.pack("<I", level)

--		[out,switch_is(level)] srvsvc_NetShareInfo info


	-- Do the call
	status, result = call_function(smbstate, 0x10, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: NetShareGetInfo() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--		[in]   [string,charset(UTF16)] uint16 *server_unc,
--		[in]   [string,charset(UTF16)] uint16 share_name[],
--		[in]   uint32 level,
--		[out,switch_is(level)] srvsvc_NetShareInfo info
	pos, level = bin.unpack("<I", arguments, pos)

	if(level == 2) then
		local referent_id

		pos, referent_id = bin.unpack("<I", arguments, pos)

		if(referent_id ~= 0) then
			local ptr_name, ptr_comment, ptr_path, ptr_password

			pos, ptr_name = bin.unpack("<I", arguments, pos) -- Referent ID (name)
			pos, response['type'] = bin.unpack("<I", arguments, pos)
	
			-- Convert the type to a string
			if(response['type'] == 0x00000000) then
				response['strtype'] = "STYPE_DISKTREE"
			elseif(response['type'] == 0x40000000) then
				response['strtype'] = "STYPE_DISKTREE_TEMPORARY"
			elseif(response['type'] == 0x80000000) then
				response['strtype'] = "STYPE_DISKTREE_HIDDEN"
	
			elseif(response['type'] == 0x00000001) then
				response['strtype'] = "STYPE_PRINTQ"
			elseif(response['type'] == 0x40000001) then
				response['strtype'] = "STYPE_PRINTQ_TEMPORARY"
			elseif(response['type'] == 0x80000001) then
				response['strtype'] = "STYPE_PRINTQ_HIDDEN"
	
			elseif(response['type'] == 0x00000002) then
				response['strtype'] = "STYPE_DEVICE"
			elseif(response['type'] == 0x40000002) then
				response['strtype'] = "STYPE_DEVICE_TEMPORARY"
			elseif(response['type'] == 0x80000002) then
				response['strtype'] = "STYPE_DEVICE_HIDDEN"
	
			elseif(response['type'] == 0x00000003) then
				response['strtype'] = "STYPE_IPC"
			elseif(response['type'] == 0x40000003) then
				response['strtype'] = "STYPE_IPC_TEMPORARY"
			elseif(response['type'] == 0x80000003) then
				response['strtype'] = "STYPE_IPC_HIDDEN"
	
			else
				response['strtype'] = "<unknown>"
			end
	
	
			pos, ptr_comment = bin.unpack("<I", arguments, pos) -- Referent ID (comment)
			pos, response['permissions']   = bin.unpack("<I", arguments, pos)
			pos, response['max_users']     = bin.unpack("<I", arguments, pos)
			pos, response['current_users'] = bin.unpack("<I", arguments, pos)
	
			pos, ptr_path = bin.unpack("<I", arguments, pos) -- Referent ID (path)
			pos, ptr_password = bin.unpack("<I", arguments, pos) -- Referent ID (password)
	
			if(ptr_name == 0) then
				response['name'] = "n/a"
			else
				pos = pos + 4 -- Max count
				pos = pos + 4 -- Offset
				pos, length = bin.unpack("<I", arguments, pos)
				pos, response['name'] = unicode_to_string(arguments, pos, length, true, true)
				if(pos == nil) then
					return false, "Read off the end of the packet (srvsvc.netsharegetinfo 1)"
				end
			end
	
			if(ptr_comment == 0) then
				response['comment'] = "n/a"
			else
				pos = pos + 4 -- Max count
				pos = pos + 4 -- Offset
				pos, length = bin.unpack("<I", arguments, pos)
				pos, response['comment'] = unicode_to_string(arguments, pos, length, true, true)
				if(pos == nil) then
					return false, "Read off the end of the packet (srvsvc.netsharegetinfo 2)"
				end
			end
	
			if(ptr_path == 0) then
				response['path'] = "n/a"
			else
				pos = pos + 4 -- Max count
				pos = pos + 4 -- Offset
				pos, length = bin.unpack("<I", arguments, pos)
				pos, response['path'] = unicode_to_string(arguments, pos, length, true, true)
				if(pos == nil) then
					return false, "Read off the end of the packet (srvsvc.netsharegetinfo 3)"
				end
			end
	
			if(ptr_password == 0) then
				response['password'] = "n/a"
			else
				pos = pos + 4 -- Max count
				pos = pos + 4 -- Offset
				pos, length = bin.unpack("<I", arguments, pos)
				pos, response['password'] = unicode_to_string(arguments, pos, length, true, true)
				if(pos == nil) then
					return false, "Read off the end of the packet (srvsvc.netsharegetinfo 4)"
				end
			end
		end
	else
		return false, string.format("Don't know how to parse netsharegetinfo level %d", level)
	end

	-- The return value
	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet (srvsvc.netsharegetinfo)"
	end
	if(response['return'] ~= 0) then
		return false, smb.get_status_name(response['return']) .. " (srvsvc.netsharegetinfo)"
	end

	return true, response
end




---Call the <code>NetSessEnum</code> function, which gets a list of active sessions on the host. For this function, 
-- a session is defined as a connection to a file share. 
--
--@param smbstate The SMB state table
--@param server   The IP or Hostname of the server (seems to be ignored but it's a good idea to have it)
--@return (status, result) If status is false, result is an error message. Otherwise, result is an array of tables.
--        Each table contains the elements 'user', 'client', 'active', and 'idle'.
function srvsvc_netsessenum(smbstate, server)
	local i, j
	local status, result
	local arguments
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling NetSessEnum() [%s]", smbstate['ip'])

--		[in]   [string,charset(UTF16)] uint16 *server_unc,
	arguments = bin.pack("<IIIIA",
					REFERENT_ID,            -- Referent ID
					string.len(server) + 1, -- Max count
					0,                      -- Offset
					string.len(server) + 1, -- Actual count
					string_to_unicode(server, true, true)
				)
	
--		[in]   [string,charset(UTF16)] uint16 *client,
	arguments = arguments .. bin.pack("<I", 0)

--		[in]   [string,charset(UTF16)] uint16 *user,
	arguments = arguments .. bin.pack("<I", 0)

--		[in,out]   uint32 level,
	arguments = arguments .. bin.pack("<I", 10) -- 10 seems to be the only useful one allowed anonymously

--		[in,out,switch_is(level)]   srvsvc_NetSessCtr ctr,
	arguments = arguments .. bin.pack("<IIII", 
					10,           -- Str
					REFERENT_ID,  -- Referent ID
					0,            -- Count
					0             -- Pointer to array
				)

--		[in]   uint32 max_buffer,
	arguments = arguments .. bin.pack("<I", 0xFFFFFFFF)

--		[out]   uint32 totalentries,
--		[in,out]   uint32 *resume_handle
	arguments = arguments .. bin.pack("<II", REFERENT_ID, 0)


	-- Do the call
	status, result = call_function(smbstate, 0x0C, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: NetSessEnum() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']

	local count
	local sessions = {}
	local referent_id
--		[in]   [string,charset(UTF16)] uint16 *server_unc,
--		[in]   [string,charset(UTF16)] uint16 *client,
--		[in]   [string,charset(UTF16)] uint16 *user,
--		[in,out]   uint32 level,
	pos = 5
--		[in,out,switch_is(level)]   srvsvc_NetSessCtr ctr,
	pos = pos + 4 -- ctr
	pos = pos + 4 -- Referent id
	pos, count = bin.unpack("<I", arguments, pos) -- count
	pos, referent_id = bin.unpack("<I", arguments, pos) -- referent_id
	if(referent_id ~= 0) then
		pos = pos + 4 -- max count
	
		for i = 1, count, 1 do
			sessions[i] = {}
	
			pos = pos + 4 -- Pointer to client
			pos = pos + 4 -- pointer to user
			pos, sessions[i]['active'], sessions[i]['idle'] = bin.unpack("<II", arguments, pos)
		end
	
		for i = 1, count, 1 do
			local length
			pos = pos + 4 -- max count
			pos = pos + 4 -- offset
			pos, length = bin.unpack("<I", arguments, pos)
			pos, sessions[i]['client'] = unicode_to_string(arguments, pos, length, true, true)
			if(pos == nil) then
				return false, "Read off the end of the packet (srvsvc.netsessenum 1)"
			end
	
			pos = pos + 4 -- max count
			pos = pos + 4 -- offset
			pos, length = bin.unpack("<I", arguments, pos)
			pos, sessions[i]['user'] = unicode_to_string(arguments, pos, length, false, true)
			if(pos == nil) then
				return false, "Read off the end of the packet (srvsvc.netsessenum 2)"
			end
		end
		response['sessions'] = sessions
	end

--		[in]   uint32 max_buffer,
--		[out]   uint32 totalentries,
	pos = pos + 4
--		[in,out]   uint32 *resume_handle
	pos = pos + 4 -- Referent ID
	pos = pos + 4 -- Resume handle


	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet (srvsvc.netsessenum)"
	end
	if(response['return'] ~= 0) then
		return false, smb.get_status_name(response['return']) .. " (srvsvc.netsessenum)"
	end

	return true, response
end

--- Calls the <code>NetServerGetStatistics</code> function, which grabs a bunch of statistics on the server. 
--  This function requires administrator access to call.
--
-- Note: Wireshark 1.0.3 doesn't parse this packet properly. 
--
--@param smbstate The SMB state table
--@param server   The IP or name of the server (I don't think this is actually used, but it's
--                good practice to send it). 
--
--@return A table containing the following values:
--  * 'start'       The time when statistics collection started (or when the statistics were last cleared). The value is 
--                stored as the number of seconds that have elapsed since 00:00:00, January 1, 1970, GMT. To calculate 
--                the length of time that statistics have been collected, subtract the value of this member from the 
--                present time. 'start_date' is the date as a string. 
--  * 'fopens'      The number of times a file is opened on a server. This includes the number of times named pipes are opened.
--  * 'devopens'    The number of times a server device is opened.
--  * 'jobsqueued'  The number of server print jobs spooled.
--  * 'sopens'      The number of times the server session started.
--  * 'stimedout'   The number of times the server session automatically disconnected.
--  * 'serrorout'   The number of times the server sessions failed with an error.
--  * 'pwerrors'    The number of server password violations.
--  * 'permerrors'  The number of server access permission errors.
--  * 'syserrors'   The number of server system errors.
--  * 'bytessent'   The number of server bytes sent to the network.
--  * 'bytesrcvd'   The number of server bytes received from the network.
--  * 'avresponse'  The average server response time (in milliseconds).
--  * 'reqbufneed'  The number of times the server required a request buffer but failed to allocate one. This value indicates that the server parameters may need adjustment.
--  * 'bigbufneed'  The number of times the server required a big buffer but failed to allocate one. This value indicates that the server parameters may need adjustment.
function srvsvc_netservergetstatistics(smbstate, server)
	local i, j
	local status, result
	local arguments
	local pos, align

	local response = {}

	local service = "SERVICE_SERVER"

	stdnse.print_debug(2, "MSRPC: Calling NetServerGetStatistics() [%s]", smbstate['ip'])

--		[in]      [string,charset(UTF16)] uint16 *server_unc,
	arguments = bin.pack("<IIIIA",
					REFERENT_ID,            -- Referent ID
					string.len(server) + 1, -- Max count
					0,                      -- Offset
					string.len(server) + 1, -- Actual count
					string_to_unicode(server, true, true)
				)

--		[in]      [string,charset(UTF16)] uint16 *service,
	arguments = arguments .. bin.pack("<IIIIA",
					REFERENT_ID,            -- Referent ID
					string.len(service) + 1, -- Max count
					0,                      -- Offset
					string.len(service) + 1, -- Actual count
					string_to_unicode(service, true, true)
				)
--		[in]      uint32 level,
	arguments = arguments .. bin.pack("<I", 0)

--		[in]      uint32 options,
	arguments = arguments .. bin.pack("<I", 0)

--		[out]     srvsvc_Statistics stat


	-- Do the call
	status, result = call_function(smbstate, 0x18, arguments)
	if(status ~= true) then
		return false, result
	end
	pos = 1

	stdnse.print_debug(3, "MSRPC: NetServerGetStatistics() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']



--		[in]      [string,charset(UTF16)] uint16 *server_unc,
--		[in]      [string,charset(UTF16)] uint16 *service,
--		[in]      uint32 level,
--		[in]      uint32 options,
--		[out]     srvsvc_Statistics stat
	pos, referent_id = bin.unpack("<I", arguments, pos)

	if(referent_id ~= 0) then
		pos, response['start'], response['fopens'], response['devopens'], response['jobsqueued'], response['sopens'], response['stimeouts'], response['serrorout'], response['pwerrors'], response['permerrors'], response['syserrors'], response['bytessent'], response['bytesrcvd'], response['avresponse'], response['reqbufneed'], response['bigbufneed'] = bin.unpack("IIIIIIIIIILLIII", arguments, pos)
	
		response['start_date'] = os.date("%Y-%m-%d %H:%M:%S", response['start'])
	end


	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet (srvsvc.netservergetstatistics)"
	end
	if(response['return'] ~= 0) then
		return false, smb.get_status_name(response['return']) .. " (srvsvc.netservergetstatistics)"
	end

	return true, response
end


---This calls NetPathCanonicalize(), which was the target of ms08-067. I haven't gotten this
-- working, yet, I trigger it indirectly through NetPathCompare(). 
--function srvsvc_netpathcanonicalize(smbstate, server, prefix, path)
--	local i, j
--	local status, result
--	local arguments
--	local pos, align
--
--	local response = {}
--
--	stdnse.print_debug(2, "MSRPC: Calling NetPathCanonicalize(%s) [%s]", path, smbstate['ip'])
--
----		[in]   [string,charset(UTF16)] uint16 *server_unc,
--	arguments = bin.pack("<IIIIA",
--					REFERENT_ID,            -- Referent ID
--					string.len(server) + 1, -- Max count
--					0,                      -- Offset
--					string.len(server) + 1, -- Actual count
--					string_to_unicode(server, true, true)
--				)
--
----		[in]   [string,charset(UTF16)] uint16 path[],
--	arguments = arguments .. bin.pack("<IIIA",
--					string.len(path) + 1, -- Max count
--					0,                      -- Offset
--					string.len(path) + 1, -- Actual count
--					string_to_unicode(path, true, true)
--				)
--
----		[out]  [size_is(maxbuf)] uint8 can_path[],
----		[in]   uint32 maxbuf,
--	arguments = arguments .. bin.pack("<I", 3)
--
----		[in]   [string,charset(UTF16)] uint16 prefix[],
--	arguments = arguments .. bin.pack("<IIIA",
--					string.len(prefix) + 1, -- Max count
--					0,                      -- Offset
--					string.len(prefix) + 1, -- Actual count
--					string_to_unicode(prefix, true, true)
--				)
--
----		[in,out] uint32 pathtype,
--	arguments = arguments .. bin.pack("<I", 1)
--
----		[in]    uint32 pathflags
--	arguments = arguments .. bin.pack("<I", 0)
--
--
--
--	-- Do the call
--	status, result = call_function(smbstate, 0x1F, arguments)
--	if(status ~= true) then
--		return false, result
--	end
--
--	stdnse.print_debug(3, "MSRPC: NetPathCanonicalize() returned successfully")
--
--	-- Make arguments easier to use
--	arguments = result['arguments']
--	pos = 1
--
----		[in]   [string,charset(UTF16)] uint16 *server_unc,
----		[in]   [string,charset(UTF16)] uint16 path[],
--		[out]  [size_is(maxbuf)] uint8 can_path[],
--	pos, test = bin.unpack("<I", arguments, pos)
--	io.write(string.format("test = %08x\n\n", test))
--	pos, path = bin.unpack(string.format("<A%d", test), arguments, pos)
--	io.write(string.format("test = %s\n\n", path))
----		[in]   uint32 maxbuf,
----		[in]   [string,charset(UTF16)] uint16 prefix[],
----		[in,out] uint32 pathtype,
--	pos, pathtype = bin.unpack("<I", arguments, pos)
--	io.write(string.format("pathtype = %08x\n", pathtype))
----		[in]    uint32 pathflags
--
--
--	pos, response['return'] = bin.unpack("<I", arguments, pos)
--	io.write(string.format("return = %08x\n", response['return']))
--	if(response['return'] == nil) then
--		return false, "Read off the end of the packet (winreg.openkey)"
--	end
--	if(response['return'] ~= 0) then
--		return false, smb.get_status_name(response['return']) .. " (winreg.openkey)"
--	end
--
--	return true, response
--
--end




---Call the NetPathCompare() function, which indirectly calls NetPathCanonicalize(), 
-- the target of ms08-067. I'm currently only using this to trigger ms08-067. 
--
-- The string used by Metasploit and other free tools to check for this vulnerability is
-- '\AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\..\n'. On vulnerable systems, this will be
-- accepted and this function will return '0'. On patched systems, this will be rejected
-- and return <code>ERROR_INVALID_PARAMETER</code>. 
--
-- Note that the srvsvc.exe process occasionally crashes when attempting this. 
--
--@param smbstate  The SMB state table
--@param server    The IP or Hostname of the server (seems to be ignored but it's a good idea to have it)
--@param path1     The first path to compare
--@param path2     The second path to compare
--@param pathtype  The pathtype to pass to the function (I always use '1')
--@param pathflags The pathflags to pass to the function (I always use '0')
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values containing
-- 'return'. 
function srvsvc_netpathcompare(smbstate, server, path1, path2, pathtype, pathflags)
	local i, j
	local status, result
	local arguments
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling NetPathCompare(%s, %s) [%s]", path1, path2, smbstate['ip'])

--		[in]   [string,charset(UTF16)] uint16 *server_unc,
	arguments = bin.pack("<IIIIA",
					REFERENT_ID,            -- Referent ID
					string.len(server) + 1, -- Max count
					0,                      -- Offset
					string.len(server) + 1, -- Actual count
					string_to_unicode(server, true, true)
				)

--		[in]   [string,charset(UTF16)] uint16 path1[],
	arguments = arguments .. bin.pack("<IIIA",
					string.len(path1) + 1, -- Max count
					0,                      -- Offset
					string.len(path1) + 1, -- Actual count
					string_to_unicode(path1, true, true)
				)


--		[in]   [string,charset(UTF16)] uint16 path2[],
	arguments = arguments .. bin.pack("<IIIA",
					string.len(path2) + 1, -- Max count
					0,                      -- Offset
					string.len(path2) + 1, -- Actual count
					string_to_unicode(path2, true, true)
				)

--		[in]    uint32 pathtype,
	arguments = arguments .. bin.pack("<I", pathtype)

--		[in]    uint32 pathflags
	arguments = arguments .. bin.pack("<I", pathflags)


	-- Do the call
	status, result = call_function(smbstate, 0x20, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: NetPathCompare() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1


--		[in]   [string,charset(UTF16)] uint16 *server_unc,
--		[in]   [string,charset(UTF16)] uint16 path1[],
--		[in]   [string,charset(UTF16)] uint16 path2[],
--		[in]    uint32 pathtype,
--		[in]    uint32 pathflags

	pos, response['return'] = bin.unpack("<I", arguments, pos)

	if(response['return'] == nil) then
		return false, "Read off the end of the packet (srvsvc.netpathcompare)"
	end
	if(response['return'] ~= 0) then
		return false, smb.get_status_name(response['return']) .. " (srvsvc.netpathcompare)"
	end

	return true, response

end



---Call the <code>connect4</code> function, to obtain a "connect handle". This must be done before calling many 
-- of the SAMR functions. 
--
--@param smbstate  The SMB state table
--@param server    The IP or Hostname of the server (seems to be ignored but it's a good idea to have it)
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'connect_handle', which is required to call other functions. 
function samr_connect4(smbstate, server)
	local i, j
	local status, result
	local arguments
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling Connect4() [%s]", smbstate['ip'])

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
	status, result = call_function(smbstate, 0x3E, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: Connect4() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1
-- [in,string,charset(UTF16)] uint16 *system_name,
-- [in] uint32 unknown,
-- [in] samr_ConnectAccessMask access_mask,
-- [out,ref]  policy_handle *connect_handle
	pos, response['connect_handle'], response['return'] = bin.unpack("<A20I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet (samr.connect4)"
	end
	if(response['return'] ~= 0) then
		return false, smb.get_status_name(response['return']) .. " (samr.connect4)"
	end

	return true, response
end

---Call the <code>enumdomains</code> function, which returns a list of all domains in use by the system. 
--
--@param smbstate       The SMB state table.
--@param connect_handle The connect_handle, returned by <code>samr_connect4</code>.
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'domains', which is a list of the domains. 
function samr_enumdomains(smbstate, connect_handle)
	local i, j
	local status, result
	local arguments
	local result
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling EnumDomains() [%s]", smbstate['ip'])

--		[in,ref]      policy_handle *connect_handle,
	arguments = bin.pack("<A", connect_handle)
	
--		[in,out,ref]  uint32 *resume_handle,
	arguments = arguments .. bin.pack("<I", 0)
--		[in]          uint32 buf_size,
	arguments = arguments .. bin.pack("<I", 0x2000)
--		[out]         samr_SamArray *sam,
--		[out]         uint32 num_entries


	-- Do the call
	status, result = call_function(smbstate, 0x06, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: EnumDomains() returned successfully")

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
		if(pos == nil) then
			return false, "Read off the end of the packet (samr.enumdomains)"
		end

		response['domains'][#response['domains'] + 1] = domain
	end
	
--		[out]         uint32 num_entries
	pos, response['num_entries'] = bin.unpack("<I", arguments, pos)

	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet (samr.enumdomains)"
	end
	if(response['return'] ~= 0) then
		return false, smb.get_status_name(response['return']) .. " (samr.enumdomains)"
	end

	return true, response
end

---Call the <code>LookupDomain</code> function, which converts a domain's name into its sid, which is
-- required to do operations on the domain. 
--
--@param smbstate       The SMB state table
--@param connect_handle The connect_handle, returned by <code>samr_connect4</code>
--@param domain         The name of the domain (all domain names can be obtained with <code>samr_enumdomains</code>)
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'sid', which is required to call other functions. 
function samr_lookupdomain(smbstate, connect_handle, domain)
	local i, j
	local status, result
	local arguments
	local pos, align
	local referent_id

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling LookupDomain(%s) [%s]", domain, smbstate['ip'])

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
	status, result = call_function(smbstate, 0x05, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: LookupDomain() returned successfully")

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
		return false, "Read off the end of the packet (samr.lookupdomain)"
	end
	if(response['return'] ~= 0) then
		return false, smb.get_status_name(response['return']) .. " (samr.lookupdomain)"
	end

	return true, response
end

---Call <code>OpenDomain</code>, which returns a handle to the domain identified by the given sid. 
-- This is required before calling certain functions. 
--
--@param smbstate       The SMB state table
--@param connect_handle The connect_handle, returned by <code>samr_connect4</code>
--@param sid            The sid for the domain, returned by <code>samr_lookupdomain</code>
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'domain_handle', which is used to call other functions. 
function samr_opendomain(smbstate, connect_handle, sid)
	local i, j
	local status, result
	local arguments
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling OpenDomain(%s) [%s]", sid_to_string(sid), smbstate['ip'])

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
	status, result = call_function(smbstate, 0x07, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: OpenDomain() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']


--		[in,ref]      policy_handle *connect_handle,
--		[in]          samr_DomainAccessMask access_mask,
--		[in,ref]      dom_sid2 *sid,
--		[out,ref]     policy_handle *domain_handle
	pos, response['domain_handle'], response['return'] = bin.unpack("<A20I", arguments)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet (samr.opendomain)"
	end
	if(response['return'] ~= 0) then
		return false, smb.get_status_name(response['return']) .. " (samr.opendomain)"
	end
	
	return true, response
end

---Call <code>EnumDomainUsers</code>, which returns a list of users only. To get more information about the users, the 
-- <code>QueryDisplayInfo</code> function can be used. 
--
--@param smbstate       The SMB state table
--@param domain_handle  The domain_handle, returned by <code>samr_opendomain</code>
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'names', which is a list of usernames in that domain. 
function samr_enumdomainusers(smbstate, domain_handle)
	local i, j
	local status, result
	local arguments
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling EnumDomainUsers() [%s]", smbstate['ip'])

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
	status, result = call_function(smbstate, 0x0d, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: EnumDomainUsers() returned successfully")

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
		if(pos == nil) then
			return false, "Read off the end of the packet (samr.enumdomainusers)"
		end
	end
--		[out]         uint32 num_entries
	pos, response['num_entries'] = bin.unpack("<I", arguments, pos)

	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet (samr.enumdomainusers)"
	end
	if(response['return'] ~= 0) then
		return false, smb.get_status_name(response['return']) .. " (samr.enumdomainusers)"
	end
	
	return true, response

end

---Call <code>QueryDisplayInfo</code>, which returns a list of users with accounts on the system, as well as extra information about
-- them (their full name and description). 
--
-- I found in testing that trying to get all the users at once is a mistake, it returns ERR_BUFFER_OVERFLOW, so instead I'm 
-- only reading one user at a time, in a loop. So one call to this will actually send out a number of packets equal to the 
-- number of users on the system. 
--
--@param smbstate       The SMB state table
--@param domain_handle  The domain handle, returned by <code>samr_opendomain</code>
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful ones being 'names', a list of all the usernames, and 'details', a further list of tables with the elements
--        'name', 'fullname', and 'description' (note that any of them can be nil if the server didn't return a value). Finally,
--        'flags' is the numeric flags for the user, while 'flags_list' is an array of strings, representing the flags.
function samr_querydisplayinfo(smbstate, domain_handle)
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
		stdnse.print_debug(2, "MSRPC: Calling QueryDisplayInfo(%d) [%s]", i, smbstate['ip'])

--		[in,ref]    policy_handle *domain_handle,
		arguments = bin.pack("<A", domain_handle)

--		[in]        uint16 level,
		arguments = arguments .. bin.pack("<SS", 
					0x0001, -- Level (1 = users, 3 = groups, 4 = usernames only)
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
		status, result = call_function(smbstate, 0x28, arguments)
		if(status ~= true) then
			return false, result
		end
	
		stdnse.print_debug(3, "MSRPC: QueryDisplayInfo() returned successfully", i)

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

		pos, info, padding, count, referent_id = bin.unpack("<SSII", arguments, pos)

		if(referent_id ~= 0) then
			pos, max_count, index = bin.unpack("<II", arguments, pos)
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
				if(pos == nil) then
					return false, "Read off the end of the packet (samr.querydisplayinfo 1)"
				end
			end
	
			if(fullname_ptr ~= 0) then
				local length, offset, count
				pos, length, offset, count = bin.unpack("<III", arguments, pos)
				pos, queryresult['fullname']   = unicode_to_string(arguments, pos, length, false, true)
				if(pos == nil) then
					return false, "Read off the end of the packet (samr.querydisplayinfo 2)"
				end
			end
	
			if(description_ptr ~= 0) then
				local length, offset, count
				pos, length, offset, count = bin.unpack("<III", arguments, pos)
				pos, queryresult['description']   = unicode_to_string(arguments, pos, length, false, true)
				if(pos == nil) then
					return false, "Read off the end of the packet (samr.querydisplayinfo 3)"
				end
			end
	
			-- Add the array to the return value
			response['details'][i + 1] = queryresult
			-- Add the name, as well (to make it easier for scripts to just grab a list of names)
			response['names'][#response['names'] + 1] = queryresult['name']
	
			-- Get the return value
			pos, function_returned = bin.unpack("<I", arguments, pos)
			if(function_returned == nil) then
				return false, "Read off the end of the packet (samr.querydisplayall)"
			end
			if(function_returned ~= 0 and function_returned ~= smb.status_names['NT_STATUS_MORE_ENTRIES']) then
				return false, smb.get_status_name(function_returned) .. " (samr.querydisplayinfo)"
			end
		end

		-- Increment the index (very important!)
		i = i + 1

	-- Keep looping as long as there are more entries. 
	until function_returned ~= smb.status_names['NT_STATUS_MORE_ENTRIES']

	return true, response
end

---Call <code>QueryDomainInfo2</code>, which grabs various data about a domain. 
--
--@param smbstate       The SMB state table
--@param domain_handle  The domain_handle, returned by <code>samr_opendomain</code>
--@param level          The level, which determines which type of information to query for. See the @return section
--                      for details. 
--@param response       [optional] A 'result' to add the entries to. This lets us call this function multiple times, 
--                      for multiple levels, and keep the results in one place. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, 
--        and the values that are returned are dependent on the 'level' settings:
--        Level 1:
--         'min_password_length' (in characters)
--         'password_history_length' (in passwords)
--         'password_properties'
--         'password_properties_list' (array of strings)
--         'max_password_age' (in days)
--         'min_password_age' (in days)
--        Level 8
--         'create_time' (1/10ms since 1601)
--         'create_date' (string)
--        Level 12
--         'lockout_duration' (in minutes)
--         'lockout_window' (in minutes)
--         'lockout_threshold' (in attempts)
function samr_querydomaininfo2(smbstate, domain_handle, level, response)
	local i, j
	local status, result
	local arguments
	local pos, align

	if(response == nil) then
		response = {}
	end

	stdnse.print_debug(2, "MSRPC: Calling QueryDomainInfo2(%d) [%s]", level, smbstate['ip'])

--		[in,ref]      policy_handle *domain_handle,
	arguments = bin.pack("<A", domain_handle)

--		[in]          uint16 level,
	arguments = arguments .. bin.pack("<S", level) -- 0 = padding/alignment

--		[out,switch_is(level)] samr_DomainInfo *info

	-- Do the call
	status, result = call_function(smbstate, 0x2e, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: QueryDomainInfo2() returned successfully")

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
		return false, "Read off the end of the packet (samr.querydomaininfo2)"
	end
	if(response['return'] ~= 0) then
		return false, smb.get_status_name(response['return']) .. " (samr.querydomaininfo2)"
	end
	
	return true, response
end

---Call the <code>close</code> function, which closes a handle of any type (for example, domain_handle or connect_handle)
--@param smbstate The SMB state table
--@param handle   The handle to close
--@return (status, result) If status is false, result is an error message. Otherwise, result is potentially
--        a table of values, none of which are likely to be used. 
function samr_close(smbstate, handle)
	local i, j
	local status, result
	local arguments
	local pos, align
	local response = {}


	stdnse.print_debug(2, "MSRPC: Calling Close() [%s]", smbstate['ip'])

--		[in,out,ref]  policy_handle *handle
	arguments = bin.pack("<A", handle)

	-- Do the call
	status, result = call_function(smbstate, 0x01, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: Close() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']

--		[in,out,ref]  policy_handle *handle
	pos, response['handle'] = bin.unpack("<A16", arguments)

	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet (samr.close)"
	end
	if(response['return'] ~= 0) then
		return false, smb.get_status_name(response['return']) .. " (samr.close)"
	end
	
	return true, response
end

---Call the <code>LsarOpenPolicy2</code> function, to obtain a "policy handle". This must be done before calling many 
-- of the LSA functions. 
--
--@param smbstate  The SMB state table
--@param server    The IP or Hostname of the server (seems to be ignored but it's a good idea to have it)
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'policy_handle', which is required to call other functions. 
function lsa_openpolicy2(smbstate, server)
	local i, j
	local status, result
	local arguments
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling LsarOpenPolicy2() [%s]", smbstate['ip'])

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
	status, result = call_function(smbstate, 0x2C, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: LsarOpenPolicy2() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']

--		[in,unique]      [string,charset(UTF16)] uint16 *system_name,
--		[in]  lsa_ObjectAttribute *attr,
--		[in]      uint32 access_mask,
--		[out] policy_handle *handle	
	pos, response['policy_handle'], response['return'] = bin.unpack("<A20I", arguments)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet (lsa.openpolicy2)"
	end
	if(response['return'] ~= 0) then
		return false, smb.get_status_name(response['return']) .. " (lsa.openpolicy2)"
	end

	return true, response
end

---Call the <code>LsarLookupNames2</code> function, to convert the server's name into a sid. 
--
--@param smbstate      The SMB state table
--@param policy_handle The policy handle returned by <code>lsa_openpolicy2</code>
--@param names         An array of names to look up. To get a SID, only one of the names needs to be valid. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values. 
--        The most useful result is 'domains', which is a list of domains known to the server. And, for each of the
--        domains, there is a 'name' entry, which is a string, and a 'sid' entry, which is yet another object which
--        can be passed to functions that understand SIDs. 
function lsa_lookupnames2(smbstate, policy_handle, names)
	local i, j
	local status, result
	local arguments
	local result
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling LsarLookupNames2(%s) [%s]", stdnse.strjoin(", ", names), smbstate['ip'])


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
	status, result = call_function(smbstate, 0x3a, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: LsarLookupNames2() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']


--		[in]     policy_handle *handle,
--		[in,range(0,1000)] uint32 num_names,
--		[in,size_is(num_names)]  lsa_String names[],
--		[out,unique]        lsa_RefDomainList *domains,
	local referent_id, count, max_count
	pos, referent_id = bin.unpack("<I", arguments)

	if(referent_id ~= 0) then
		pos, count, referent_id = bin.unpack("<II", arguments, pos)

		if(referent_id ~= 0) then
		pos, max_count = bin.unpack("<I", arguments, pos)

			stdnse.print_debug(3, "MSRPC: LsarLookupNames2(): Processing domains")
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
					local max_count, offset, actual_count
					pos, max_count, offset, actual_count = bin.unpack("<III", arguments, pos)
					pos, response['domains'][i]['name'] = unicode_to_string(arguments, pos, actual_count, false, true)
					if(pos == nil) then
						return false, "Read off the end of the packet (lsa.lookupnames2 1)"
					end
			
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
		end
	end

--		[in,out] lsa_TransSidArray2 *rids,
	local count, referent_id, max_count

	pos, count, referent_id = bin.unpack("<II", arguments, pos)

	if(referent_id ~= 0) then
		pos, max_count = bin.unpack("<I", arguments, pos)
	
		response['users'] = {}
		for i = 1, count, 1 do
			response['users'][i] = {}
			response['users'][i]['name'] = names[i]
	
			pos, response['users'][i]['type'], align, response['users'][i]['rid'], response['users'][i]['index'], response['users'][i]['unknown'] = bin.unpack("<SSIII", arguments, pos)
		end
	end
	
--		[in]         lsa_LookupNamesLevel level,
--		[in,out] uint32 *count,
	local count
	pos, count = bin.unpack("<I", arguments, pos)
--		[in]         uint32 unknown1,
--		[in]         uint32 unknown2


	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet (lsa.lookupnames2)"
	end
	if(response['return'] == smb.status_names['NT_STATUS_NONE_MAPPED']) then
		return false, "Couldn't find any names the host recognized"
	end

	if(response['return'] ~= 0 and response['return'] ~= smb.status_names['NT_STATUS_SOME_NOT_MAPPED']) then
		return false, smb.get_status_name(response['return']) .. " (lsa.lookupnames2)"
	end

	return true, response
end

---Call the <code>LsarLookupSids2</code> function, to convert a list of SIDs to their names
--
--@param smbstate      The SMB state table
--@param policy_handle The policy handle returned by <code>lsa_openpolicy2</code>
--@param sid           The SID object for the server
--@param rids          The RIDs of users to look up
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values. 
--        The element 'domains' is identical to the <code>lookupnames2</code> element called 'domains'. The element 'names' is a 
--        list of strings, for the usernames (not necessary a 1:1 mapping with the RIDs), and the element 'details' is
--        a table containing more information about each name, even if the name wasn't found (this one is a 1:1 mapping
--        with the RIDs). 
function lsa_lookupsids2(smbstate, policy_handle, sid, rids)
	local i, j
	local status, result
	local arguments
	local result
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling LsarLookupSids2(%s, %s) [%s]", sid_to_string(sid), stdnse.strjoin(", ", rids), smbstate['ip'])

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
	status, result = call_function(smbstate, 0x39, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: LsarLookupSids2() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']

--stdnse.print_debug(1, "0 Received response: %s", stdnse.tohex(arguments, {separator = " "}))

--		[in]     policy_handle *handle,
--		[in]     lsa_SidArray *sids,
--		[out,unique]        lsa_RefDomainList *domains,
	local referent_id, count, max_count
	pos, referent_id = bin.unpack("<I", arguments)
--stdnse.print_debug(1, "1 Referent ID = %d", referent_id)

	if(referent_id ~= 0) then
		pos, count, referent_id, max_count = bin.unpack("<III", arguments, pos)
--stdnse.print_debug(1, "2 count = %d, referent_id = %d, max_count = %d", count, referent_id, max_count)

		if(referent_id ~= 0) then

			stdnse.print_debug(3, "MSRPC: LsarLookupSids2(): Processing domains")
			response['domains'] = {}
		
			pos, max_count = bin.unpack("<I", arguments, pos)
--stdnse.print_debug(1, "3 max_count = %d", max_count)
	
			for i = 1, count, 1 do
				local length, size, referent_id, referent_id2
				pos, length, size, referent_id, referent_id2 = bin.unpack("<SSII", arguments, pos)
--stdnse.print_debug(1, "4 length = %d, size = %d, referent_id = %d, referent_id = %d", length, size, referent_id, referent_id2)
			end
		
			response['domains'] = {}
			for i = 1, count, 1 do
				response['domains'][i] = {}
				response['domains'][i]['sid'] = {}
		
				-- The name
				local max_count, offset, actual_count
				pos, max_count, offset, actual_count = bin.unpack("<III", arguments, pos)
--stdnse.print_debug(1, "5 max_count = %d, offset = %d, actual_count = %d", max_count, offset, actual_count)

				pos, response['domains'][i]['name'] = unicode_to_string(arguments, pos, actual_count, false, true)
--stdnse.print_debug(1, "6 name = %s", response['domains'][i]['name'])
				if(pos == nil) then
					 return false, "Read off the end of the packet (lsa.lookupsids2 1)"                                ------------ THIS is where Brandon is having issues----------
				end
		
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
	end

--		[in,out] lsa_TransNameArray2 *names,
	local count, referent_id, max_count
	-- Lets us convert types to strings
	local type_strings = { "User", "Group", "<unknown (3)>", "Alias", "Well known group", "Deleted account", "<unknown (7)>", "Not found" }

	pos, count, referent_id = bin.unpack("<II", arguments, pos)

	if(referent_id ~= 0) then
		pos, max_count = bin.unpack("<I", arguments, pos)
	
		stdnse.print_debug(3, "MSRPC: LsarLookupSids2(): Processing %d name headers", count)
		response['details'] = {}
		for i = 1, count, 1 do
			local name_length, name_size, referent_id

			response['details'][i] = {}
			pos, response['details'][i]['type'], align, name_length, name_size, response['details'][i]['referent_id'] = bin.unpack("<SSSSI", arguments, pos)
			pos, response['details'][i]['index'], response['details'][i]['unknown'] = bin.unpack("<II", arguments, pos)
		end
	
		stdnse.print_debug(3, "MSRPC: LsarLookupSids2(): Processing %d name values", count)
		response['names'] = {}
		for i = 1, count, 1 do
			-- If the user type is 'deleted', it may or may not still have a name set
			-- 1 = user account, 2 = group, 4 = alias, 5 = well known group, 6 = deleted account, 8 = not found
			local max_count, offset, actual_count

			if(response['details'][i]['referent_id'] ~= 0) then	
				pos, max_count, offset, actual_count = bin.unpack("<III", arguments, pos)
				pos, response['names'][#response['names'] + 1]   = unicode_to_string(arguments, pos, actual_count, false, true)
				if(pos == nil) then
					return false, "Read off the end of the packet (lsa.lookupsids2 2)"
				end
				response['details'][i]['name'] = response['names'][#response['names']]
				response['details'][i]['typestr'] = type_strings[response['details'][i]['type']]
			end
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
		return false, "Read off the end of the packet (lsa.lookupnames2)"
	end
	if(response['return'] ~= 0 and response['return'] ~= smb.status_names['NT_STATUS_SOME_NOT_MAPPED'] and response['return'] ~= smb.status_names['NT_STATUS_NONE_MAPPED']) then
		if(response['return'] == 8) then
			io.write("test: %s", nil)
		end
		return false, smb.get_status_name(response['return']) .. " (lsa.lookupsids2)"
	end

	stdnse.print_debug(3, "MSRPC: LsarLookupSids2(): Returning")
	return true, response

end

---Call the <code>close</code> function, which closes a session created with a <code>lsa_openpolicy</code>-style function
--@param smbstate  The SMB state table
--@param handle    The handle to close
--@return (status, result) If status is false, result is an error message. Otherwise, result is potentially
--        a table of values, none of which are likely to be used. 
function lsa_close(smbstate, handle)
	local i, j
	local status, result
	local arguments
	local pos, align
	local response = {}


	stdnse.print_debug(2, "MSRPC: Calling LsaClose() [%s]", smbstate['ip'])

--		[in,out]     policy_handle *handle
	arguments = bin.pack("<A", handle)

	-- Do the call
	status, result = call_function(smbstate, 0x00, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: LsaClose() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']

--		[in,out]     policy_handle *handle
	pos, response['handle'] = bin.unpack("<A16", arguments)

	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet (lsa.close)"
	end
	if(response['return'] ~= 0) then
		return false, smb.get_status_name(response['return']) .. " (lsa.close)"
	end
	
	return true, response
end

---Call the <code>OpenHKU</code> function, to obtain a handle to the HKEY_USERS hive
--
--@param smbstate  The SMB state table
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'handle', which is required to call other winreg functions. 
function winreg_openhku(smbstate)
	local i, j
	local status, result
	local arguments
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling OpenHKU() [%s]", smbstate['ip'])

--		[in]      uint16 *system_name,
	arguments = bin.pack("<ISS", REFERENT_ID, 0x1337, 0)
--		[in]      winreg_AccessMask access_mask,
	arguments = arguments .. bin.pack("<I", 0x02000000) -- "Maximum allowed"
--		[out,ref] policy_handle *handle

	-- Do the call
	status, result = call_function(smbstate, 0x04, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: OpenHKU() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']

--		[in]      uint16 *system_name,
--		[in]      winreg_AccessMask access_mask,
--		[out,ref] policy_handle *handle
	pos, response['handle'], response['return'] = bin.unpack("<A20I", arguments)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet (winreg.openhku)"
	end
	if(response['return'] ~= 0) then
		return false, smb.get_status_name(response['return']) .. " (winreg.openhku)"
	end

	return true, response

end

---Call the <code>OpenHKLM</code> function, to obtain a handle to the HKEY_LOCAL_MACHINE hive
--
--@param smbstate  The SMB state table
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'handle', which is required to call other winreg functions. 
function winreg_openhklm(smbstate)
	local i, j
	local status, result
	local arguments
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling OpenHKLM() [%s]", smbstate['ip'])

--		[in]      uint16 *system_name,
	arguments = bin.pack("<ISS", REFERENT_ID, 0x1337, 0)
--		[in]      winreg_AccessMask access_mask,
	arguments = arguments .. bin.pack("<I", 0x02000000) -- "Maximum allowed"
--		[out,ref] policy_handle *handle

	-- Do the call
	status, result = call_function(smbstate, 0x02, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: OpenHKLM() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']

--		[in]      uint16 *system_name,
--		[in]      winreg_AccessMask access_mask,
--		[out,ref] policy_handle *handle
	pos, response['handle'], response['return'] = bin.unpack("<A20I", arguments)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet (winreg.openhklm)"
	end
	if(response['return'] ~= 0) then
		return false, smb.get_status_name(response['return']) .. " (winreg.openhklm)"
	end

	return true, response

end

---Calls the Windows registry function <code>EnumKey</code>, which returns a single key
-- under the given handle, at the index of 'index'. 
--
--@param smbstate  The SMB state table
--@param handle    A handle to hive or key. <code>winreg_openhku</code> provides a useable key, for example. 
--@param index     The index of the key to return. Generally you'll start at 0 and increment until
--                 an error is returned.
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'name', which is the name of the current key
function winreg_enumkey(smbstate, handle, index)
	local i, j
	local status, result
	local arguments
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling EnumKey(%d) [%s]", index, smbstate['ip'])

--		[in,ref]        policy_handle    *handle,
	arguments = bin.pack("<A", handle)
--		[in]            uint32           enum_index,
	arguments = arguments .. bin.pack("<I", index) 
--		[in,out,ref]    winreg_StringBuf *name,
	arguments = arguments .. bin.pack("SSIIII", 
								0,           -- Length
								1040,        -- Size
								REFERENT_ID,
								520,         -- Max count
								0,           -- Offset
								0            -- Actual count
							)
--		[in,out,unique] winreg_StringBuf *keyclass,
	arguments = arguments .. bin.pack("ISSI", 
								REFERENT_ID,
								0,           -- Length
								0,           -- Size
								0            -- Pointer to name
							)
--		[in,out,unique] NTTIME           *last_changed_time
	arguments = arguments .. bin.pack("IL", REFERENT_ID, 0)


	-- Do the call
	status, result = call_function(smbstate, 0x09, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: EnumKey() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	local referent_id

	pos = 1

--		[in,ref]        policy_handle    *handle,
--		[in]            uint32           enum_index,
--		[in,out,ref]    winreg_StringBuf *name,
	pos = pos + 2 -- length
	pos = pos + 2 -- size
	pos, referent_id = bin.unpack("<I", arguments, pos)
	if(referent_id ~= 0) then
		pos = pos + 4 -- max count
		pos = pos + 4 -- offset
		pos, response['length'] = bin.unpack("<I", arguments, pos)
	
		if(response['length'] > 0) then
			pos, response['name']   = unicode_to_string(arguments, pos, response['length'], true, true)
			if(pos == nil) then
				return false, "Read off the end of the packet (winreg.enumkey)"
			end
		else
			response['name'] = "<unknown>" -- Not sure why the name could have a 0 length, but who knows?
		end
	end

--		[in,out,unique] winreg_StringBuf *keyclass,
	pos, referent_id = bin.unpack("<I", arguments, pos)
	if(referent_id ~= 0) then
		pos = pos + 2 -- length
		pos = pos + 2 -- size
		pos, referent_id = bin.unpack("<I", arguments, pos)
		if(referent_id ~= 0) then
			stdnse.print_debug(1, "EnumKeys() returned a value for 'name', which we don't know how to handle.")
		end
	end	
--		[in,out,unique] NTTIME           *last_changed_time
	pos, referent_id = bin.unpack("<I", arguments, pos)
	if(referent_id ~= 0) then
		pos, response['changed_time'] = bin.unpack("<L", arguments, pos)
		response['changed_date'] = os.date("%Y-%m-%d %H:%M:%S", (response['changed_time'] / 10000000) - 11644473600)
	else
		response['changed_time'] = 0
		response['changed_date'] = 0
	end

	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet (winreg.enumkey)"
	end
	if(response['return'] ~= 0) then
		return false, smb.get_status_name(response['return']) .. " (winreg.enumkey)"
	end

	return true, response

end

--- Calls the function <code>OpenKey</code>, which obtains a handle to a named key. 
--
--@param smbstate  The SMB state table
--@param handle    A handle to hive or key. <code>winreg_openhku</code> provides a useable key, for example. 
--@param keyname   The name of the key to open. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'handle', which is a handle to the newly opened key. 
function winreg_openkey(smbstate, handle, keyname)
	local i, j
	local status, result
	local arguments
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling OpenKey(%s) [%s]", keyname, smbstate['ip'])

--		[in,ref] policy_handle *parent_handle,
	arguments = bin.pack("<A", handle)
--		[in] winreg_String keyname,
	arguments = arguments .. bin.pack("<SSIIIIA", 
					(string.len(keyname) + 1) * 2, -- Name len
					(string.len(keyname) + 1) * 2, -- Name size
					REFERENT_ID,
					string.len(keyname) + 1, -- Max count
					0, 
					string.len(keyname) + 1, -- Actual count
					string_to_unicode(keyname, true, true)
				)

--		[in] uint32 unknown,
	arguments = arguments .. bin.pack("<I", 0)

--		[in] winreg_AccessMask access_mask,
	arguments = arguments .. bin.pack("<I", 0x02000000) -- Max allowed

--		[out,ref] policy_handle *handle


	-- Do the call
	status, result = call_function(smbstate, 0x0F, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: OpenKey() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--		[in,ref] policy_handle *parent_handle,
--		[in] winreg_String keyname,
--		[in] uint32 unknown,
--		[in] winreg_AccessMask access_mask,
--		[out,ref] policy_handle *handle
	pos, response['handle'] = bin.unpack("<A20", arguments, pos)

	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet (winreg.openkey)"
	end
	if(response['return'] ~= 0) then
		return false, smb.get_status_name(response['return']) .. " (winreg.openkey)"
	end

	return true, response
end

--- Calls the function <code>QueryInfoKey</code>, which obtains information about an opened key. 
--
--@param smbstate  The SMB state table
--@param handle    A handle to the key that's being queried. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one, at least for me, being 'last_changed_time'/'last_changed_date', which are the date and time that the
--        key was changed. 
function winreg_queryinfokey(smbstate, handle)
	local i, j
	local status, result
	local arguments
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling QueryInfoKey() [%s]", smbstate['ip'])

--		[in,ref] policy_handle *handle,
	arguments = bin.pack("<20A", handle)

--		[in,out,ref] winreg_String *classname,
	arguments = arguments .. bin.pack("<SSIIII", 0, 4096, REFERENT_ID, 2048, 0, 0)

--		[out,ref] uint32 *num_subkeys,
--		[out,ref] uint32 *max_subkeylen,
--		[out,ref] uint32 *max_subkeysize,
--		[out,ref] uint32 *num_values,
--		[out,ref] uint32 *max_valnamelen,
--		[out,ref] uint32 *max_valbufsize,
--		[out,ref] uint32 *secdescsize,
--		[out,ref] NTTIME *last_changed_time


	-- Do the call
	status, result = call_function(smbstate, 0x10, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: QueryInfoKey() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--		[in,ref] policy_handle *handle,
--		[in,out,ref] winreg_String *classname,
	pos = pos + 2 -- Length 
	pos = pos + 2 -- Size	
	pos = pos + 4 -- Referent ID
	pos = pos + 4 -- Max count
	pos = pos + 4 -- Offset
	pos, length = bin.unpack("<I", arguments, pos)
	pos, response['classname'] = unicode_to_string(arguments, pos, length, true, true)
	if(pos == nil) then
		return false, "Read off the end of the packet (winreg.queryinfokey)"
	end

--		[out,ref] uint32 *num_subkeys,
	pos, response['subkeys'] = bin.unpack("<I", arguments, pos)

--		[out,ref] uint32 *max_subkeylen,
	pos, response['subkeylen'] = bin.unpack("<I", arguments, pos)

--		[out,ref] uint32 *max_subkeysize,
	pos, response['subkeysize'] = bin.unpack("<I", arguments, pos)

--		[out,ref] uint32 *num_values,
	pos, response['num_values'] = bin.unpack("<I", arguments, pos)

--		[out,ref] uint32 *max_valnamelen,
	pos, response['max_valnamelen'] = bin.unpack("<I", arguments, pos)

--		[out,ref] uint32 *max_valbufsize,
	pos, response['max_valbufsize'] = bin.unpack("<I", arguments, pos)

--		[out,ref] uint32 *secdescsize,
	pos, response['secdescsize'] = bin.unpack("<I", arguments, pos)

--		[out,ref] NTTIME *last_changed_time
	pos, response['last_changed_time'] = bin.unpack("<L", arguments, pos)
	response['last_changed_date'] = os.date("%Y-%m-%d %H:%M:%S", (response['last_changed_time'] / 10000000) - 11644473600)

	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet (winreg.queryinfokey)"
	end
	if(response['return'] ~= 0) then
		return false, smb.get_status_name(response['return']) .. " (winreg.queryinfokey)"
	end

	return true, response
end


--- Calls the function <code>QueryValue</code>, which returns the value of the requested key.
--
--@param smbstate  The SMB state table
--@param handle    A handle to the key that's being queried. 
--@param value     The value we're looking for. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one, at least for me, being 'last_changed_time'/'last_changed_date', which are the date and time that the
--        key was changed. 
function winreg_queryvalue(smbstate, handle, value)
	local i, j
	local status, result
	local arguments
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling QueryValue(%s) [%s]", value, smbstate['ip'])


--		[in,ref] policy_handle *handle,
	arguments = bin.pack("<20A", handle)
--		[in] winreg_String value_name,
	arguments = arguments .. bin.pack("<SSIIIIA", 
						(#value + 1) * 2, 
						(#value + 1) * 2, 
						REFERENT_ID, 
						#value + 1, 
						0, 
						#value + 1, 
						string_to_unicode(value, true, true)
					)
--		[in,out] winreg_Type *type,
	arguments = arguments .. bin.pack("<II", REFERENT_ID, 0)

--		[in,out,size_is(*size),length_is(*length)] uint8 *data,
	arguments = arguments .. bin.pack("<IIII", REFERENT_ID, 520, 0, 0)

--		[in,out] uint32 *size,
	arguments = arguments .. bin.pack("<II", REFERENT_ID, 520)

--		[in,out] uint32 *length
	arguments = arguments .. bin.pack("<II", REFERENT_ID, 0)


	-- Do the call
	status, result = call_function(smbstate, 0x11, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: QueryValue() returned successfully")
	local length, referent_id

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1


--		[in,ref] policy_handle *handle,
--		[in] winreg_String value_name,
--		[in,out] winreg_Type *type,
	pos = pos + 4
	pos, response['type'] = bin.unpack("<I", arguments, pos)

--		[in,out,size_is(*size),length_is(*length)] uint8 *data,
	pos, referent_id = bin.unpack("<I", arguments, pos)
	pos = pos + 4 -- Max count
	pos = pos + 4 -- Offset
	pos, length = bin.unpack("<I", arguments, pos)

	if(referent_id ~= 0) then
		if(response['type'] == 0) then -- REG_NONE
			-- Do nothing
		elseif(response['type'] == 4) then -- REG_DWORD
			pos, response['value'] = bin.unpack("<I", arguments, pos)
		elseif(response['type'] == 8) then
			pos, response['value'] = bin.unpack("<A" .. length, arguments, pos)
		else
			pos, response['value'] = unicode_to_string(arguments, pos, length / 2, true, true)
			if(pos == nil) then
				return false, "Read off the end of the packet (winreg.queryvalue)"
			end
		end
	end

--		[in,out] uint32 *size,
	pos, referent_id = bin.unpack("<I", arguments, pos)
	if(referent_id ~= 0) then
		pos = pos + 4 -- size
	end

--		[in,out] uint32 *length
	pos, referent_id = bin.unpack("<I", arguments, pos)
	if(referent_id ~= 0) then
		pos = pos + 4 -- length
	end


	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet (winreg.queryvalue)"
	end
	if(response['return'] ~= 0) then
		return false, smb.get_status_name(response['return']) .. " (winreg.queryvalue)"
	end

	return true, response
end



--- Calls the function <code>CloseKey</code>, which closes an opened handle. Strictly speaking, this doesn't have to be called (Windows
--  will close the key for you), but it's good manners to clean up after yourself. 
--
--@param smbstate  The SMB state table
--@param handle    the handle to be closed. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, none of
--                         which are especially useful. 
function winreg_closekey(smbstate, handle)
	local i, j
	local status, result
	local arguments
	local pos, align

	local response = {}

	stdnse.print_debug(2, "MSRPC: Calling CloseKey() [%s]", smbstate['ip'])

--		[in,out,ref] policy_handle *handle
	arguments = bin.pack("<A", handle)

	-- Do the call
	status, result = call_function(smbstate, 0x05, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: CloseKey() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--		[in,out,ref] policy_handle *handle
	pos = pos + 20

	pos, response['return'] = bin.unpack("<I", arguments, pos)
	if(response['return'] == nil) then
		return false, "Read off the end of the packet (winreg.closekey)"
	end
	if(response['return'] ~= 0) then
		return false, smb.get_status_name(response['return']) .. " (winreg.closekey)"
	end

	return true, response
end
 
