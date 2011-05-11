---
-- By making heavy use of the <code>smb</code> library, this library will call various MSRPC 
--  functions. The functions used here can be accessed over TCP ports 445 and 139, 
--  with an established session. A NULL session (the default) will work for some 
--  functions and operating systems (or configurations), but not for others. 
--
-- To make use of these function calls, a SMB session with the server has to be
-- established. This can be done manually with the <code>smb</code> library, or the function
-- <code>start_smb</code> can be called. A session has to be created, then the IPC$ 
-- tree opened. 
--
-- Next, the interface has to be bound. The <code>bind()</code> function will take care of that. 
--
-- After that, you're free to call any function that's part of that interface. In
-- other words, if you bind to the SAMR interface, you can only call the <code>samr_</code>
-- functions, for <code>lsa_</code> functions, bind to the LSA interface, etc.  Although functions 
-- can technically be called in any order, many functions depend on the
-- value returned by other functions. I indicate those in the function comments, 
-- so keep an eye out. SAMR functions, for example, require a call to 
-- <code>connect4</code>. 
--
-- Something to note is that these functions, for the most part, return a whole ton
-- of stuff in a table; basically, everything that is returned by the function. 
-- Generally, if you want to know exactly what you have access to, either display the
-- returned data with a <code>print_table</code>-type function, or check the documentation (Samba 4.0's
-- <code>.idl</code> files (in <code>samba_4.0/source/librpc/idl</code>; see below for link) are what I based 
-- the names on). 
--
-- The parameters for each function are converted to a string of bytes in a process
-- called "marshalling". Functions here take arguments that match what a user would
-- logically want to send. These are marshalled by using functions in the 
-- <code>msrpctypes</code> module. Those functions require a table of values that 
-- isn't very use friendly; as such, it's generated, when possible, in the functions
-- in this module. The value returned, on the other hand, is returned directly to the
-- user; I don't want to limit what data they can use, and it's difficult to rely on 
-- servers to format it consistently (sometimes a <code>null</code> is returned, and
-- other times an empty array or blank string), so I put the onus on the scripts to 
-- deal with the returned values. 
--
-- When implementing this, I used Wireshark's output significantly, as well as Samba's
-- <code>.idl</code> files for reference:
--  http://websvn.samba.org/cgi-bin/viewcvs.cgi/branches/SAMBA_4_0/source/librpc/idl/.
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
require 'msrpctypes'
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

-- The path, UUID, and version for SVCCTL
SVCCTL_PATH    = "\\svcctl"
SVCCTL_UUID    = string.char(0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35, 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03)
SVCCTL_VERSION = 2

-- The path, UUID, and version for ATSVC
ATSVC_PATH     = "\\atsvc"
ATSVC_UUID     = string.char(0x82, 0x06, 0xf7, 0x1f, 0x51, 0x0a, 0xe8, 0x30, 0x07, 0x6d, 0x74, 0x0b, 0xe8, 0xce, 0xe9, 0x8b)
ATSVC_VERSION  = 1

-- This is the only transfer syntax I've seen in the wild, not that I've looked hard. It seems to work well. 
TRANSFER_SYNTAX = string.char(0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60)

-- The 'referent_id' value is ignored, as far as I can tell, so this value is passed for it. No, it isn't random. :)
REFERENT_ID = 0x50414d4e

-- The maximum length of a packet fragment
MAX_FRAGMENT = 0x800

---The number of SAMR records to pull at once. This was originally 1, but since I've written 
-- proper fragmentation code, I've successfully done it with 110 users, although I'd be surprised
-- if you couldn't go a lot higher. I had some issues that I suspect was UNIX truncating packets, 
-- so I scaled it back. 
local SAMR_GROUPSIZE = 20

---The number of LSA RIDs to check at once. I've successfully tested with up to about 110. Note that
-- due to very long message sizes, Wireshark might truncate packets if you have more than 30 together, 
-- so for debugging, setting this to 30 might be a plan. Like SAMR, I scaled this back due to UNIX
-- truncation. 
local LSA_GROUPSIZE  = 20

---The number of consecutive empty groups to stop after. Basically, this means that after 
-- <code>LSA_MINEMPTY</code> groups of <code>LSA_GROUPSIZE</code> users come back empty, we give
-- up. Raising this could find more users, but at the expense of more packets. 
local LSA_MINEMPTY = 10

--- This is a wrapper around the SMB class, designed to get SMB going quickly for MSRPC calls. This will
--  connect to the SMB server, negotiate the protocol, open a session, connect to the IPC$ share, and
--  open the named pipe given by 'path'. When this successfully returns, the 'smbstate' table can be immediately 
--  used for MSRPC (the <code>bind</code> function should be called right after). 
--
-- Note that the smbstate table is the same one used in the SMB files (obviously), so it will contain
-- the various results/information places in there by SMB functions. 
--
--@param host The host object. 
--@param path The path to the named pipe; for example, msrpc.SAMR_PATH or msrpc.SRVSVC_PATH. 
--@param disable_extended [optional] If set to 'true', disables extended security negotiations. 
--@param overrides [optional] Overrides variables in all the SMB functions. 
--@return (status, smbstate) if status is false, smbstate is an error message. Otherwise, smbstate is
--        required for all further calls. 
function start_smb(host, path, disable_extended, overrides)
	overrides = overrides or {}
	return smb.start_ex(host, true, true, "IPC$", path, disable_extended, overrides)
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
	local result

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
				MAX_FRAGMENT, -- Max transmit frag
				MAX_FRAGMENT, -- Max receive frag
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

	status, result = smb.write_file(smbstate, data, 0)
	if(status ~= true) then
		return false, result
	end

	status, result = smb.read_file(smbstate, 0, MAX_FRAGMENT)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: Received Bind() result")

	-- Make these easier to access. 
	parameters = result['parameters']
	data = result['data']

	-- Extract the first part from the resposne
	pos, result['version_major'], result['version_minor'], result['packet_type'], result['packet_flags'], result['data_representation'], result['frag_length'], result['auth_length'], result['call_id'] = bin.unpack("<CCCC>I<SSI", data)
	if(result['call_id'] == nil) then
		return false, "MSRPC: ERROR: Ran off the end of SMB packet; likely due to server truncation"
	end

	-- Check if the packet tyep was a fault
	if(result['packet_type'] == 0x03) then -- MSRPC_FAULT
		return false, "Bind() returned a fault (packet type)"
	end
	-- Check if the flags indicate DID_NOT_EXECUTE
	if(bit.band(result['packet_flags'], 0x20) == 0x20) then
		return false, "Bind() returned a fault (flags)"
	end
	-- Check if it requested authorization (I've never seen this, but wouldn't know how to handle it)
	if(result['auth_length'] ~= 0) then
		return false, "Bind() returned an 'auth length', which we don't know how to deal with"
	end
	-- Check if the packet was fragmented (I've never seen this, but wouldn't know how to handle it)
	if(bit.band(result['packet_flags'], 0x03) ~= 0x03) then
		return false, "Bind() returned a fragmented packet, which we don't know how to handle"
	end
	-- Check if the wrong message type was returned
	if(result['packet_type'] ~= 0x0c) then
		return false, "Bind() returned an unexpected packet type (not BIND_ACK)"
	end
	-- Ensure the proper call_id was echoed back (if this is wrong, it's likely because our read is out of sync, not a bad server)
	if(result['call_id'] ~= 0x41414141) then
		return false, "MSRPC call returned an incorrect 'call_id' value"
	end

	-- If we made it this far, then we have a valid Bind() result. Pull out some more parameters. 
	pos, result['max_transmit_frag'], result['max_receive_frag'], result['assoc_group'], result['secondary_address_length'] = bin.unpack("<SSIS", data, pos)
	if(result['secondary_address_length'] == nil) then
		return false, "MSRPC: ERROR: Ran off the end of SMB packet; likely due to server truncation"
	end

	-- Read the secondary address
	pos, result['secondary_address'] = bin.unpack(string.format("<A%d", result['secondary_address_length']), data, pos)
	if(result['secondary_address'] == nil) then
		return false, "MSRPC: ERROR: Ran off the end of SMB packet; likely due to server truncation"
	end
	pos = pos + ((4 - ((pos - 1) % 4)) % 4); -- Alignment -- don't ask how I came up with this, it was a lot of drawing, and there's probably a far better way

	-- Read the number of results
	pos, result['num_results'] = bin.unpack("<C", data, pos)
	if(result['num_results'] == nil) then
		return false, "MSRPC: ERROR: Ran off the end of SMB packet; likely due to server truncation"
	end
	pos = pos + ((4 - ((pos - 1) % 4)) % 4); -- Alignment

	-- Verify we got back what we expected
	if(result['num_results'] ~= 1) then
		return false, "Bind() returned the incorrect number of result"
	end

	-- Read in the last bits
	pos, result['ack_result'], result['align'], result['transfer_syntax'], result['syntax_version'] = bin.unpack("<SSA16I", data, pos)
	if(result['syntax_version'] == nil) then
		return false, "MSRPC: ERROR: Ran off the end of SMB packet; likely due to server truncation"
	end

	return true, result
end

--- Call a MSRPC function on the remote sever, with the given opnum and arguments. I opted to make this a local function
--  for design reasons -- scripts shouldn't be directly calling a function, if a function I haven't written is needed, it
--  ought to be added to this file. 
--
-- Anyways, this function takes the opnum and marshalled arguments, and passes it down to the SMB layer. The SMB layer sends
-- out a <code>SMB_COM_TRANSACTION</code> packet, and parses the result. Once the SMB stuff has been stripped off the result, it's 
-- passed down here, cleaned up some more, and returned to the caller.
--
-- There's a reason that SMB is sometimes considered to be between layer 4 and 7 on the OSI model. :)
--
--@param smbstate  The SMB state table (after <code>bind</code> has been called). 
--@param opnum     The operating number (ie, the function). Find this in the MSRPC documentation or with a packet logger. 
--@param arguments The marshalled arguments to pass to the function. Currently, marshalling is all done manually. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'arguments', which are the values returned by the server. If the packet is fragmented, the fragments
--        will be reassembled and 'arguments' will represent all the arguments; however, the rest of the result table will represent
--        the most recent fragment. 
function call_function(smbstate, opnum, arguments)
	local i
	local status, result
	local parameters, data
	local pos, align
	local result
	local first = true
	local is_first, is_last

	data = bin.pack("<CCCC>I<SSIISSA",
				0x05,        -- Version (major)
				0x00,        -- Version (minor)
				0x00,        -- Packet type (0x00 = request)
				0x03,        -- Packet flags (0x03 = first frag + last frag)
				0x10000000,  -- Data representation (big endian)
				0x18 + #arguments, -- Frag length (0x18 = the size of this data)
				0x0000,      -- Auth length
				0x41414141,  -- Call ID (I use 'AAAA' because it's easy to recognize)
				0x00000038,  -- Alloc hint
				0x0000,      -- Context ID
				opnum,       -- Opnum
				arguments
			)

	stdnse.print_debug(3, "MSRPC: Calling function 0x%02x with %d bytes of arguments", #arguments, opnum)

	-- Pass the information up to the smb layer
	status, result = smb.write_file(smbstate, data, 0)
	if(status ~= true) then
		return false, result
	end

	-- Loop over the fragments
	local arguments = ""
	repeat
		-- Read the information from the smb layer
		status, result = smb.read_file(smbstate, 0, 0x1001)
		if(status ~= true) then
			return false, result
		end
	
		-- Make these easier to access. 
		parameters = result['parameters']
		data       = result['data']
	
		-- Extract the first part from the resposne
		pos, result['version_major'], result['version_minor'], result['packet_type'], result['packet_flags'], result['data_representation'], result['frag_length'], result['auth_length'], result['call_id'] = bin.unpack("<CCCC>I<SSI", data)
		if(result['call_id'] == nil) then
			return false, "MSRPC: ERROR: Ran off the end of SMB packet; likely due to server truncation"
		end

		-- Check if we're fragmented
		is_first = (bit.band(result['packet_flags'], 0x01) == 0x01)
		is_last  = (bit.band(result['packet_flags'], 0x02) == 0x02)

		-- We have a fragmented packet, make sure it's the first (if we're on the first)
		if(first == true and is_first == false) then
			return false, "MSRPC: First fragment doesn't have proper 'first' (0x01) flag set"
		end

		-- We have a fragmented packet, make sure it isn't the first (if we aren't on the first)
		if(first == false and is_first) then
			return false, "MSRPC: Middle (or last) fragment doesn't have proper 'first' (0x01) flag set"
		end

		-- Check if there was an error
		if(result['packet_type'] == 0x03) then -- MSRPC_FAULT
			return false, "MSRPC call returned a fault (packet type)"
		end
		if(bit.band(result['packet_flags'], 0x20) == 0x20) then
			return false, "MSRPC call returned a fault (flags)"
		end
		if(result['auth_length'] ~= 0) then
			return false, "MSRPC call returned an 'auth length', which we don't know how to deal with"
		end
		if(result['packet_type'] ~= 0x02) then
			return false, "MSRPC call returned an unexpected packet type (not RESPONSE)"
		end
		if(result['call_id'] ~= 0x41414141) then
			return false, "MSRPC call returned an incorrect 'call_id' value"
		end
	
		-- Extract some more
		pos, result['alloc_hint'], result['context_id'], result['cancel_count'], align = bin.unpack("<ISCC", data, pos)
		if(align == nil) then
			return false, "MSRPC: ERROR: Ran off the end of SMB packet; likely due to server truncation"
		end

		-- Rest is the arguments
		arguments = arguments .. string.sub(data, pos)

		-- No longer the 'first'
		first = false
	until is_last == true

	result['arguments'] = arguments

	stdnse.print_debug(3, "MSRPC: Function call successful, %d bytes of returned argumenst", #result['arguments'])

	return true, result
end

---LANMAN API calls use different conventions than everything else, so make a separate function for them. 
function call_lanmanapi(smbstate, opnum, server_type)
	local status, result
	local parameters = ""
	local data
	local convert, entry_count, available_entries
	local entries = {}
	local pos

	parameters = bin.pack("<SzzSSI", 
							opnum, 
							"WrLehDO",  -- Parameter Descriptor
							"B16",      -- Return Descriptor
							0,          -- Detail level
							14724,      -- Return buffer size
							server_type -- Server type
						)

	stdnse.print_debug(1, "MSRPC: Sending Browser Service request")
	status, result = smb.send_transaction_named_pipe(smbstate, parameters, nil, "\\PIPE\\LANMAN", true)
	if(not(status)) then
		return false, "Couldn't call LANMAN API: " .. result
	end

	parameters = result.parameters
	data       = result.data

	stdnse.print_debug(1, "MSRPC: Parsing Browser Service response")
	pos, status, convert, entry_count, available_entries = bin.unpack("<SSSS", parameters)
	if(status ~= 0) then
		return false, string.format("Call to Browser Service failed with status = %d", status)
	end

	stdnse.print_debug(1, "MSRPC: Browser service returned %d entries", entry_count)

	local pos = 1
	local entry
	for i = 1, entry_count, 1 do
		-- Read the string
		pos, entry = bin.unpack("<z", data, pos)
		stdnse.print_debug(1, "MSRPC: Found name: %s", entry)

		-- pos needs to be rounded to the next even multiple of 16
		while(((pos - 1) % 16) ~= 0) do
			pos = pos + 1
		end

		-- Make sure we didn't hit the end of the packet
		if(not(entry)) then
			return false, "Call to browser service didn't receive enough data"
		end

		-- Insert the result
		table.insert(entries, entry)
	end

	return true, entries
end

---A proxy to a <code>msrpctypes</code> function that converts a ShareType to an english string. 
-- I implemented this as a proxy so scripts don't have to make direct calls to <code>msrpctypes</code>
-- functions.
--
--@param val The value to convert.
--@return A string that can be displayed to the user. 
function srvsvc_ShareType_tostr(val)
	return msrpctypes.srvsvc_ShareType_tostr(val)
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

	stdnse.print_debug(2, "MSRPC: Calling NetShareEnumAll() [%s]", smbstate['ip'])

-- [in]   [string,charset(UTF16)] uint16 *server_unc
	arguments = msrpctypes.marshall_unicode_ptr("\\\\" .. server, true)

-- [in,out]   uint32 level
	arguments = arguments .. msrpctypes.marshall_int32(0)

-- [in,out,switch_is(level)] srvsvc_NetShareCtr ctr
	arguments = arguments .. msrpctypes.marshall_srvsvc_NetShareCtr(0, {array=nil})

-- [in]   uint32 max_buffer,
	arguments = arguments .. msrpctypes.marshall_int32(4096)

-- [out]  uint32 totalentries
-- [in,out]   uint32 *resume_handle*
	arguments = arguments .. msrpctypes.marshall_int32_ptr(0)


	-- Do the call
	status, result = call_function(smbstate, 0x0F, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: NetShareEnumAll() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

-- [in]   [string,charset(UTF16)] uint16 *server_unc
-- [in,out]   uint32 level
	pos, result['level'] = msrpctypes.unmarshall_int32(arguments, pos)

-- [in,out,switch_is(level)] srvsvc_NetShareCtr ctr
	pos, result['ctr'] = msrpctypes.unmarshall_srvsvc_NetShareCtr(arguments, pos, level)
	if(pos == nil) then
		return false, "unmarshall_srvsvc_NetShareCtr() returned an error"
	end

-- [out]  uint32 totalentries
	pos, result['totalentries'] = msrpctypes.unmarshall_int32(arguments, pos)

-- [in,out]   uint32 *resume_handle
	pos, result['resume_handle'] = msrpctypes.unmarshall_int32_ptr(arguments, pos)

	-- The return value
	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (srvsvc.netshareenumall)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (srvsvc.netshareenumall)"
	end

	return true, result
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

--		[in]   [string,charset(UTF16)] uint16 *server_unc,
	arguments = msrpctypes.marshall_unicode_ptr("\\\\" .. server, true)

--		[in]   [string,charset(UTF16)] uint16 share_name[],
	arguments = arguments .. msrpctypes.marshall_unicode(share, true)

--		[in]   uint32 level,
	arguments = arguments .. msrpctypes.marshall_int32(level)

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
	pos, result['info'] = msrpctypes.unmarshall_srvsvc_NetShareInfo(arguments, pos)
	if(pos == nil) then
		return false, "unmarshall_srvsvc_NetShareInfo() returned an error"
	end

	-- The return value
	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (srvsvc.netsharegetinfo)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (srvsvc.netsharegetinfo)"
	end

	return true, result
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

	stdnse.print_debug(2, "MSRPC: Calling NetSessEnum() [%s]", smbstate['ip'])

--		[in]   [string,charset(UTF16)] uint16 *server_unc,
	arguments = msrpctypes.marshall_unicode_ptr(server, true)
	
--		[in]   [string,charset(UTF16)] uint16 *client,
	arguments = arguments .. msrpctypes.marshall_unicode_ptr(nil)

--		[in]   [string,charset(UTF16)] uint16 *user,
	arguments = arguments .. msrpctypes.marshall_unicode_ptr(nil)

--		[in,out]   uint32 level,
	arguments = arguments .. msrpctypes.marshall_int32(10) -- 10 seems to be the only useful one allowed anonymously

--		[in,out,switch_is(level)]   srvsvc_NetSessCtr ctr,
	arguments = arguments .. msrpctypes.marshall_srvsvc_NetSessCtr(10, {array=nil})

--		[in]   uint32 max_buffer,
	arguments = arguments .. msrpctypes.marshall_int32(0xFFFFFFFF)

--		[out]   uint32 totalentries,
--		[in,out]   uint32 *resume_handle
	arguments = arguments .. msrpctypes.marshall_int32_ptr(0)


	-- Do the call
	status, result = call_function(smbstate, 0x0C, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: NetSessEnum() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

	local count
	local sessions = {}
	local referent_id
--		[in]   [string,charset(UTF16)] uint16 *server_unc,
--		[in]   [string,charset(UTF16)] uint16 *client,
--		[in]   [string,charset(UTF16)] uint16 *user,
--		[in,out]   uint32 level,
	pos, result['level'] = msrpctypes.unmarshall_int32(arguments, pos)

--		[in,out,switch_is(level)]   srvsvc_NetSessCtr ctr,
	pos, result['ctr'] = msrpctypes.unmarshall_srvsvc_NetSessCtr(arguments, pos)
	if(pos == nil) then
		return false, "unmarshall_srvsvc_NetSessCtr() returned an error"
	end

--		[in]   uint32 max_buffer,
--		[out]   uint32 totalentries,
	pos, result['totalentries'] = msrpctypes.unmarshall_int32(arguments, pos)

--		[in,out]   uint32 *resume_handle
	pos, result['resume_handle'] = msrpctypes.unmarshall_int32_ptr(arguments, pos)


	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (srvsvc.netsessenum)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (srvsvc.netsessenum)"
	end

	return true, result
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
--  * 'avresult'  The average server result time (in milliseconds).
--  * 'reqbufneed'  The number of times the server required a request buffer but failed to allocate one. This value indicates that the server parameters may need adjustment.
--  * 'bigbufneed'  The number of times the server required a big buffer but failed to allocate one. This value indicates that the server parameters may need adjustment.
function srvsvc_netservergetstatistics(smbstate, server)
	local i, j
	local status, result
	local arguments
	local pos, align

	local service = "SERVICE_SERVER"

	stdnse.print_debug(2, "MSRPC: Calling NetServerGetStatistics() [%s]", smbstate['ip'])

--		[in]      [string,charset(UTF16)] uint16 *server_unc,
	arguments = msrpctypes.marshall_unicode_ptr(server, true)

--		[in]      [string,charset(UTF16)] uint16 *service,
	arguments = arguments .. msrpctypes.marshall_unicode_ptr(service, true)

--		[in]      uint32 level,
	arguments = arguments .. msrpctypes.marshall_int32(0)

--		[in]      uint32 options,
	arguments = arguments .. msrpctypes.marshall_int32(0)

--		[out]     srvsvc_Statistics stat


	-- Do the call
	status, result = call_function(smbstate, 0x18, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: NetServerGetStatistics() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--		[in]      [string,charset(UTF16)] uint16 *server_unc,
--		[in]      [string,charset(UTF16)] uint16 *service,
--		[in]      uint32 level,
--		[in]      uint32 options,
--		[out]     srvsvc_Statistics stat
	pos, result['stat'] = msrpctypes.unmarshall_srvsvc_Statistics_ptr(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (srvsvc.netservergetstatistics)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (srvsvc.netservergetstatistics)"
	end

	return true, result
end

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

	stdnse.print_debug(2, "MSRPC: Calling NetPathCompare(%s, %s) [%s]", path1, path2, smbstate['ip'])

--	  [in]   [string,charset(UTF16)] uint16 *server_unc,
	arguments = msrpctypes.marshall_unicode_ptr(server, true)

--	  [in]   [string,charset(UTF16)] uint16 path1[],
	arguments = arguments .. msrpctypes.marshall_unicode(path1, true)

--	  [in]   [string,charset(UTF16)] uint16 path2[],
	arguments = arguments .. msrpctypes.marshall_unicode(path2, true)

--	  [in]	uint32 pathtype,
	arguments = arguments .. msrpctypes.marshall_int32(pathtype)

--	  [in]	uint32 pathflags
	arguments = arguments .. msrpctypes.marshall_int32(pathflags)

	-- Do the call
	status, result = call_function(smbstate, 0x20, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: NetPathCompare() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1


--	  [in]   [string,charset(UTF16)] uint16 *server_unc,
--	  [in]   [string,charset(UTF16)] uint16 path1[],
--	  [in]   [string,charset(UTF16)] uint16 path2[],
--	  [in]	uint32 pathtype,
--	  [in]	uint32 pathflags

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)

	if(result['return'] == nil) then
		return false, "Read off the end of the packet (srvsvc.netpathcompare)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (srvsvc.netpathcompare)"
	end

	return true, result

end


---Call the NetPathCanonicalize() function, which is the target of ms08-067. 
--
--@param smbstate  The SMB state table
--@param server    The IP or Hostname of the server (seems to be ignored but it's a good idea to have it)
--@param path      The path to canonicalize
--@return (status, result, error_result) If status is false, result is an error message and error_result is
--        the result table. Otherwise, result is a table of values. 
function srvsvc_netpathcanonicalize(smbstate, server, path)
	local i, j
	local status, result
	local arguments
	local pos, align

	stdnse.print_debug(2, "MSRPC: Calling NetPathCanonicalize(%s) [%s]", path, smbstate['ip'])

--        [in]   [string,charset(UTF16)] uint16 *server_unc,
	arguments = msrpctypes.marshall_unicode_ptr(server, true)
--        [in]   [string,charset(UTF16)] uint16 path[],
	arguments = arguments .. msrpctypes.marshall_unicode(path, true)
--        [out]  [size_is(maxbuf)] uint8 can_path[],
--        [in]   uint32 maxbuf,
	arguments = arguments .. msrpctypes.marshall_int32(2)

--        [in]   [string,charset(UTF16)] uint16 prefix[],
	arguments = arguments .. msrpctypes.marshall_unicode("\\", true)

--        [in,out] uint32 pathtype,
	arguments = arguments .. msrpctypes.marshall_int32(1)
--        [in]    uint32 pathflags
	arguments = arguments .. msrpctypes.marshall_int32(1)


	-- Do the call
	status, result = call_function(smbstate, 0x1F, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: NetPathCanonicalize() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--        [in]   [string,charset(UTF16)] uint16 *server_unc,
--        [in]   [string,charset(UTF16)] uint16 path[],
--        [out]  [size_is(maxbuf)] uint8 can_path[],A
--        [in]   uint32 maxbuf,
--        [in]   [string,charset(UTF16)] uint16 prefix[],
--        [in,out] uint32 pathtype,
--        [in]    uint32 pathflags

	-- NOTE: This isn't being done correctly.. due to Wireshark's broken parsing, 
	-- and Samba's possibly-broken definition, I'm not sure how this is supposed
	-- to be parsed. 
	pos, result['max_count'] = msrpctypes.unmarshall_int32(arguments, pos)
	pos, result['can_path']  = msrpctypes.unmarshall_int32(arguments, pos)
	pos, result['type']      = msrpctypes.unmarshall_int32(arguments, pos) 
	pos, result['return']    = msrpctypes.unmarshall_int32(arguments, pos)

	if(result['return'] == nil) then
		return false, "Read off the end of the packet (srvsvc.netpathcanonicalize)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (srvsvc.netpathcanonicalize)", result
	end

	return true, result

end





---A proxy to a <code>msrpctypes</code> function that converts a PasswordProperties to an english string. 
-- I implemented this as a proxy so scripts don't have to make direct calls to <code>msrpctypes</code>
-- functions.
--
--@param val The value to convert.
--@return A string that can be displayed to the user. 
function samr_PasswordProperties_tostr(val)
	return msrpctypes.samr_PasswordProperties_tostr(val)
end

---A proxy to a <code>msrpctypes</code> function that converts a AcctFlags to an english string. 
-- I implemented this as a proxy so scripts don't have to make direct calls to <code>msrpctypes</code>
-- functions.
--
--@param val The value to convert.
--@return A string that can be displayed to the user. 
function samr_AcctFlags_tostr(val)
	return msrpctypes.samr_AcctFlags_tostr(val)
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

	stdnse.print_debug(2, "MSRPC: Calling Connect4() [%s]", smbstate['ip'])

-- [in,string,charset(UTF16)] uint16 *system_name,
	arguments = msrpctypes.marshall_unicode_ptr("\\\\" .. server, true)
	
-- [in] uint32 unknown,
	arguments = arguments .. msrpctypes.marshall_int32(0x02)

-- [in] samr_ConnectAccessMask access_mask,
	arguments = arguments .. msrpctypes.marshall_samr_ConnectAccessMask("SAMR_ACCESS_ENUM_DOMAINS|SAMR_ACCESS_OPEN_DOMAIN")
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
	pos, result['connect_handle'] = msrpctypes.unmarshall_policy_handle(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (samr.connect4)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (samr.connect4)"
	end

	return true, result
end

---Call the <code>enumdomains</code> function, which returns a list of all domains in use by the system. 
--
--@param smbstate       The SMB state table
--@param connect_handle The connect_handle, returned by samr_connect4()
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'domains', which is a list of the domains. 
function samr_enumdomains(smbstate, connect_handle)
	local i, j
	local status, result
	local arguments
	local result
	local pos, align

	stdnse.print_debug(2, "MSRPC: Calling EnumDomains() [%s]", smbstate['ip'])

--		[in,ref]      policy_handle *connect_handle,
	arguments = msrpctypes.marshall_policy_handle(connect_handle)
	
--		[in,out,ref]  uint32 *resume_handle,
	arguments = arguments .. msrpctypes.marshall_int32(0)

--		[in]          uint32 buf_size,
	arguments = arguments .. msrpctypes.marshall_int32(0x2000)

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
	pos, result['resume_handle'] = msrpctypes.unmarshall_int32(arguments, pos)

--		[in]          uint32 buf_size,
--		[out]         samr_SamArray *sam,
	pos, result['sam'] = msrpctypes.unmarshall_samr_SamArray_ptr(arguments, pos)

--		[out]         uint32 num_entries
	pos, result['num_entries'] = msrpctypes.unmarshall_int32(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (samr.enumdomains)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (samr.enumdomains)"
	end

	return true, result
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

	stdnse.print_debug(2, "MSRPC: Calling LookupDomain(%s) [%s]", domain, smbstate['ip'])

--		[in,ref]  policy_handle *connect_handle,		
	arguments = msrpctypes.marshall_policy_handle(connect_handle)

--		[in,ref]  lsa_String *domain_name,
	arguments = arguments .. msrpctypes.marshall_lsa_String(domain)

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
	pos, result['sid'] = msrpctypes.unmarshall_dom_sid2_ptr(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (samr.lookupdomain)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (samr.lookupdomain)"
	end

	return true, result
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

	stdnse.print_debug(2, "MSRPC: Calling OpenDomain(%s) [%s]", sid, smbstate['ip'])

--		[in,ref]      policy_handle *connect_handle,
	arguments = msrpctypes.marshall_policy_handle(connect_handle)

--		[in]          samr_DomainAccessMask access_mask,
	arguments = arguments .. msrpctypes.marshall_samr_DomainAccessMask("DOMAIN_ACCESS_LOOKUP_INFO_1|DOMAIN_ACCESS_LOOKUP_INFO_2|DOMAIN_ACCESS_ENUM_ACCOUNTS|DOMAIN_ACCESS_OPEN_ACCOUNT")

--		[in,ref]      dom_sid2 *sid,
	arguments = arguments .. msrpctypes.marshall_dom_sid2(sid)

--		[out,ref]     policy_handle *domain_handle


	-- Do the call
	status, result = call_function(smbstate, 0x07, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: OpenDomain() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--		[in,ref]      policy_handle *connect_handle,
--		[in]          samr_DomainAccessMask access_mask,
--		[in,ref]      dom_sid2 *sid,
--		[out,ref]     policy_handle *domain_handle
	pos, result['domain_handle'] = msrpctypes.unmarshall_policy_handle(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (samr.opendomain)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (samr.opendomain)"
	end
	
	return true, result
end

---Call <code>EnumDomainUsers</code>, which returns a list of users only. To get more information about the users, the 
-- QueryDisplayInfo() function can be used. 
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

	stdnse.print_debug(2, "MSRPC: Calling EnumDomainUsers() [%s]", smbstate['ip'])

--		[in,ref]      policy_handle *domain_handle,
	arguments = msrpctypes.marshall_policy_handle(domain_handle)

--		[in,out,ref]  uint32 *resume_handle,
	arguments = arguments .. msrpctypes.marshall_int32_ptr(nil)

--		[in]          samr_AcctFlags acct_flags,
	arguments = arguments .. msrpctypes.marshall_samr_AcctFlags("ACB_NONE")

--		[in]          uint32 max_size,
	arguments = arguments .. msrpctypes.marshall_int32(0x0400)

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
	pos = 1

--		[in,ref]      policy_handle *domain_handle,
--		[in,out,ref]  uint32 *resume_handle,
	pos, result['resume_handle'] = msrpctypes.unmarshall_int32(arguments, pos)

--		[in]          samr_AcctFlags acct_flags,
--		[in]          uint32 max_size,
--		[out]         samr_SamArray *sam,
	pos, result['sam'] = msrpctypes.unmarshall_samr_SamArray_ptr(arguments, pos)

--		[out]         uint32 num_entries
	pos, result['num_entries'] = msrpctypes.unmarshall_int32(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (samr.enumdomainusers)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (samr.enumdomainusers)"
	end
	
	return true, result

end

---Call <code>QueryDisplayInfo</code>, which returns a list of users with accounts on the system, as well as extra information about
-- them (their full name and description). 
--
-- I found in testing that trying to get all the users at once is a mistake, it returns ERR_BUFFER_OVERFLOW, so instead I'm 
-- only reading one user at a time. My recommendation is to start at <code>index</code> = 0, and increment until you stop getting
-- an error indicator in <code>result['return']</code>. 
--
--@param smbstate       The SMB state table
--@param domain_handle  The domain handle, returned by <code>samr_opendomain</code>
--@param index          The index of the user to check; the first user is 0, next is 1, etc.
--@param count          [optional] The number of users to return; you may want to be careful about going too high. Default: 1. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful ones being 'names', a list of all the usernames, and 'details', a further list of tables with the elements
--        'name', 'fullname', and 'description' (note that any of them can be nil if the server didn't return a value). Finally,
--        'flags' is the numeric flags for the user, while 'flags_list' is an array of strings, representing the flags.
function samr_querydisplayinfo(smbstate, domain_handle, index, count)
	local i, j
	local status, result
	local arguments
	local pos, align

	if(count == nil) then
		count = 1
	end

	-- This loop is because, in my testing, if I asked for all the results at once, it would blow up (ERR_BUFFER_OVERFLOW). So, instead,
	-- I put a little loop here and grab the names individually. 
	stdnse.print_debug(2, "MSRPC: Calling QueryDisplayInfo(%d) [%s]", index, smbstate['ip'])

--		[in,ref]    policy_handle *domain_handle,
	arguments = msrpctypes.marshall_policy_handle(domain_handle)

--		[in]        uint16 level,
	arguments = arguments .. msrpctypes.marshall_int16(1) -- Level (1 = users, 3 = groups, 4 = usernames only)

--		[in]        uint32 start_idx,
	arguments = arguments .. msrpctypes.marshall_int32(index)

--		[in]        uint32 max_entries,
	arguments = arguments .. msrpctypes.marshall_int32(count)

--		[in]        uint32 buf_size,
	arguments = arguments .. msrpctypes.marshall_int32(0x7FFFFFFF)

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
	pos = 1

--		[in,ref]    policy_handle *domain_handle,
--		[in]        uint16 level,
--		[in]        uint32 start_idx,
--		[in]        uint32 max_entries,
--		[in]        uint32 buf_size,
--		[out]       uint32 total_size,
	pos, result['total_size'] = msrpctypes.unmarshall_int32(arguments, pos)

--		[out]       uint32 returned_size,
	pos, result['returned_size'] = msrpctypes.unmarshall_int32(arguments, pos)
--		[out,switch_is(level)] samr_DispInfo info
	pos, result['info'] = msrpctypes.unmarshall_samr_DispInfo(arguments, pos)
	if(pos == nil) then
		return false, "SMB: An error occurred while calling unmarshall_samr_DispInfo"
	end

	-- Get the return value
	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (samr.querydisplayall)"
	end
	if(result['return'] ~= 0 and result['return'] ~= smb.status_codes['NT_STATUS_MORE_ENTRIES']) then
		return false, smb.get_status_name(result['return']) .. " (samr.querydisplayinfo)"
	end

	return true, result
end

---Call <code>QueryDomainInfo2</code>, which grabs various data about a domain. 
--
--@param smbstate       The SMB state table
--@param domain_handle  The domain_handle, returned by <code>samr_opendomain</code>
--@param level          The level, which determines which type of information to query for. See the @return section
--                      for details. 
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
function samr_querydomaininfo2(smbstate, domain_handle, level)
	local i, j
	local status, result
	local arguments
	local pos, align

	stdnse.print_debug(2, "MSRPC: Calling QueryDomainInfo2(%d) [%s]", level, smbstate['ip'])

--		[in,ref]      policy_handle *domain_handle,
	arguments = msrpctypes.marshall_policy_handle(domain_handle)

--		[in]          uint16 level,
	arguments = arguments .. msrpctypes.marshall_int32(level)

--		[out,switch_is(level)] samr_DomainInfo *info

	-- Do the call
	status, result = call_function(smbstate, 0x2e, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: QueryDomainInfo2() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--		[in,ref]      policy_handle *domain_handle,
--		[in]          uint16 level,
--		[out,switch_is(level)] samr_DomainInfo *info
	pos, result['info'] = msrpctypes.unmarshall_samr_DomainInfo_ptr(arguments, pos)
	if(pos == nil) then
		return false, "unmarshall_samr_DomainInfo_ptr() returned an error"
	end

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (samr.querydomaininfo2)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (samr.querydomaininfo2)"
	end
	
	return true, result
end

---Call the <code>EnumDomainAliases</code> function, which retrieves a list of groups for a given domain
--
--@param smbstate       The SMB state table
--@param domain_handle  The domain_handle, returned by <code>samr_opendomain</code>
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values. 
function samr_enumdomainaliases(smbstate, domain_handle)
	local i, j
	local status, result
	local arguments
	local pos, align

	arguments = ''

--        [in]          policy_handle *domain_handle,
	arguments = arguments .. msrpctypes.marshall_policy_handle(domain_handle)
	
--        [in,out,ref]  uint32 *resume_handle,
	arguments = arguments .. msrpctypes.marshall_int32_ptr(nil)

--        [out,ref]     samr_SamArray **sam,
--        [in]          uint32 max_size, (note: Wireshark says this is flags. Either way..)
	arguments = arguments .. msrpctypes.marshall_int32(0x400)

--        [out,ref]     uint32 *num_entries


	-- Do the call
	status, result = call_function(smbstate, 0x0f, arguments)
	if(status ~= true) then
		return false, result
	end

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--        [in]          policy_handle *domain_handle,
--        [in,out,ref]  uint32 *resume_handle,
	pos, result['resume_handle'] = msrpctypes.unmarshall_int32(arguments, pos)
	
--        [out,ref]     samr_SamArray **sam,
	pos, result['sam'] = msrpctypes.unmarshall_samr_SamArray_ptr(arguments, pos)

--        [in]          uint32 max_size,
--        [out,ref]     uint32 *num_entries
	pos, result['num_entries'] = msrpctypes.unmarshall_int32(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (samr.enumdomainaliases)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (samr.enumdomainaliases)"
	end
	
	return true, result
end

---Call the <code>EnumDomainAliases</code> function, which retrieves a list of groups for a given domain
--
--@param smbstate       The SMB state table
--@param domain_handle  The domain_handle, returned by <code>samr_opendomain</code>
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values. 
function samr_lookupnames(smbstate, domain_handle, names)
	local i, j
	local status, result
	local arguments
	local pos, align

	arguments = ''

--        [in,ref]      policy_handle *domain_handle,
	arguments = arguments .. msrpctypes.marshall_policy_handle(domain_handle)

--        [in,range(0,1000)] uint32 num_names,
	arguments = arguments .. msrpctypes.marshall_int32(#names)

--        [in,size_is(1000),length_is(num_names)] lsa_String names[],
	arguments = arguments .. msrpctypes.marshall_lsa_String_array2(names)
	
--        [out,ref]     samr_Ids *rids,
--        [out,ref]     samr_Ids *types


	-- Do the call
	status, result = call_function(smbstate, 0x11, arguments)
	if(status ~= true) then
		return false, result
	end

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--        [in,ref]      policy_handle *domain_handle,
--        [in,range(0,1000)] uint32 num_names,
--        [in,size_is(1000),length_is(num_names)] lsa_String names[],
--        [out,ref]     samr_Ids *rids,
	pos, result['rids'] = msrpctypes.unmarshall_samr_Ids(arguments, pos)

--        [out,ref]     samr_Ids *types
	pos, result['types'] = msrpctypes.unmarshall_samr_Ids(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (samr.lookupnames)"
	end
	if(result['return'] == smb.status_codes['NT_STATUS_NONE_MAPPED']) then
		return false, "Couldn't find any names the host recognized"
	end

	if(result['return'] ~= 0 and result['return'] ~= smb.status_codes['NT_STATUS_SOME_NOT_MAPPED']) then
		return false, smb.get_status_name(result['return']) .. " (samr.lookupnames)"
	end
	
	return true, result
end

---Call the <code>OpenAlias</code> function, which gets a handle to a group. 
--
--@param smbstate       The SMB state table
--@param domain_handle  The domain_handle, returned by <code>samr_opendomain</code>
--@param rid            The RID of the alias
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values. 
function samr_openalias(smbstate, domain_handle, rid)
	local i, j
	local status, result
	local arguments
	local pos, align

	arguments = ''

--        [in,ref]      policy_handle *domain_handle,
	arguments = arguments .. msrpctypes.marshall_policy_handle(domain_handle)

--        [in]          samr_AliasAccessMask access_mask,
	arguments = arguments .. msrpctypes.marshall_int32(0x0002000c) -- Full read permission

--        [in]          uint32 rid,
	arguments = arguments .. msrpctypes.marshall_int32(rid)

--        [out,ref]     policy_handle *alias_handle


	-- Do the call
	status, result = call_function(smbstate, 0x1b, arguments)
	if(status ~= true) then
		return false, result
	end

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--        [in,ref]      policy_handle *domain_handle,
--        [in]          samr_AliasAccessMask access_mask,
--        [in]          uint32 rid,
--        [out,ref]     policy_handle *alias_handle
	pos, result['alias_handle'] = msrpctypes.unmarshall_policy_handle(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (samr.openalias)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (samr.openalias)"
	end
	
	return true, result
end

---Call the <code>GetMembersInAlias</code> function, which retrieves a list of users in 
-- a group. 
--
--@param smbstate       The SMB state table
--@param alias_handle   The alias_handle, returned by <code>samr_openalias</code>
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values. 
function samr_getmembersinalias(smbstate, alias_handle)
	local i, j
	local status, result
	local arguments
	local pos, align

	arguments = ''

--        [in,ref]   policy_handle *alias_handle,
	arguments = arguments .. msrpctypes.marshall_policy_handle(alias_handle)
--        [out,ref]  lsa_SidArray    *sids


	-- Do the call
	status, result = call_function(smbstate, 0x21, arguments)
	if(status ~= true) then
		return false, result
	end

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--        [in,ref]   policy_handle *alias_handle,
--        [out,ref]  lsa_SidArray    *sids
	pos, result['sids'] = msrpctypes.unmarshall_lsa_SidArray(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (samr.getmembersinalias)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (samr.getmembersinalias)"
	end
	
	return true, result
end

-- Call the <code>LookupRids</code> function, which converts a list of RIDs to 
-- names. 
--
--NOTE: This doesn't appear to work (it generates a fault, despite the packet being properly formatted). 
--if you ever feel like you need this function, check out <code>lsa_lookupsids2</code>. 
--
--@param smbstate       The SMB state table
--@param domain_handle  The domain_handle, returned by <code>samr_opendomain</code>
--@param rids           An array of RIDs to look up
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values. 
--function samr_lookuprids(smbstate, domain_handle, rids)
--	local i, j
--	local status, result
--	local arguments
--	local pos, align
--
--	arguments = ''
--
----        [in,ref]      policy_handle *domain_handle,
--	arguments = arguments .. msrpctypes.marshall_policy_handle(domain_handle)
----        [in,range(0,1000)] uint32 num_rids,
--	arguments = arguments .. msrpctypes.marshall_int32(#rids)
----        [in,size_is(1000),length_is(num_rids)] uint32 rids[],
--	arguments = arguments .. msrpctypes.marshall_int32_array(rids)
----        [out,ref]     lsa_Strings *names,
----        [out,ref]     samr_Ids *types
--
--
--	-- Do the call
--	status, result = call_function(smbstate, 0x12, arguments)
--	if(status ~= true) then
--		return false, result
--	end
--
--	-- Make arguments easier to use
--	arguments = result['arguments']
--	pos = 1
--
----        [in,ref]      policy_handle *domain_handle,
----        [in,range(0,1000)] uint32 num_rids,
----        [in,size_is(1000),length_is(num_rids)] uint32 rids[],
----        [out,ref]     lsa_Strings *names,
----        [out,ref]     samr_Ids *types
--
--
--	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
--stdnse.print_debug("Return = %08x\n", result['return'])
--	if(result['return'] == nil) then
--		return false, "Read off the end of the packet (samr.getmembersinalias)"
--	end
--	if(result['return'] ~= 0) then
--		return false, smb.get_status_name(result['return']) .. " (samr.getmembersinalias)"
--	end
--	
--	return true, result
--end



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


	stdnse.print_debug(2, "MSRPC: Calling Close() [%s]", smbstate['ip'])

--		[in,out,ref]  policy_handle *handle
	arguments = msrpctypes.marshall_policy_handle(handle)

	-- Do the call
	status, result = call_function(smbstate, 0x01, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: Close() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--		[in,out,ref]  policy_handle *handle
	pos, result['handle'] = msrpctypes.unmarshall_policy_handle(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (samr.close)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (samr.close)"
	end
	
	return true, result
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

	stdnse.print_debug(2, "MSRPC: Calling LsarOpenPolicy2() [%s]", smbstate['ip'])

--		[in,unique]      [string,charset(UTF16)] uint16 *system_name,
	arguments = msrpctypes.marshall_unicode_ptr(server, true)

--		[in]  lsa_ObjectAttribute *attr,
	arguments = arguments .. msrpctypes.marshall_lsa_ObjectAttribute()

--		[in]      uint32 access_mask,
	arguments = arguments .. msrpctypes.marshall_int32(0x00000800)

--		[out] policy_handle *handle	

	-- Do the call
	status, result = call_function(smbstate, 0x2C, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: LsarOpenPolicy2() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--		[in,unique]      [string,charset(UTF16)] uint16 *system_name,
--		[in]  lsa_ObjectAttribute *attr,
--		[in]      uint32 access_mask,
--		[out] policy_handle *handle	
	pos, result['policy_handle'] = msrpctypes.unmarshall_policy_handle(arguments, pos)
	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)

	if(result['return'] == nil) then
		return false, "Read off the end of the packet (lsa.openpolicy2)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (lsa.openpolicy2)"
	end

	return true, result
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

	stdnse.print_debug(2, "MSRPC: Calling LsarLookupNames2(%s) [%s]", stdnse.strjoin(", ", names), smbstate['ip'])


--		[in]     policy_handle *handle,
	arguments = msrpctypes.marshall_policy_handle(policy_handle)

--		[in,range(0,1000)] uint32 num_names,
	arguments = arguments .. msrpctypes.marshall_int32(#names)

--		[in,size_is(num_names)]  lsa_String names[],
	arguments = arguments .. msrpctypes.marshall_lsa_String_array(names)

--		[out,unique]        lsa_RefDomainList *domains,
--		[in,out] lsa_TransSidArray2 *sids,
	arguments = arguments .. msrpctypes.marshall_lsa_TransSidArray2({nil})

--		[in]         lsa_LookupNamesLevel level,
	arguments = arguments .. msrpctypes.marshall_lsa_LookupNamesLevel("LOOKUP_NAMES_ALL")

--		[in,out] uint32 *count,
	arguments = arguments .. msrpctypes.marshall_int32(0)
	
--		[in]         uint32 unknown1,
	arguments = arguments .. msrpctypes.marshall_int32(0)

--		[in]         uint32 unknown2
	arguments = arguments .. msrpctypes.marshall_int32(2)



	-- Do the call
	status, result = call_function(smbstate, 0x3a, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: LsarLookupNames2() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1


--		[in]     policy_handle *handle,
--		[in,range(0,1000)] uint32 num_names,
--		[in,size_is(num_names)]  lsa_String names[],
--		[out,unique]        lsa_RefDomainList *domains,
	pos, result['domains'] = msrpctypes.unmarshall_lsa_RefDomainList_ptr(arguments, pos)

--		[in,out] lsa_TransSidArray2 *rids,
	pos, result['rids'] = msrpctypes.unmarshall_lsa_TransSidArray2(arguments, pos)
	
--		[in]         lsa_LookupNamesLevel level,
--		[in,out] uint32 *count,
	pos, result['count'] = msrpctypes.unmarshall_int32(arguments, pos)

--		[in]         uint32 unknown1,
--		[in]         uint32 unknown2


	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (lsa.lookupnames2)"
	end
	if(result['return'] == smb.status_codes['NT_STATUS_NONE_MAPPED']) then
		return false, "Couldn't find any names the host recognized"
	end

	if(result['return'] ~= 0 and result['return'] ~= smb.status_codes['NT_STATUS_SOME_NOT_MAPPED']) then
		return false, smb.get_status_name(result['return']) .. " (lsa.lookupnames2)"
	end

	return true, result
end

---Call the <code>LsarLookupSids2</code> function, to convert a list of SIDs to their names
--
--@param smbstate      The SMB state table
--@param policy_handle The policy handle returned by <code>lsa_openpolicy2</code>
--@param sids          The SIDs to look up (will probably be the server's SID with "-[rid]" appended
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values. 
--        The element 'domains' is identical to the lookupnames2() element called 'domains'. The element 'names' is a 
--        list of strings, for the usernames (not necessary a 1:1 mapping with the RIDs), and the element 'details' is
--        a table containing more information about each name, even if the name wasn't found (this one is a 1:1 mapping
--        with the RIDs). 
function lsa_lookupsids2(smbstate, policy_handle, sids)
	local i, j
	local status, result
	local arguments
	local result
	local pos, align

	stdnse.print_debug(2, "MSRPC: Calling LsarLookupSids2(%s) [%s]", stdnse.strjoin(", ", sids), smbstate['ip'])

--		[in]     policy_handle *handle,
	arguments = msrpctypes.marshall_policy_handle(policy_handle)
	
--		[in]     lsa_SidArray *sids,
	arguments = arguments .. msrpctypes.marshall_lsa_SidArray(sids)

--		[out,unique]        lsa_RefDomainList *domains,
--		[in,out] lsa_TransNameArray2 *names,
	arguments = arguments .. msrpctypes.marshall_lsa_TransNameArray2(nil)

--		[in]         uint16 level,
	arguments = arguments .. msrpctypes.marshall_int16(1)

--		[in,out] uint32 *count,
	arguments = arguments .. msrpctypes.marshall_int32(0)

--		[in]         uint32 unknown1,
	arguments = arguments .. msrpctypes.marshall_int32(0)

--		[in]         uint32 unknown2
	arguments = arguments .. msrpctypes.marshall_int32(2)


	-- Do the call
	status, result = call_function(smbstate, 0x39, arguments)
	if(status ~= true) then
		return false, result
	end

	-- Make arguments easier to use
	arguments = result['arguments']

--		[in]     policy_handle *handle,
--		[in]     lsa_SidArray *sids,
--		[out,unique]        lsa_RefDomainList *domains,
	pos, result['domains'] = msrpctypes.unmarshall_lsa_RefDomainList_ptr(arguments, pos)

--		[in,out] lsa_TransNameArray2 *names,
	pos, result['names'] = msrpctypes.unmarshall_lsa_TransNameArray2(arguments, pos)

--		[in]         uint16 level,
--		[in,out] uint32 *count,
	local count
	pos, result['count'] = msrpctypes.unmarshall_int32(arguments, pos)

--		[in]         uint32 unknown1,
--		[in]         uint32 unknown2

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (lsa.lookupnames2)"
	end
	if(result['return'] ~= 0 and result['return'] ~= smb.status_codes['NT_STATUS_SOME_NOT_MAPPED'] and result['return'] ~= smb.status_codes['NT_STATUS_NONE_MAPPED']) then
		return false, smb.get_status_name(result['return']) .. " (lsa.lookupsids2)"
	end

	stdnse.print_debug(3, "MSRPC: LsarLookupSids2(): Returning")
	return true, result

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

	stdnse.print_debug(2, "MSRPC: Calling LsaClose() [%s]", smbstate['ip'])

--		[in,out]     policy_handle *handle
	arguments = msrpctypes.marshall_policy_handle(handle)

	-- Do the call
	status, result = call_function(smbstate, 0x00, arguments)
	if(status ~= true) then
		return false, result
	end

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--		[in,out]     policy_handle *handle
	pos, result['handle'] = msrpctypes.unmarshall_policy_handle(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (lsa.close)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (lsa.close)"
	end
	
	stdnse.print_debug(3, "MSRPC: LsaClose() returned successfully")
	return true, result
end

---A proxy to a <code>msrpctypes</code> function that converts a SidType to an english string. 
-- I implemented this as a proxy so scripts don't have to make direct calls to <code>msrpctypes</code>
-- functions.
--
--@param val The value to convert.
--@return A string that can be displayed to the user. 
function lsa_SidType_tostr(val)
	return msrpctypes.lsa_SidType_tostr(val)
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

	stdnse.print_debug(2, "MSRPC: Calling OpenHKU() [%s]", smbstate['ip'])

--		[in]      uint16 *system_name,
	arguments = msrpctypes.marshall_int16_ptr(0x1337, true)

--		[in]      winreg_AccessMask access_mask,
	arguments = arguments .. msrpctypes.marshall_winreg_AccessMask('MAXIMUM_ALLOWED_ACCESS')

--		[out,ref] policy_handle *handle

	-- Do the call
	status, result = call_function(smbstate, 0x04, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: OpenHKU() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--		[in]      uint16 *system_name,
--		[in]      winreg_AccessMask access_mask,
--		[out,ref] policy_handle *handle
	pos, result['handle'] = msrpctypes.unmarshall_policy_handle(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (winreg.openhku)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (winreg.openhku)"
	end

	return true, result

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

	stdnse.print_debug(2, "MSRPC: Calling OpenHKLM() [%s]", smbstate['ip'])

--		[in]      uint16 *system_name,
	arguments = msrpctypes.marshall_int16_ptr(0x1337, true)

--		[in]      winreg_AccessMask access_mask,
	arguments = arguments .. msrpctypes.marshall_winreg_AccessMask('MAXIMUM_ALLOWED_ACCESS')

--		[out,ref] policy_handle *handle

	-- Do the call
	status, result = call_function(smbstate, 0x02, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: OpenHKLM() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--		[in]      uint16 *system_name,
--		[in]      winreg_AccessMask access_mask,
--		[out,ref] policy_handle *handle
	pos, result['handle'] = msrpctypes.unmarshall_policy_handle(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (winreg.openhklm)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (winreg.openhklm)"
	end

	return true, result
end

---Call the <code>OpenHKPD</code> function, to obtain a handle to the hidden HKEY_PERFORMANCE_DATA hive
--
--@param smbstate  The SMB state table
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'handle', which is required to call other winreg functions. 
function winreg_openhkpd(smbstate)
	local i, j
	local status, result
	local arguments
	local pos, align

	stdnse.print_debug(2, "MSRPC: Calling OpenHKPD() [%s]", smbstate['ip'])

--		[in]      uint16 *system_name,
	arguments = msrpctypes.marshall_int16_ptr(0x1337, true)

--		[in]      winreg_AccessMask access_mask,
	arguments = arguments .. msrpctypes.marshall_winreg_AccessMask('MAXIMUM_ALLOWED_ACCESS')

--		[out,ref] policy_handle *handle

	-- Do the call
	status, result = call_function(smbstate, 0x03, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: OpenHKPD() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--		[in]      uint16 *system_name,
--		[in]      winreg_AccessMask access_mask,
--		[out,ref] policy_handle *handle
	pos, result['handle'] = msrpctypes.unmarshall_policy_handle(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (winreg.openhkpd)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (winreg.openhkpd)"
	end

	return true, result
end

---Call the <code>OpenHKCU</code> function, to obtain a handle to the HKEY_CURRENT_USER hive
--
--@param smbstate  The SMB state table
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'handle', which is required to call other winreg functions. 
function winreg_openhkcu(smbstate)
	local i, j
	local status, result
	local arguments
	local pos, align

	stdnse.print_debug(2, "MSRPC: Calling OpenHKCU() [%s]", smbstate['ip'])

--		[in]      uint16 *system_name,
	arguments = msrpctypes.marshall_int16_ptr(0x1337, true)

--		[in]      winreg_AccessMask access_mask,
	arguments = arguments .. msrpctypes.marshall_winreg_AccessMask('MAXIMUM_ALLOWED_ACCESS')

--		[out,ref] policy_handle *handle

	-- Do the call
	status, result = call_function(smbstate, 0x01, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: OpenHKCU() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--		[in]      uint16 *system_name,
--		[in]      winreg_AccessMask access_mask,
--		[out,ref] policy_handle *handle
	pos, result['handle'] = msrpctypes.unmarshall_policy_handle(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (winreg.openhkcu)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (winreg.openhkcu)"
	end

	return true, result

end



---Calls the Windows registry function <code>EnumKey</code>, which returns a single key
-- under the given handle, at the index of 'index'. 
--
--@param smbstate  The SMB state table
--@param handle    A handle to hive or key. <code>winreg_openhku</code> provides a useable key, for example. 
--@param index     The index of the key to return. Generally you'll start at 0 and increment until
--                 an error is returned.
--@param name      The <code>name</code> buffer. This should be set to the empty string; however, setting to 'nil' can have
--                 interesting effects on Windows 2000 (I experienced crashes). 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful one being 'name', which is the name of the current key
function winreg_enumkey(smbstate, handle, index, name)
	local i, j
	local status, result
	local arguments
	local pos, align

	stdnse.print_debug(2, "MSRPC: Calling EnumKey(%d) [%s]", index, smbstate['ip'])

--		[in,ref]        policy_handle    *handle,
	arguments = msrpctypes.marshall_policy_handle(handle)

--		[in]            uint32           enum_index,
	arguments = arguments .. msrpctypes.marshall_int32(index)

--		[in,out,ref]    winreg_StringBuf *name,
	-- NOTE: if the 'name' parameter here is set to 'nil', the service on a fully patched Windows 2000 system
	-- may crash. 
	arguments = arguments .. msrpctypes.marshall_winreg_StringBuf({name=""}, 520)

--		[in,out,unique] winreg_StringBuf *keyclass,
	arguments = arguments .. msrpctypes.marshall_winreg_StringBuf_ptr({name=nil})

--		[in,out,unique] NTTIME           *last_changed_time
	arguments = arguments .. msrpctypes.marshall_NTTIME_ptr(0)

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
	pos, result['name'] = msrpctypes.unmarshall_winreg_StringBuf(arguments, pos)

--		[in,out,unique] winreg_StringBuf *keyclass,
	pos, result['keyclass'] = msrpctypes.unmarshall_winreg_StringBuf_ptr(arguments, pos)

--		[in,out,unique] NTTIME           *last_changed_time
	pos, result['changed_time'] = msrpctypes.unmarshall_NTTIME_ptr(arguments, pos)
	result['changed_date'] = os.date("%Y-%m-%d %H:%M:%S", result['changed_time'])

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (winreg.enumkey)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (winreg.enumkey)"
	end

	return true, result

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

	stdnse.print_debug(2, "MSRPC: Calling OpenKey(%s) [%s]", keyname, smbstate['ip'])

--		[in,ref] policy_handle *parent_handle,
	arguments = msrpctypes.marshall_policy_handle(handle)

--		[in] winreg_String keyname,
	arguments = arguments .. msrpctypes.marshall_winreg_String({name=keyname})

--		[in] uint32 unknown,
	arguments = arguments .. msrpctypes.marshall_int32(0)

--		[in] winreg_AccessMask access_mask,
	arguments = arguments .. msrpctypes.marshall_winreg_AccessMask('MAXIMUM_ALLOWED_ACCESS')

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
	pos, result['handle'] = msrpctypes.unmarshall_policy_handle(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (winreg.openkey)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (winreg.openkey)"
	end

	return true, result
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

	stdnse.print_debug(2, "MSRPC: Calling QueryInfoKey() [%s]", smbstate['ip'])

--		[in,ref] policy_handle *handle,
	arguments = msrpctypes.marshall_policy_handle(handle)

--		[in,out,ref] winreg_String *classname,
	arguments = arguments .. msrpctypes.marshall_winreg_String({name=""}, 2048)

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
	pos, result['classname'] = msrpctypes.unmarshall_winreg_String(arguments, pos)

--		[out,ref] uint32 *num_subkeys,
	pos, result['subkeys'] = msrpctypes.unmarshall_int32(arguments, pos)

--		[out,ref] uint32 *max_subkeylen,
	pos, result['subkeylen'] = msrpctypes.unmarshall_int32(arguments, pos)

--		[out,ref] uint32 *max_subkeysize,
	pos, result['subkeysize'] = msrpctypes.unmarshall_int32(arguments, pos)

--		[out,ref] uint32 *num_values,
	pos, result['num_values'] = msrpctypes.unmarshall_int32(arguments, pos)

--		[out,ref] uint32 *max_valnamelen,
	pos, result['max_valnamelen'] = msrpctypes.unmarshall_int32(arguments, pos)

--		[out,ref] uint32 *max_valbufsize,
	pos, result['max_valbufsize'] = msrpctypes.unmarshall_int32(arguments, pos)

--		[out,ref] uint32 *secdescsize,
	pos, result['secdescsize'] = msrpctypes.unmarshall_int32(arguments, pos)

--		[out,ref] NTTIME *last_changed_time
	pos, result['last_changed_time'] = msrpctypes.unmarshall_NTTIME(arguments, pos)
	result['last_changed_date'] = os.date("%Y-%m-%d %H:%M:%S", result['last_changed_time'])

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (winreg.queryinfokey)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (winreg.queryinfokey)"
	end

	return true, result
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

	stdnse.print_debug(2, "MSRPC: Calling QueryValue(%s) [%s]", value, smbstate['ip'])


--		[in,ref] policy_handle *handle,
	arguments = msrpctypes.marshall_policy_handle(handle)

--		[in] winreg_String value_name,
	arguments = arguments .. msrpctypes.marshall_winreg_String({name=value})

--		[in,out] winreg_Type *type,
	arguments = arguments .. msrpctypes.marshall_winreg_Type_ptr("REG_NONE")

--		[in,out,size_is(*size),length_is(*length)] uint8 *data,
	arguments = arguments .. msrpctypes.marshall_int8_array_ptr("", 1000000)

--		[in,out] uint32 *size,
	arguments = arguments .. msrpctypes.marshall_int32_ptr(1000000)

--		[in,out] uint32 *length
	arguments = arguments .. msrpctypes.marshall_int32_ptr(0)

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
	pos, result['type'] = msrpctypes.unmarshall_winreg_Type_ptr(arguments, pos)

--		[in,out,size_is(*size),length_is(*length)] uint8 *data,
	pos, result['data'] = msrpctypes.unmarshall_int8_array_ptr(arguments, pos)

	-- Format the type properly and put it in "value"
	if(result['data'] ~= nil) then
        local _
		if(result['type'] == "REG_DWORD") then
			_, result['value'] = bin.unpack("<I", result['data'])
		elseif(result['type'] == "REG_SZ" or result['type'] == "REG_MULTI_SZ" or result['type'] == "REG_EXPAND_SZ") then
			_, result['value'] = msrpctypes.unicode_to_string(result['data'], 1, #result['data'] / 2)
		elseif(result['type'] == "REG_BINARY") then
			result['value'] = result['data']
		elseif(result['type'] == "REG_NONE") then
			result['value'] = ""
		else
			stdnse.print_debug("MSRPC ERROR: Unknown type: %s", result['type'])
			result['value'] = result['type']
		end
	else
		result['value'] = nil
	end

--		[in,out] uint32 *size,
	pos, result['size'] = msrpctypes.unmarshall_int32_ptr(arguments, pos)

--		[in,out] uint32 *length
	pos, result['length'] = msrpctypes.unmarshall_int32_ptr(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)

	if(result['return'] == nil) then
		return false, "Read off the end of the packet (winreg.queryvalue)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (winreg.queryvalue)"
	end

	return true, result
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

	stdnse.print_debug(2, "MSRPC: Calling CloseKey() [%s]", smbstate['ip'])

--		[in,out,ref] policy_handle *handle
	arguments = msrpctypes.marshall_policy_handle(handle)

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
	pos, result['handle'] = msrpctypes.unmarshall_policy_handle(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (winreg.closekey)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (winreg.closekey)"
	end

	return true, result
end

--- Calls the function <code>OpenSCManagerA</code>, which gets a handle to the service manager. Should be closed with
-- <code>CloseServiceHandle</code> when finished. 
--
--@param smbstate    The SMB state table
--@param machinename The name or IP of the machine. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values
--        representing the "out" parameters.  
function svcctl_openscmanagera(smbstate, machinename)
	local i, j
	local status, result
	local arguments
	local pos, align

	stdnse.print_debug(2, "MSRPC: Calling OpenSCManagerA() [%s]", smbstate['ip'])

--        [in] [string,charset(UTF16)] uint16 *MachineName,
	arguments = msrpctypes.marshall_ascii_ptr("\\\\" .. machinename)

--        [in] [string,charset(UTF16)] uint16 *DatabaseName,
	arguments = arguments .. msrpctypes.marshall_ascii_ptr(nil)

--        [in] uint32 access_mask,
--	arguments = arguments .. msrpctypes.marshall_int32(0x000f003f) 
	arguments = arguments .. msrpctypes.marshall_int32(0x00000002) 

--        [out,ref] policy_handle *handle

	-- Do the call
	status, result = call_function(smbstate, 0x1b, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: OpenSCManagerA() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--        [in] [string,charset(UTF16)] uint16 *MachineName,
--        [in] [string,charset(UTF16)] uint16 *DatabaseName,
--        [in] uint32 access_mask,
--        [out,ref] policy_handle *handle
	pos, result['handle'] = msrpctypes.unmarshall_policy_handle(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (svcctl.openscmanagera)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (svcctl.openscmanagera)"
	end

	return true, result
end


--- Calls the function <code>OpenSCManagerW</code>, which gets a handle to the service manager. Should be closed with
-- <code>CloseServiceHandle</code> when finished. 
--
--@param smbstate    The SMB state table
--@param machinename The name or IP of the machine. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values
--        representing the "out" parameters.  
function svcctl_openscmanagerw(smbstate, machinename)
	local i, j
	local status, result
	local arguments
	local pos, align

--	if(1 == 1) then
--		return svcctl_openscmanagera(smbstate, machinename)
--	end

	stdnse.print_debug(2, "MSRPC: Calling OpenSCManagerW() [%s]", smbstate['ip'])

--        [in] [string,charset(UTF16)] uint16 *MachineName,
	arguments = msrpctypes.marshall_unicode_ptr("\\\\" .. machinename, true)

--        [in] [string,charset(UTF16)] uint16 *DatabaseName,
	arguments = arguments .. msrpctypes.marshall_unicode_ptr(nil, true)

--        [in] uint32 access_mask,
--	arguments = arguments .. msrpctypes.marshall_int32(0x000f003f) 
	arguments = arguments .. msrpctypes.marshall_int32(0x02000000) 

--        [out,ref] policy_handle *handle

	-- Do the call
	status, result = call_function(smbstate, 0x0f, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: OpenSCManagerW() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--        [in] [string,charset(UTF16)] uint16 *MachineName,
--        [in] [string,charset(UTF16)] uint16 *DatabaseName,
--        [in] uint32 access_mask,
--        [out,ref] policy_handle *handle
	pos, result['handle'] = msrpctypes.unmarshall_policy_handle(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (svcctl.openscmanagerw)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (svcctl.openscmanagerw)"
	end

	return true, result
end


--- Calls the function <code>CloseServiceHandle</code>, which releases a handle.
--
--@param smbstate  The SMB state table
--@param handle    The handle to be closed. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values
--        representing the "out" parameters.  
function svcctl_closeservicehandle(smbstate, handle)
	local i, j
	local status, result
	local arguments
	local pos, align

	stdnse.print_debug(2, "MSRPC: Calling CloseServiceHandle() [%s]", smbstate['ip'])

--        [in,out,ref] policy_handle *handle
	arguments = msrpctypes.marshall_policy_handle(handle)


	-- Do the call
	status, result = call_function(smbstate, 0x00, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: OpenSCManagerA() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--        [in,out,ref] policy_handle *handle
	pos, result['handle'] = msrpctypes.unmarshall_policy_handle(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (svcctl.closeservicehandle)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (svcctl.closeservicehandle)"
	end

	return true, result
end

--- Calls the function <code>CreateServiceW</code>, which creates a service on the remote machine. This should
-- be deleted with <code>DeleteService</code> when finished. 
--
--@param smbstate  The SMB state table
--@param handle    The handle created by <code>OpenSCManagerW</code>
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values
--        representing the "out" parameters.  
function svcctl_createservicew(smbstate, handle, service_name, display_name, path)
	local i, j
	local status, result
	local arguments
	local pos, align

	stdnse.print_debug(2, "MSRPC: Calling CreateServiceW() [%s]", smbstate['ip'])

--        [in,ref] policy_handle *scmanager_handle,
	arguments = msrpctypes.marshall_policy_handle(handle)

--        [in] [string,charset(UTF16)] uint16 ServiceName[],
	arguments = arguments .. msrpctypes.marshall_unicode(service_name, true)

--        [in] [string,charset(UTF16)] uint16 *DisplayName,
	arguments = arguments .. msrpctypes.marshall_unicode_ptr(display_name, true)

--        [in] uint32 desired_access,
	arguments = arguments .. msrpctypes.marshall_int32(0x000f01ff) -- Access: Max

--        [in] uint32 type,
	arguments = arguments .. msrpctypes.marshall_int32(0x00000010) -- Type: own process

--        [in] uint32 start_type,
	arguments = arguments .. msrpctypes.marshall_int32(0x00000003) -- Start: Demand

--        [in] uint32 error_control,
	arguments = arguments .. msrpctypes.marshall_int32(0x00000000) -- Error: Ignore

--        [in] [string,charset(UTF16)] uint16 binary_path[],
	arguments = arguments .. msrpctypes.marshall_unicode(path, true)

--        [in] [string,charset(UTF16)] uint16 *LoadOrderGroupKey,
	arguments = arguments .. msrpctypes.marshall_unicode_ptr(nil)

--        [in,out] uint32 *TagId,
	arguments = arguments .. msrpctypes.marshall_int32_ptr(nil)

--        [in,size_is(dependencies_size)] uint8 *dependencies,
	arguments = arguments .. msrpctypes.marshall_int8_ptr(nil)

--        [in] uint32 dependencies_size,
	arguments = arguments .. msrpctypes.marshall_int32(0)

--        [in] [string,charset(UTF16)] uint16 *service_start_name,
	arguments = arguments .. msrpctypes.marshall_unicode_ptr(nil)

--        [in,size_is(password_size)] uint8 *password,
	arguments = arguments .. msrpctypes.marshall_int8_ptr(nil)

--        [in] uint32 password_size,
	arguments = arguments .. msrpctypes.marshall_int32(0)

--        [out,ref] policy_handle *handle



	-- Do the call
	status, result = call_function(smbstate, 0x0c, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: CreateServiceW() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--        [in,ref] policy_handle *scmanager_handle,
--        [in] [string,charset(UTF16)] uint16 ServiceName[],
--        [in] [string,charset(UTF16)] uint16 *DisplayName,
--        [in] uint32 desired_access,
--        [in] uint32 type,
--        [in] uint32 start_type,
--        [in] uint32 error_control,
--        [in] [string,charset(UTF16)] uint16 binary_path[],
--        [in] [string,charset(UTF16)] uint16 *LoadOrderGroupKey,
--        [in,out] uint32 *TagId,
	pos, result['TagId'] = msrpctypes.unmarshall_int32_ptr(arguments, pos)
	
--        [in,size_is(dependencies_size)] uint8 *dependencies,
--        [in] uint32 dependencies_size,
--        [in] [string,charset(UTF16)] uint16 *service_start_name,
--        [in,size_is(password_size)] uint8 *password,
--        [in] uint32 password_size,
--        [out,ref] policy_handle *handle
	pos, result['handle'] = msrpctypes.unmarshall_policy_handle(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (svcctl.createservicew)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (svcctl.createservicew)"
	end

	return true, result
end

--- Calls the function <code>DeleteService</code>, which deletes a service on the remote machine. This service
-- has to opened with <code>OpenServiceW</code> or similar functions. 
--
--@param smbstate  The SMB state table.
--@param handle    The handle to delete, opened with <code>OpenServiceW</code> or similar. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values
--        representing the "out" parameters.  
function svcctl_deleteservice(smbstate, handle)
	local i, j
	local status, result
	local arguments
	local pos, align

	stdnse.print_debug(2, "MSRPC: Calling DeleteService() [%s]", smbstate['ip'])

--        [in,ref] policy_handle *handle
	arguments = msrpctypes.marshall_policy_handle(handle)


	-- Do the call
	status, result = call_function(smbstate, 0x02, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: DeleteService() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1


--        [in,ref] policy_handle *handle


	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (svcctl.deleteservice)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (svcctl.deleteservice)"
	end

	return true, result
end

--- Calls the function <code>OpenServiceW</code>, which gets a handle to the service.  Should be closed with
-- <code>CloseServiceHandle</code> when finished. 
--
--@param smbstate The SMB state table.
--@param handle   A handle to the policy manager, opened with <code>OpenSCManagerW</code> or similar. 
--@param name     The name of the service. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values
--        representing the "out" parameters.  
function svcctl_openservicew(smbstate, handle, name)
	local i, j
	local status, result
	local arguments
	local pos, align

	stdnse.print_debug(2, "MSRPC: Calling OpenServiceW() [%s]", smbstate['ip'])

--        [in,ref] policy_handle *scmanager_handle,
	arguments = msrpctypes.marshall_policy_handle(handle)

--        [in] [string,charset(UTF16)] uint16 ServiceName[],
	arguments = arguments .. msrpctypes.marshall_unicode(name, true)

--        [in] uint32 access_mask,
	arguments = arguments .. msrpctypes.marshall_int32(0x000f01ff)
--        [out,ref] policy_handle *handle


	-- Do the call
	status, result = call_function(smbstate, 0x10, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: OpenServiceW() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--        [in,ref] policy_handle *scmanager_handle,
--        [in] [string,charset(UTF16)] uint16 ServiceName[],
--        [in] uint32 access_mask,
--        [out,ref] policy_handle *handle
	pos, result['handle'] = msrpctypes.unmarshall_policy_handle(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (svcctl.openservicew)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (svcctl.openservicew)"
	end

	return true, result
end

--- Calls the function <code>StartServiceW</code>, which starts a service. Requires a handle
-- created by <code>OpenServiceW</code>. 
--
--@param smbstate The SMB state table.
--@param handle   The handle, opened by <code>OpenServiceW</code>.
--@param args     An array of strings representing the arguments. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values
--        representing the "out" parameters.
function svcctl_startservicew(smbstate, handle, args)
	local i, j
	local status, result
	local arguments
	local pos, align
	stdnse.print_debug(2, "MSRPC: Calling StartServiceW() [%s]", smbstate['ip'])

--        [in,ref] policy_handle *handle,
	arguments = msrpctypes.marshall_policy_handle(handle)

--        [in] uint32 NumArgs,
	if(args == nil) then
		arguments = arguments .. msrpctypes.marshall_int32(0)
	else
		arguments = arguments .. msrpctypes.marshall_int32(#args)
	end

--        [in/*FIXME:,length_is(NumArgs)*/] [string,charset(UTF16)] uint16 *Arguments
	arguments = arguments .. msrpctypes.marshall_unicode_array_ptr(args, true)

	-- Do the call
	status, result = call_function(smbstate, 0x13, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: StartServiceW() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--        [in,ref] policy_handle *handle,
--        [in] uint32 NumArgs,
--        [in/*FIXME:,length_is(NumArgs)*/] [string,charset(UTF16)] uint16 *Arguments

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (svcctl.startservicew)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (svcctl.startservicew)"
	end

	return true, result

end

--- Calls the function <code>ControlService</code>, which can send various commands to the service. 
--
--@param smbstate The SMB state table.
--@param handle   The handle, opened by <code>OpenServiceW</code>.
--@param control  The command to send. See <code>svcctl_ControlCode</code> in <code>msrpctypes.lua</code>. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values
--        representing the "out" parameters.
function svcctl_controlservice(smbstate, handle, control)
	local i, j
	local status, result
	local arguments
	local pos, align

	stdnse.print_debug(2, "MSRPC: Calling ControlService() [%s]", smbstate['ip'])

--        [in,ref] policy_handle *handle,
	arguments = msrpctypes.marshall_policy_handle(handle)

--        [in] uint32 control,
	arguments = arguments .. msrpctypes.marshall_svcctl_ControlCode(control)

--        [out,ref] SERVICE_STATUS *service_status


	-- Do the call
	status, result = call_function(smbstate, 0x01, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: ControlService() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--        [in,ref] policy_handle *handle,
--        [in] uint32 control,
--        [out,ref] SERVICE_STATUS *service_status
	pos, result['service_status'] = msrpctypes.unmarshall_SERVICE_STATUS(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (svcctl.controlservice)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (svcctl.controlservice)"
	end

	return true, result

end


--- Calls the function <code>QueryServiceStatus</code>, which gets the state information about the service. 
--
--@param smbstate The SMB state table.
--@param handle   The handle, opened by <code>OpenServiceW</code>.
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values
--        representing the "out" parameters.
function svcctl_queryservicestatus(smbstate, handle, control)
	local i, j
	local status, result
	local arguments
	local pos, align

	stdnse.print_debug(2, "MSRPC: Calling QueryServiceStatus() [%s]", smbstate['ip'])

--        [in,ref] policy_handle *handle,
	arguments = msrpctypes.marshall_policy_handle(handle)

--        [out,ref] SERVICE_STATUS *service_status


	-- Do the call
	status, result = call_function(smbstate, 0x06, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: QueryServiceStatus() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--        [in,ref] policy_handle *handle,
--        [out,ref] SERVICE_STATUS *service_status
	pos, result['service_status'] = msrpctypes.unmarshall_SERVICE_STATUS(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (svcctl.queryservicestatus)"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (svcctl.queryservicestatus)"
	end

	return true, result
end

---Calls the function <code>JobAdd</code>, which schedules a process to be run on the remote 
-- machine. This requires administrator privileges to run, and the command itself runs as
-- SYSTEM. 
--@param smbstate The SMB state table.
--@param server   The IP or Hostname of the server (seems to be ignored but it's a good idea to have it)
--@param command  The command to run on the remote machine. The appropriate file(s) already 
--                have to be there, and this should be a full path. 
--@param time     (optional) The time at which to run the command. Default: 5 seconds from 
--                when the user logged in. 
function atsvc_jobadd(smbstate, server, command, time)
	local i, j
	local status, result
	local arguments
	local pos, align

	-- Set up the time
	if(time == nil) then
		-- TODO
	end

	stdnse.print_debug(2, "MSRPC: Calling AddJob(%s) [%s]", command, smbstate['ip'])

--        [in,unique,string,charset(UTF16)] uint16 *servername,
	arguments = msrpctypes.marshall_unicode_ptr(server, true)

--        [in] atsvc_JobInfo *job_info,
	arguments = arguments .. msrpctypes.marshall_atsvc_JobInfo(command, time)
--        [out,ref]    uint32 *job_id


	-- Do the call
	status, result = call_function(smbstate, 0x00, arguments)
	if(status ~= true) then
		return false, result
	end

	stdnse.print_debug(3, "MSRPC: AddJob() returned successfully")

	-- Make arguments easier to use
	arguments = result['arguments']
	pos = 1

--        [in,unique,string,charset(UTF16)] uint16 *servername,
--        [in] atsvc_JobInfo *job_info,
--        [out,ref]    uint32 *job_id
	pos, result['job_id'] = msrpctypes.unmarshall_int32(arguments, pos)

	pos, result['return'] = msrpctypes.unmarshall_int32(arguments, pos)
	if(result['return'] == nil) then
		return false, "Read off the end of the packet (atsvc.addjob())"
	end
	if(result['return'] ~= 0) then
		return false, smb.get_status_name(result['return']) .. " (atsvc.addjob())"
	end

	return true, result
end

---Attempt to enumerate users using SAMR functions. 
--
--@param host The host object. 
--@return (status, result) If status is false, result is an error message. Otherwise, result
-- is an array of tables, each of which contain the following fields:
-- * name
-- * fullname
-- * description
-- * rid
-- * domain
-- * typestr
-- * source
-- * flags[]
function samr_enum_users(host)
	local i, j

	local smbstate
	local bind_result, connect4_result, enumdomains_result
	local connect_handle
	local status, smbstate
	local response = {}

	-- Create the SMB session
	status, smbstate = start_smb(host, SAMR_PATH, true)

	if(status == false) then
		return false, smbstate
	end

	-- Bind to SAMR service
	status, bind_result = bind(smbstate, SAMR_UUID, SAMR_VERSION, nil)
	if(status == false) then
		stop_smb(smbstate)
		return false, bind_result
	end

	-- Call connect4()
	status, connect4_result = samr_connect4(smbstate, host.ip)
	if(status == false) then
		stop_smb(smbstate)
		return false, connect4_result
	end

	-- Save the connect_handle
	connect_handle = connect4_result['connect_handle']

	-- Call EnumDomains()
	status, enumdomains_result = samr_enumdomains(smbstate, connect_handle)
	if(status == false) then
		stop_smb(smbstate)
		return false, enumdomains_result
	end

	-- If no domains were returned, go back with an error
	if(#enumdomains_result['sam']['entries'] == 0) then
		stop_smb(smbstate)
		return false, "Couldn't find any domains"
	end

	-- Now, loop through the domains and find the users
	for i = 1, #enumdomains_result['sam']['entries'], 1 do

		local domain = enumdomains_result['sam']['entries'][i]['name']
		-- We don't care about the 'builtin' domain, in all my tests it's empty
		if(domain ~= 'Builtin') then
			-- Call LookupDomain()
			local status, lookupdomain_result = samr_lookupdomain(smbstate, connect_handle, domain)
			if(status == false) then
				stop_smb(smbstate)
				return false, lookupdomain_result
			end

			-- Save the sid
			local sid = lookupdomain_result['sid']
	
			-- Call OpenDomain()
			local status, opendomain_result = samr_opendomain(smbstate, connect_handle, sid)
			if(status == false) then
				stop_smb(smbstate)
				return false, opendomain_result
			end

			-- Save the domain handle
			local domain_handle = opendomain_result['domain_handle']

			-- Loop as long as we're getting valid results	
			j = 0
			repeat
				-- Call QueryDisplayInfo()
				local status, querydisplayinfo_result = samr_querydisplayinfo(smbstate, domain_handle, j, SAMR_GROUPSIZE)
				if(status == false) then
					stop_smb(smbstate)
					return false, querydisplayinfo_result
				end

				-- Save the response
				if(querydisplayinfo_result['info'] ~= nil and querydisplayinfo_result['info']['entries'] ~= nil) then
					local k
					for k = 1, #querydisplayinfo_result['info']['entries'], 1 do
						local array = {}
						local l
	
						-- The reason these are all indexed from '1' is because we request names one at a time. 
						array['name']        = querydisplayinfo_result['info']['entries'][k]['account_name']
						array['fullname']    = querydisplayinfo_result['info']['entries'][k]['full_name']
						array['description'] = querydisplayinfo_result['info']['entries'][k]['description']
						array['rid']         = querydisplayinfo_result['info']['entries'][k]['rid']
						array['domain']      = domain
						array['type']        = 'SID_NAME_USER'
						array['typestr']     = 'User'
						array['source']      = 'SAMR Enumeration'
						array['flags']       = querydisplayinfo_result['info']['entries'][k]['acct_flags']

						-- Convert each element in the 'flags' array into the equivalent string
						for l = 1, #array['flags'], 1 do
							array['flags'][l] = samr_AcctFlags_tostr(array['flags'][l])
						end
	
						-- Add it to the array
						response[#response + 1] = array
					end
				end
				j = j + SAMR_GROUPSIZE
			until querydisplayinfo_result['return'] == 0

			-- Close the domain handle
			samr_close(smbstate, domain_handle)
		end -- Checking for 'builtin'
	end -- Domain loop

	-- Close the connect handle
	samr_close(smbstate, connect_handle)

	-- Stop the SAMR SMB
	stop_smb(smbstate)

	return true, response
end

function samr_enum_groups(host)
	local i, j

	stdnse.print_debug(1, "MSRPC: Attempting to enumerate groups on %s", host.ip)
	-- Create the SMB session
	local status, smbstate = start_smb(host, SAMR_PATH, true)

	if(status == false) then
		return false, smbstate
	end

	-- Bind to SAMR service
	local status, bind_result = bind(smbstate, SAMR_UUID, SAMR_VERSION, nil)
	if(status == false) then
		stop_smb(smbstate)
		return false, bind_result
	end

	-- Call connect4()
	local status, connect4_result = samr_connect4(smbstate, host.ip)
	if(status == false) then
		stop_smb(smbstate)
		return false, connect4_result
	end

	-- Save the connect_handle
	local connect_handle = connect4_result['connect_handle']

	-- Call EnumDomains()
	local status, enumdomains_result = samr_enumdomains(smbstate, connect_handle)
	if(status == false) then
		stop_smb(smbstate)
		return false, enumdomains_result
	end

	-- If no domains were returned, go back with an error
	if(#enumdomains_result['sam']['entries'] == 0) then
		stop_smb(smbstate)
		return false, "Couldn't find any domains"
	end

	-- Now, loop through the domains and find the groups
	local domains = {}
	for _, domain in ipairs(enumdomains_result['sam']['entries']) do
		-- Get a handy domain name
		domain = domain['name']
		domains[domain] = {}

		-- Call LookupDomain()
		local status, lookupdomain_result = samr_lookupdomain(smbstate, connect_handle, domain)
		if(status == false) then
			stop_smb(smbstate)
			return false, lookupdomain_result
		end

		-- Save the sid
		local domain_sid = lookupdomain_result['sid']

		-- Call OpenDomain()
		local status, opendomain_result = samr_opendomain(smbstate, connect_handle, domain_sid)
		if(status == false) then
			stop_smb(smbstate)
			return false, opendomain_result
		end

		-- Save the domain handle
		local domain_handle = opendomain_result['domain_handle']

		-- Get a list of groups
		local status, enumaliases_result = samr_enumdomainaliases(smbstate, domain_handle)
		if(status == false) then
			stop_smb(smbstate)
			return false, "Couldn't enumerate groups: " .. enumaliases_result
		end

		-- If it returned a nil array
		if(enumaliases_result['sam'] == nil or enumaliases_result['sam']['entries'] == nil) then
			return false, "ERROR: No groups returned by samr_EnumDomainAliases()"
		end

		-- Print some output
		stdnse.print_debug(1, "MSRPC: Found %d groups in %s", #enumaliases_result['sam']['entries'], domain)

		-- Record the results
		local group_rids = {}
		for _, group in ipairs(enumaliases_result['sam']['entries']) do
			-- The RID
			local group_rid = group['idx']

			-- Keep a list of just RIDs, for easier lookup after
			table.insert(group_rids, group_rid)

			-- Save the output, this is what will be returned
			domains[domain][group_rid] = {}
			domains[domain][group_rid]['name'] = group['name']
		end -- Loop over group entries

		for _, group_rid in ipairs(group_rids) do
			-- Get a handle to the alias
			local status, openalias_result = samr_openalias(smbstate, domain_handle, group_rid)
			if(not(status)) then
				stop_smb(smbstate)
				return false, "Couldn't open handle to group: " .. openalias_result
			end
			local group_handle = openalias_result['alias_handle']

			-- Get the members of the group
			local status, getmembers_result = samr_getmembersinalias(smbstate, group_handle)
			if(not(status)) then
				stop_smb(smbstate)
				return false, "Couldn't get members in group: " .. getmembers_result
			end

			-- Save the SIDs
			local member_sids = {}
			if(getmembers_result and getmembers_result.sids and getmembers_result.sids.sids) then
				-- Set the list of member_sids
				member_sids = getmembers_result.sids.sids
			end

			-- Print some output
			stdnse.print_debug(1, "MSRPC: Adding group '%s' (RID: %d) with %d members", domains[domain][group_rid]['name'], group_rid, #member_sids)

			-- Save the output
			domains[domain][group_rid]['member_sids'] = member_sids

			-- Close the group
			samr_close(smbstate, group_handle)
		end -- Loop over group RIDs

		-- Close the domain handle
		samr_close(smbstate, domain_handle)

	end -- Domain loop

	-- Close the connect handle
	samr_close(smbstate, connect_handle)

	-- Stop the SAMR SMB
	stop_smb(smbstate)


	-- Now, we need a handle to LSA (in order to convert the RIDs to users
	-- Create the SMB session
	local status, smbstate = start_smb(host, LSA_PATH, true)
	if(status == false) then
		return false, smbstate
	end

	-- Bind to LSA service
	local status, bind_result = bind(smbstate, LSA_UUID, LSA_VERSION, nil)
	if(status == false) then
		stop_smb(smbstate)
		return false, bind_result
	end

	-- Open the LSA policy
	local status, openpolicy2_result = lsa_openpolicy2(smbstate, host.ip)
	if(status == false) then
		stop_smb(smbstate)
		return false, openpolicy2_result
	end

	-- Loop through the domains
	for domain, domain_data in pairs(domains) do
		for group_rid, group in pairs(domain_data) do
			-- Look up the SIDs
			local status, lookupsids2_result = lsa_lookupsids2(smbstate, openpolicy2_result['policy_handle'], group['member_sids'])
			if(status == false) then
				stop_smb(smbstate)
				return false, "Error looking up RIDs: " .. lookupsids2_result
			end

			if(lookupsids2_result and lookupsids2_result.names and lookupsids2_result.names.names and (#lookupsids2_result.names.names > 0)) then
				local members = {}
				for _, resolved_name in ipairs(lookupsids2_result.names.names) do
					if(resolved_name.sid_type == "SID_NAME_USER") then
						table.insert(members, resolved_name.name)
					end
				end
				domains[domain][group_rid]['members'] = members
			else
				domains[domain][group_rid]['members'] = {}
			end
		end
	end

	-- Close the handle
	lsa_close(smbstate, openpolicy2_result['policy_handle'])

	stop_smb(smbstate)

	return true, domains
end

---Attempt to enumerate users using LSA functions.
--
--@param host The host object. 
--@return status, result -- if status is false, result is an error message; otherwise, result is 
--        an array of tables, each containing the following elements:
-- * name
-- * rid
-- * domain
-- * typestr
-- * source
function lsa_enum_users(host)

	local smbstate
	local response = {}
	local status, smbstate, bind_result, openpolicy2_result, lookupnames2_result, lookupsids2_result

	-- Create the SMB session
	status, smbstate = start_smb(host, LSA_PATH, true)
	if(status == false) then
		return false, smbstate
	end

	-- Bind to LSA service
	status, bind_result = bind(smbstate, LSA_UUID, LSA_VERSION, nil)
	if(status == false) then
		stop_smb(smbstate)
		return false, bind_result
	end

	-- Open the LSA policy
	status, openpolicy2_result = lsa_openpolicy2(smbstate, host.ip)
	if(status == false) then
		stop_smb(smbstate)
		return false, openpolicy2_result
	end

	-- Start with some common names, as well as the name returned by the negotiate call
	-- Vista doesn't like a 'null' after the server name, so fix that (TODO: the way I strip the null here feels hackish, is there a better way?)
	local names = {"administrator", "guest", "test"}
	-- These aren't always sent back (especially with 'extended security')
	if(smbstate['domain'] ~= nil) then
		names[#names + 1] = smbstate['domain']
	end
	if(smbstate['server'] ~= nil) then
		names[#names + 1] = string.sub(smbstate['server'], 1, #smbstate['server'] - 1) 
	end

	-- Get the server's name from nbstat
	local result, server_name = netbios.get_server_name(host.ip)
	if(result == true) then
		names[#names + 1] = server_name
	end

	-- Get the logged in user from nbstat
	local result, user_name = netbios.get_user_name(host.ip)
	if(result == true) then
		names[#names + 1] = user_name
	end

	-- Look up the names, if any are valid than the server's SID will be returned
	status, lookupnames2_result = lsa_lookupnames2(smbstate, openpolicy2_result['policy_handle'], names)
	if(status == false) then
		stop_smb(smbstate)
		return false, lookupnames2_result
	end
	-- Loop through the domains returned and find the users in each
	for i = 1, #lookupnames2_result['domains']['domains'], 1 do
		local domain = lookupnames2_result['domains']['domains'][i]['name']
		local sid	= lookupnames2_result['domains']['domains'][i]['sid']
		local sids   = { }

		-- Start by looking up 500 and up
		for j = 500, 500 + LSA_GROUPSIZE, 1 do 
			sids[#sids + 1] = sid .. "-" .. j 
		end

		status, lookupsids2_result = lsa_lookupsids2(smbstate, openpolicy2_result['policy_handle'], sids)
		if(status == false) then
			stdnse.print_debug(1, string.format("Error looking up RIDs: %s", lookupsids2_result))
		else
			-- Put the details for each name into an array
			-- NOTE: Be sure to mirror any changes here in the next bit! 
			for j = 1, #lookupsids2_result['names']['names'], 1 do
				if(lookupsids2_result['names']['names'][j]['sid_type'] == "SID_NAME_USER") then
					local result = {}
					result['name']    = lookupsids2_result['names']['names'][j]['name']
					result['rid']	  = 500 + j - 1
					result['domain']  = domain
					result['type']    = lookupsids2_result['names']['names'][j]['sid_type']
					result['typestr'] = lsa_SidType_tostr(result['type'])
					result['source']  = "LSA Bruteforce"
					table.insert(response, result)
				end
			end
		end

		-- Start at RID 1000
		local start      = 1000
		-- Keep track of the number of consecutive empty groups
		local empty      = 0
		repeat
			-- Keep track of the number of names we found in this group
			local used_names = 0

			local sids = {}
			for j = start, start + LSA_GROUPSIZE, 1 do 
				sids[#sids + 1] = sid .. "-" .. j
			end

			-- Try converting this group of RIDs into names
			status, lookupsids2_result = lsa_lookupsids2(smbstate, openpolicy2_result['policy_handle'], sids)
			if(status == false) then
				stdnse.print_debug(1, string.format("Error looking up RIDs: %s", lookupsids2_result))
			else
				-- Put the details for each name into an array
				for j = 1, #lookupsids2_result['names']['names'], 1 do
					-- Determine the RID
					local name = lookupsids2_result['names']['names'][j]['name']
					local rid = start + j - 1
					local typenum = lookupsids2_result['names']['names'][j]['sid_type']
					local typestr = lsa_SidType_tostr(typenum)

					-- Check if the username matches the rid (one server we discovered returned every user as valid, 
					-- this is to prevent that infinite loop)
					if(tonumber(name) ~= rid) then
						if(lookupsids2_result['names']['names'][j]['sid_type'] == "SID_NAME_USER") then
							local result = {}
							result['name']    = name
							result['rid']	  = rid
							result['domain']  = domain
							result['type']    = typenum
							result['typestr'] = typestr
							result['source']  = "LSA Bruteforce"
							table.insert(response, result)
	
							-- Increment the number of names we've found
							used_names = used_names + 1
						end
					end
				end
			end


			-- Either increment or reset the number of empty groups
			if(used_names == 0) then
				empty = empty + 1
			else
				empty = 0
			end

			-- Go to the next set of RIDs
			start = start + LSA_GROUPSIZE
		until (status == false or (empty == LSA_MINEMPTY))
	end

	-- Close the handle
	lsa_close(smbstate, openpolicy2_result['policy_handle'])

	stop_smb(smbstate)

	return true, response
end

---Gets the best possible list of user accounts on the remote system using every available method. 
--
-- TODO: Caching, store this in the registry
--
--@param host The host object. 
--@return (status, result, names) If status is false, result is an error message; otherwise, result
--        is an array of users indexed by username and names is a sorted array of names. 
function get_user_list(host)
	local status_samr, result_samr
	local status_lsa,  result_lsa
	local response = {}
	local names = {}
	local i, v

	status_lsa,  result_lsa  = lsa_enum_users(host)
	if(status_lsa == false) then
		stdnse.print_debug("MSRPC: Failed to enumerate users through LSA: %s", result_lsa)
	else
		for i = 1, #result_lsa, 1 do
			if(result_lsa[i]['name'] ~= nil and result_lsa[i]['type'] == "SID_NAME_USER") then
				response[result_lsa[i]['domain'] .. '\\' .. result_lsa[i]['name']] = result_lsa[i]
			end
		end
	end

	status_samr, result_samr = samr_enum_users(host)
	if(status_samr == false) then
		stdnse.print_debug("MSRPC: Failed to enumerate users through SAMR: %s", result_samr)
	else
		for i = 1, #result_samr, 1 do
			if(result_samr[i]['name'] ~= nil and result_samr[i]['type'] == "SID_NAME_USER") then
				response[result_samr[i]['domain'] .. '\\' .. result_samr[i]['name']] = result_samr[i]
			end
		end
	end

	if(status_samr == false and status_lsa == false) then
		return false, "MSRPC: Couldn't enumerate users; see debug output for more information"
	end

	for i, v in pairs(response) do
		table.insert(names, i)
	end
	table.sort(names, function(a,b) return a:lower() < b:lower() end )

	return true, response, names
end

---Retrieve information about a domain. This is done by three seperate calls to samr_querydomaininfo2() to get all
-- possible information. smbstate has to be in the proper state for this to work. 
local function get_domain_info(host, domain)
	local result = {}
	local status, smbstate, bind_result, connect4_result, lookupdomain_result, opendomain_result, enumdomainusers_result

	-- Create the SMB session
	status, smbstate  = msrpc.start_smb(host, msrpc.SAMR_PATH)
	if(status == false) then
		return false, smbstate
	end

	-- Bind to SAMR service
	status, bind_result = msrpc.bind(smbstate, msrpc.SAMR_UUID, msrpc.SAMR_VERSION, nil)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, bind_result
	end

	-- Call connect4()
	status, connect4_result = msrpc.samr_connect4(smbstate, host.ip)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, connect4_result
	end

	-- Call LookupDomain()
	status, lookupdomain_result = msrpc.samr_lookupdomain(smbstate, connect4_result['connect_handle'], domain)
	if(status == false) then
		msrpc.samr_close(smbstate, connect4_result['connect_handle'])
		msrpc.stop_smb(smbstate)
		return false, "Couldn't look up the domain: " .. lookupdomain_result
	end

	-- Call OpenDomain()
	status, opendomain_result = msrpc.samr_opendomain(smbstate, connect4_result['connect_handle'], lookupdomain_result['sid'])
	if(status == false) then
		msrpc.samr_close(smbstate, connect4_result['connect_handle'])
		msrpc.stop_smb(smbstate)
		return false, opendomain_result
	end

	-- Call QueryDomainInfo2() to get domain properties. We call these for three types -- 1, 8, and 12, since those return
	-- the most useful information. 
	local status_1,  querydomaininfo2_result_1  = msrpc.samr_querydomaininfo2(smbstate, opendomain_result['domain_handle'], 1)
	local status_8,  querydomaininfo2_result_8  = msrpc.samr_querydomaininfo2(smbstate, opendomain_result['domain_handle'], 8)
	local status_12, querydomaininfo2_result_12 = msrpc.samr_querydomaininfo2(smbstate, opendomain_result['domain_handle'], 12)

	if(status_1 == false) then
		msrpc.samr_close(smbstate, connect4_result['connect_handle'])
		msrpc.stop_smb(smbstate)
		return false, querydomaininfo2_result_1
	end

	if(status_8 == false) then
		msrpc.samr_close(smbstate, connect4_result['connect_handle'])
		msrpc.stop_smb(smbstate)
		return false, querydomaininfo2_result_8
	end

	if(status_12 == false) then
		msrpc.samr_close(smbstate, connect4_result['connect_handle'])
		msrpc.stop_smb(smbstate)
		return false, querydomaininfo2_result_12
	end

	-- Call EnumDomainUsers() to get users
	status, enumdomainusers_result = msrpc.samr_enumdomainusers(smbstate, opendomain_result['domain_handle'])
	if(status == false) then
		msrpc.samr_close(smbstate, connect4_result['connect_handle'])
		msrpc.stop_smb(smbstate)
		return false, enumdomainusers_result
	end

	-- Call EnumDomainAliases() to get groups
	local status, enumdomaingroups_result = msrpc.samr_enumdomainaliases(smbstate, opendomain_result['domain_handle'])
	if(status == false) then
		msrpc.samr_close(smbstate, connect4_result['connect_handle'])
		msrpc.stop_smb(smbstate)
		return false, enumdomaingroups_result
	end

	-- Close the domain handle
	msrpc.samr_close(smbstate, opendomain_result['domain_handle'])
	-- Close the smb session
	msrpc.stop_smb(smbstate)

	-- Create a list of groups
	local groups = {}
	if(enumdomaingroups_result['sam'] ~= nil and enumdomaingroups_result['sam']['entries'] ~= nil) then
		for _, group in ipairs(enumdomaingroups_result['sam']['entries']) do
			table.insert(groups, group.name)
		end
	end

	-- Create the list of users
	local names = {}
	if(enumdomainusers_result['sam'] ~= nil and enumdomainusers_result['sam']['entries'] ~= nil) then
		for _, name in ipairs(enumdomainusers_result['sam']['entries']) do
			table.insert(names, name.name)
		end
	end

	-- Our output table
	local response = {}

	-- Finally, start filling in the response!
	response['name'] = domain
	response['sid']  = lookupdomain_result['sid']
	response['groups'] = groups
	response['users'] = names
	if(querydomaininfo2_result_8['info']['domain_create_time'] ~= 0) then
		response['created'] = os.date("%Y-%m-%d %H:%M:%S", querydomaininfo2_result_8['info']['domain_create_time'])
	else
		response['created'] = "unknown"
	end

	-- Password characteristics
	response['min_password_length'] = querydomaininfo2_result_1['info']['min_password_length']
	response['max_password_age']    = querydomaininfo2_result_1['info']['max_password_age'] / 60 / 60 / 24
	response['min_password_age']    = querydomaininfo2_result_1['info']['min_password_age'] / 60 / 60 / 24
	response['password_history']    = querydomaininfo2_result_1['info']['password_history_length']
	response['lockout_duration']    = querydomaininfo2_result_12['info']['lockout_duration'] / 60
	response['lockout_threshold']   = querydomaininfo2_result_12['info']['lockout_threshold']
	response['lockout_window']      = querydomaininfo2_result_12['info']['lockout_window'] / 60

	-- Sanity check the different values, and remove them if they don't appear to be set
	if(response['min_password_length'] <= 0) then
		response['min_password_length'] = nil
	end

	if(response['max_password_age'] < 0 or response['max_password_age'] > 5000) then
		response['max_password_age'] = nil
	end

	if(response['min_password_age'] <= 0) then
		response['min_password_age'] = nil
	end

	if(response['password_history'] <= 0) then
		response['password_history'] = nil
	end

	if(response['lockout_duration'] <= 0) then
		response['lockout_duration'] = nil
	end

	if(response['lockout_threshold'] <= 0) then
		response['lockout_threshold'] = nil
	end

	if(response['lockout_window'] <= 0) then
		response['lockout_window'] = nil
	end

	local password_properties = querydomaininfo2_result_1['info']['password_properties']
	
	if(#password_properties > 0) then
		local password_properties_response = {}
		password_properties_response['name'] = "Password properties:"
		for j = 1, #password_properties, 1 do
			table.insert(password_properties_response, msrpc.samr_PasswordProperties_tostr(password_properties[j]))
		end

		response['password_properties'] = password_properties_response
	end

	return true, response
end

function get_domains(host)
	local result = {}
	local status, smbstate, bind_result, connect4_result, enumdomains_result
	local i, j

	-- Create the SMB session
	status, smbstate  = msrpc.start_smb(host, msrpc.SAMR_PATH)
	if(status == false) then
		return false, smbstate
	end

	-- Bind to SAMR service
	status, bind_result = msrpc.bind(smbstate, msrpc.SAMR_UUID, msrpc.SAMR_VERSION, nil)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, bind_result
	end

	-- Call connect4()
	status, connect4_result = msrpc.samr_connect4(smbstate, host.ip)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, connect4_result
	end

	-- Call EnumDomains()
	status, enumdomains_result = msrpc.samr_enumdomains(smbstate, connect4_result['connect_handle'])
	if(status == false) then
		msrpc.samr_close(smbstate, connect4_result['connect_handle'])
		msrpc.stop_smb(smbstate)

		return false, enumdomains_result
	end

	-- Close the connect handle
	msrpc.samr_close(smbstate, connect4_result['connect_handle'])

	-- Close the SMB session
	msrpc.stop_smb(smbstate)

	-- If no domains were returned, return an error (not sure that this can ever happen, but who knows?)
	if(#enumdomains_result['sam']['entries'] == 0) then
		return false, "No domains could be found"
	end

	local response = {}
	for i = 1, #enumdomains_result['sam']['entries'], 1 do
		local domain = enumdomains_result['sam']['entries'][i]['name']
		local status, domain_info = get_domain_info(host, domain)

		if(not(status)) then
			return false, "Couldn't get info for the domain: " .. domain_info
		else
			response[domain] = domain_info
		end

	end

	return true, response
end

---Create a "service" on a remote machine. This service is linked to an executable that is already
-- on the system. The name of the service can be whatever you want it to be. The service is created
-- in the "stopped" state with "manual" startup, and it ignores errors. The 'servicename' is what
-- people will see on the system while the service is running, and what'll stay there is something
-- happens that the service can't be deleted properly. 
--
-- Note that this (and the other "service" functions) are highly invasive. They make configuration
-- changes to the machine that can potentially affect stability. 
--
-- The reason that this and the other "service" functions don't require a <code>smbstate</code> 
-- object is that I wanted them to be independent. If a service fails to start, I don't want it 
-- to affect the program's ability to stop and delete the service. Every service function is
-- independent. 
--
--@param host        The host object. 
--@param servicename The name of the service to create. 
--@param path        The path and filename on the remote system. 
--@return (status, err) If status is <code>false</code>, <code>err</code> is an error message; 
--        otherwise, err is undefined. 
function service_create(host, servicename, path)
	local status, smbstate, bind_result, open_result, create_result, close_result

	stdnse.print_debug(1, "Creating service: %s (%s)", servicename, path)

	-- Create the SMB session
	status, smbstate = start_smb(host, SVCCTL_PATH)
	if(status == false) then
		return false, smbstate
	end

	-- Bind to SVCCTL service
	status, bind_result = bind(smbstate, SVCCTL_UUID, SVCCTL_VERSION, nil)
	if(status == false) then
		smb.stop(smbstate)
		return false, bind_result
	end

	-- Open the service manager
	stdnse.print_debug(2, "Opening the remote service manager")
	status, open_result = svcctl_openscmanagerw(smbstate, host.ip)
	if(status == false) then
		smb.stop(smbstate)
		return false, open_result
	end

	-- Create the service
	stdnse.print_debug(2, "Creating the service", servicename)
	status, create_result = svcctl_createservicew(smbstate, open_result['handle'], servicename, servicename, path)
	if(status == false) then
		smb.stop(smbstate)
		return false, create_result
	end
	-- Close the handle to the service
	status, close_result = svcctl_closeservicehandle(smbstate, create_result['handle'])
	if(status == false) then
		smb.stop(smbstate)
		return false, close_result
	end

	-- Close the service manager
	status, close_result = svcctl_closeservicehandle(smbstate, open_result['handle'])
	if(status == false) then
		smb.stop(smbstate)
		return false, close_result
	end

	smb.stop(smbstate)

	return true
end

---Start a service on the remote machine based on its name. For example, to start the registry 
-- service, this can be called on "RemoteRegistry". 
--
-- If you start a service on a machine, you should also stop it when you're finished. Every service
-- running is extra attack surface for a potential attacker
--
--@param host        The host object. 
--@param servicename The name of the service to start. 
--@param args        [optional] The arguments to pass to the service. Most built-in services don't
--                   require arguments. 
--@return (status, err) If status is <code>false</code>, <code>err</code> is an error message; 
--        otherwise, err is undefined. 
function service_start(host, servicename, args)
	local status, smbstate, bind_result, open_result, open_service_result, start_result, close_result, query_result

	stdnse.print_debug(1, "Starting service: %s", servicename)

	-- Create the SMB session
	status, smbstate = start_smb(host, SVCCTL_PATH)
	if(status == false) then
		return false, smbstate
	end

	-- Bind to SVCCTL service
	status, bind_result = bind(smbstate, SVCCTL_UUID, SVCCTL_VERSION, nil)
	if(status == false) then
		smb.stop(smbstate)
		return false, bind_result
	end

	-- Open the service manager
	stdnse.print_debug(1, "Opening the remote service manager")
	status, open_result = svcctl_openscmanagerw(smbstate, host.ip)
	if(status == false) then
		smb.stop(smbstate)
		return false, open_result
	end

	-- Get a handle to the service
	stdnse.print_debug(2, "Getting a handle to the service")
	status, open_service_result = svcctl_openservicew(smbstate, open_result['handle'], servicename)
	if(status == false) then
		smb.stop(smbstate)
		return false, open_service_result
	end

	-- Start it
	stdnse.print_debug(2, "Starting the service")
	status, start_result = svcctl_startservicew(smbstate, open_service_result['handle'], args)
	if(status == false) then
		smb.stop(smbstate)
		return false, start_result
	end

	-- Wait for it to start (TODO: Check the query result better)
	stdnse.print_debug(1, "Waiting for the service to start")
	repeat
		status, query_result = svcctl_queryservicestatus(smbstate, open_service_result['handle'])
		if(status == false) then
			smb.stop(smbstate)
			return false, query_result
		end
		stdnse.sleep(.5)
	until query_result['service_status']['controls_accepted'][1] == "SERVICE_CONTROL_STOP" or query_result['service_status']['state'][1] == "SERVICE_STATE_ACTIVE"

	-- Close the handle to the service
	status, close_result = svcctl_closeservicehandle(smbstate, open_service_result['handle'])
	if(status == false) then
		smb.stop(smbstate)
		return false, close_result
	end

	-- Close the service manager
	status, close_result = svcctl_closeservicehandle(smbstate, open_result['handle'])
	if(status == false) then
		smb.stop(smbstate)
		return false, close_result
	end

	smb.stop(smbstate)

	return true
end

---Stop a service on the remote machine based on its name. For example, to stop the registry 
-- service, this can be called on "RemoteRegistry". 
--
-- This can be called on a service that's already stopped without hurting anything (just keep in mind
-- that an error will be returned). 
-- 
--@param host        The host object. 
--@param servicename The name of the service to stop. 
--@return (status, err) If status is <code>false</code>, <code>err</code> is an error message; 
--        otherwise, err is undefined. 
function service_stop(host, servicename)
	local status, smbstate, bind_result, open_result, open_service_result, control_result, close_result, query_result

	stdnse.print_debug(1, "Stopping service: %s", servicename)

	-- Create the SMB session
	status, smbstate = start_smb(host, SVCCTL_PATH)
	if(status == false) then
		return false, smbstate
	end

	-- Bind to SVCCTL service
	status, bind_result = bind(smbstate, SVCCTL_UUID, SVCCTL_VERSION, nil)
	if(status == false) then
		smb.stop(smbstate)
		return false, bind_result
	end

	-- Open the service manager
	stdnse.print_debug(2, "Opening the remote service manager")
	status, open_result = svcctl_openscmanagerw(smbstate, host.ip)
	if(status == false) then
		smb.stop(smbstate)
		return false, open_result
	end

	-- Get a handle to the service
	stdnse.print_debug(2, "Getting a handle to the service")
	status, open_service_result = svcctl_openservicew(smbstate, open_result['handle'], servicename)
	if(status == false) then
		smb.stop(smbstate)
		return false, open_service_result
	end

	-- Stop it
	stdnse.print_debug(2, "Stopping the service")
	status, control_result = svcctl_controlservice(smbstate, open_service_result['handle'], "SERVICE_CONTROL_STOP")
	if(status == false) then
		smb.stop(smbstate)
		return false, control_result
	end

	-- Wait for it to stop (TODO: Check the query result better)
	stdnse.print_debug(2, "Waiting for the service to stop")
	repeat
		status, query_result = svcctl_queryservicestatus(smbstate, open_service_result['handle'])
		if(status == false) then
			smb.stop(smbstate)
			return false, query_result
		end
		stdnse.sleep(.5)
	until query_result['service_status']['controls_accepted'][1] == nil

	-- Close the handle to the service
	status, close_result = svcctl_closeservicehandle(smbstate, open_service_result['handle'])
	if(status == false) then
		smb.stop(smbstate)
		return false, close_result
	end

	-- Close the service manager
	status, close_result = svcctl_closeservicehandle(smbstate, open_result['handle'])
	if(status == false) then
		smb.stop(smbstate)
		return false, close_result
	end

	smb.stop(smbstate)

	return true
end 

---Delete a service on the remote machine based on its name. I don't recommend deleting any services that
-- you didn't create. 
-- 
--@param host        The host object. 
--@param servicename The name of the service to delete. 
--@return (status, err) If status is <code>false</code>, <code>err</code> is an error message; 
--        otherwise, err is undefined. 
function service_delete(host, servicename)
	local status, smbstate, bind_result, open_result, open_service_result, delete_result, close_result

	stdnse.print_debug(1, "Deleting service: %s", servicename)

	-- Create the SMB session
	status, smbstate = start_smb(host, SVCCTL_PATH)
	if(status == false) then
		return false, smbstate
	end

	-- Bind to SVCCTL service
	status, bind_result = bind(smbstate, SVCCTL_UUID, SVCCTL_VERSION, nil)
	if(status == false) then
		smb.stop(smbstate)
		return false, bind_result
	end

	-- Open the service manager
	stdnse.print_debug(2, "Opening the remote service manager")
	status, open_result = svcctl_openscmanagerw(smbstate, host.ip)
	if(status == false) then
		smb.stop(smbstate)
		return false, open_result
	end

	-- Get a handle to the service
	stdnse.print_debug(2, "Getting a handle to the service: %s", servicename)
	status, open_service_result = svcctl_openservicew(smbstate, open_result['handle'], servicename)
	if(status == false) then
		smb.stop(smbstate)
		return false, open_service_result
	end

	-- Delete the service
	stdnse.print_debug(2, "Deleting the service")
	status, delete_result = svcctl_deleteservice(smbstate, open_service_result['handle'])
	if(status == false) then
		smb.stop(smbstate)
		return false, delete_result
	end

	-- Close the handle to the service
	status, close_result = svcctl_closeservicehandle(smbstate, open_service_result['handle'])
	if(status == false) then
		smb.stop(smbstate)
		return false, close_result
	end

	-- Close the service manager
	status, close_result = svcctl_closeservicehandle(smbstate, open_result['handle'])
	if(status == false) then
		smb.stop(smbstate)
		return false, close_result
	end

	smb.stop(smbstate)

	return true
end

---Retrieves statistical information about the given server. This function requires administrator privileges
-- to run, and is present on all Windows versions, so it's a useful way to check whether or not an account
-- is administrative. 
--@param host       The host object
--@return (status, data) If status is false, data is an error message; otherwise, data is a table of information
--        about the server. 
function get_server_stats(host)
	local stats
	local status
	local smbstate

	-- Create the SMB session
	status, smbstate = start_smb(host, SRVSVC_PATH)
	if(status == false) then
		return false, smbstate
	end
   
	-- Bind to SRVSVC service
	local status, bind_result = bind(smbstate, SRVSVC_UUID, SRVSVC_VERSION, nil)
	if(status == false) then
		smb.stop(smbstate)
		return false, bind_result
	end
   
	-- Call netservergetstatistics for 'server'
	local status, netservergetstatistics_result = srvsvc_netservergetstatistics(smbstate, host.ip)
	if(status == false) then
		smb.stop(smbstate)
		return false, netservergetstatistics_result
	end
   
	-- Stop the session
	smb.stop(smbstate)
   
	-- Build the response   
	local stats = netservergetstatistics_result['stat']

	-- Convert the date to a string
	stats['start_str'] = os.date("%Y-%m-%d %H:%M:%S", stats['start'])

	-- Get the period and convert it to a proper time offset
	stats['period'] = os.time() - stats['start']
	if(stats['period'] > 60 * 60 * 24) then
		stats['period_str'] = string.format("%dd%dh%02dm%02ds", stats['period'] / (60*60*24), (stats['period'] % (60*60*24)) / 3600, (stats['period'] % 3600) / 60, stats['period'] % 60)
	elseif(stats['period'] > 60 * 60) then
		stats['period_str'] = string.format("%dh%02dm%02ds", stats['period'] / 3600, (stats['period'] % 3600) / 60, stats['period'] % 60)
	else
		stats['period_str'] = string.format("%02dm%02ds", stats['period'] / 60, stats['period'] % 60)
	end
   
	-- Combine the 64-bit values
	stats['bytessent'] = bit.bor(bit.lshift(stats['bytessent_high'], 32), stats['bytessent_low'])
	stats['bytesrcvd'] = bit.bor(bit.lshift(stats['bytesrcvd_high'], 32), stats['bytesrcvd_low'])

	-- Sidestep divide-by-zero errors (probabyl won't come up, but I'd rather be safe)
	if(stats['period'] == 0) then
		stats['period'] = 1
	end
   
  	-- Get the bytes/second values
	stats['bytessentpersecond'] = stats['bytessent'] / stats['period']
	stats['bytesrcvdpersecond'] = stats['bytesrcvd'] / stats['period']

	return true, stats
end

---Attempts to enumerate the shares on a remote system using MSRPC calls. Without a user account,
-- this will likely fail against a modern system, but will succeed against Windows 2000. 
--
--@param host The host object. 
--@return Status (true or false).
--@return List of shares (if status is true) or an an error string (if status is false).
function enum_shares(host)

	local status, smbstate
	local bind_result, netshareenumall_result
	local shares
	local i, v

	-- Create the SMB session
	status, smbstate = start_smb(host, SRVSVC_PATH)
	if(status == false) then
		return false, smbstate
	end

	-- Bind to SRVSVC service
	status, bind_result = bind(smbstate, SRVSVC_UUID, SRVSVC_VERSION, nil)
	if(status == false) then
		smb.stop(smbstate) 
		return false, bind_result
	end

	-- Call netsharenumall
	status, netshareenumall_result = srvsvc_netshareenumall(smbstate, host.ip)
	if(status == false) then
		smb.stop(smbstate) 
		return false, netshareenumall_result
	end

	-- Stop the SMB session
	smb.stop(smbstate)

	-- Convert the share list to an array
	shares = {}
	for i, v in pairs(netshareenumall_result['ctr']['array']) do
		shares[#shares + 1] = v['name']
	end

	return true, shares
end


---Attempts to retrieve additional information about a share. Will fail unless we have 
-- administrative access. 
--
--@param host The host object. 
--@return Status (true or false).
--@return A table of information about the share (if status is true) or an an error string (if 
--        status is false).
function get_share_info(host, name)
	local response = {}

	-- Create the SMB session
	local status, smbstate = start_smb(host, SRVSVC_PATH)
	if(status == false) then
		return false, smbstate
	end

	-- Bind to SRVSVC service
	local status, bind_result = bind(smbstate, SRVSVC_UUID, SRVSVC_VERSION, nil)
	if(status == false) then
		smb.stop(smbstate) 
		return false, bind_result
	end

	-- Call NetShareGetInfo
	local status, netsharegetinfo_result = srvsvc_netsharegetinfo(smbstate, host.ip, name, 2)
	if(status == false) then
		smb.stop(smbstate) 
		return false, netsharegetinfo_result
	end

	smb.stop(smbstate)

	return true, netsharegetinfo_result
end

--####################################################################--
--#		1) RRAS RASRPC INTERFACE
--####################################################################--
ROUTER_PATH = "\\router" --also can be reached across "\\srvsvc" pipe in WinXP
RASRPC_UUID = string.char(0x36, 0x00, 0x61, 0x20, 0x22, 0xfa, 0xcf, 0x11, 0x98, 0x23, 0x00, 0xa0, 0xc9, 0x11, 0xe5, 0xdf)
RASRPC_VERSION = 1

--####################################################################--
--#		2) RRAS RASRPC TYPES
--####################################################################--

--####################################################################--
--typedef enum _ReqTypes{
--	REQTYPE_PORTENUM = 21,//Request to enumerate all the port information on the RRAS.
--	REQTYPE_GETINFO = 22,//Request to get information about a specific port on the RRAS.
--	REQTYPE_GETDEVCONFIG = 73,//Request to get device information on the RRAS.
--	REQTYPE_SETDEVICECONFIGINFO = 94,//Request to set device configuration information on RRAS.
--	REQTYPE_GETDEVICECONFIGINFO = 95,//Request to get device configuration information on RRAS.
--	REQTYPE_GETCALLEDID = 105,//Request to get CalledId information for a specific device on RRAS.
--	REQTYPE_SETCALLEDID = 106,//Request to set CalledId information for a specific device on RRAS.
--	REQTYPE_GETNDISWANDRIVERCAPS = 111//Request to get the encryption capabilities of the RRAS.
--} ReqTypes;
--- The <code>ReqTypes</code> enumerations indicate the different types of message requests that can be passed in
--the <code>RB_ReqType</code> field of <code>RequestBuffer</code> structure.
-- * [MS-RRASM] <code>2.2.1.1.18 ReqTypes</code>
--####################################################################--
RRAS_RegTypes = {}
RRAS_RegTypes['PORTENUM'] = 21
RRAS_RegTypes['GETINFO'] = 22
RRAS_RegTypes['GETDEVCONFIG'] = 73 --this method is vulnerable to ms06-025
RRAS_RegTypes['SETDEVICECONFIGINFO'] = 94
RRAS_RegTypes['GETDEVICECONFIGINFO'] = 95
RRAS_RegTypes['GETCALLEDID'] = 105
RRAS_RegTypes['SETCALLEDID'] = 106
RRAS_RegTypes['GETNDISWANDRIVERCAPS'] = 111

--####################################################################--
--typedef struct _RequestBuffer {
--	DWORD       RB_PCBIndex;//A unique identifier for the port.
--	ReqTypes    RB_Reqtype;//A ReqTypes enumeration value indicating the request type sent to the server.
--	DWORD       RB_Dummy;//MUST be set to the size of the ULONG_PTR on the client.
--	DWORD       RB_Done;//MBZ
--	LONGLONG    Alignment;//MBZ
--	BYTE        RB_Buffer[1];//variable size
--} RequestBuffer;
--- The <code>RequestBuffer</code> is a generic information container used by the <code>RasRpcSubmitRequest</code>
--method to set or retrieve information on RRAS server. This method performs
--serialization of <code>RequestBuffer</code> structure.
-- Note: This structure is not an IDL specification and as such is not translated into NDR.
-- @return Returns a blob of <code>RequestBuffer</code> structure.
-- * [MS-RRASM] <code>2.2.1.2.218 RequestBuffer</code>
--####################################################################--
function RRAS_marshall_RequestBuffer(RB_PCBIndex, RB_ReqType, RB_Buffer)
	local rb_blob, RB_Dummy, RB_Done, Alignment
	RB_Dummy = 4
	RB_Done = 0
	Alignment = 0
	rb_blob = bin.pack("<IIIILA",
		RB_PCBIndex,
		RB_ReqType,
		RB_Dummy,
		RB_Done,
		Alignment,
		RB_Buffer)
	return rb_blob
end

--####################################################################--
--#		3) RRAS RASRPC OPERATIONS
--####################################################################--
local RRAS_DEBUG_LVL = 2 --debug level for rras operations when calling stdnse.print_debug

--####################################################################--
--- RRAS operation numbers.
-- * [MS-RRASM] <code>3.3.4 Message Processing Events and Sequencing Rules</code>
--####################################################################--
RRAS_Opnums = {}
RRAS_Opnums["RasRpcDeleteEntry"] = 5
RRAS_Opnums["RasRpcGetUserPreferences"] = 9
RRAS_Opnums["RasRpcSetUserPreferences"] = 10
RRAS_Opnums["RasRpcGetSystemDirectory"] = 11
RRAS_Opnums["RasRpcSubmitRequest"] = 12
RRAS_Opnums["RasRpcGetInstalledProtocolsEx"] = 14
RRAS_Opnums["RasRpcGetVersion"] = 15

--####################################################################--
--DWORD RasRpcSubmitRequest(
--	[in] handle_t hServer,//An RPC binding handle. (not send)
--	[in, out, unique, size_is(dwcbBufSize)] PBYTE pReqBuffer,//A pointer to a buffer of size dwcbBufSize.
--	[in] DWORD dwcbBufSize//Size in byte of pReqBuffer.
--);
---The RasRpcSubmitRequest method retrieves or sets the configuration data on RRAS server.
-- @param smbstate The smb object.
-- @param pReqBuffer The buffer MUST be large enough to hold the <code>RequestBuffer</code>
--structure and <code>RequestBuffer.RB_Buffer</code> data. <code>RequestBuffer.RB_Reqtype</code>
--specifies the request type which will be processed by the server and
--<code>RequestBuffer.RB_Buffer</code> specifies the structure specific to <code>RB_Reqtype</code>
--to be processed. <code>RequestBuffer.RB_PCBIndex<code> MUST be set to the unique port identifier
--whose information is sought for <code>ReqTypes REQTYPE_GETINFO</code> and <code>REQTYPE_GETDEVCONFIG</code>.
--For other valid <code>ReqTypes</code>, <code>RequestBuffer.RB_PCBIndex</code> MUST be set to zero.
-- @param dwcbBufSize Integer representing the size of <code>pRegBuffer</code> in bytes.
-- @return (status, result)
--* <code>status == true</code> -> <code>result</code> is a blob that represent a <code>pRegBuffer</code> .
--* <code>status == false</code> -> <code>result</code> is a error message that caused the fuzz.
-- * [MS-RRASM] <code>3.3.4.5 RasRpcSubmitRequest (Opnum 12)</code>
--####################################################################--
function RRAS_SubmitRequest(smbstate, pReqBuffer, dwcbBufSize)
	--sanity check
	if(dwcbBufSize == nil) then
		dwcbBufSize = #pReqBuffer
	end
	--pack the request
	local req_blob
	--[in, out, unique, size_is(dwcbBufSize) PBYTE pReqBuffer,
	req_blob = bin.pack("<IIAA", 0x20000, dwcbBufSize, pReqBuffer, get_pad(pReqBuffer,4)) --unique pointer see samba:ndr_push_unique_ptr
	--[in] DWORD dwcbBufSize
	req_blob = req_blob .. msrpctypes.marshall_int32(dwcbBufSize)
	--call the function
	local status, result
	stdnse.print_debug(
		RRAS_DEBUG_LVL,
		"RRAS_SubmitRequest: Calling...")
	status, result = call_function(
		smbstate,
		RRAS_Opnums["RasRpcSubmitRequest"],
		req_blob)
	--sanity check
	if(status == false) then
		stdnse.print_debug(
			RRAS_DEBUG_LVL,
			"RRAS_SubmitRequest: Call function failed: %s",
			result)
		return false, result
	end
	stdnse.print_debug(
		RRAS_DEBUG_LVL,
		"RRAS_SubmitRequest: Returned successfully")
	--dissect the reply
	local rep_blob
	rep_blob = result
	return true, rep_blob
end

--####################################################################--
--#		1) DNS SERVER MANAGEMENT SERVICE INTERFACE
--####################################################################--
DNSSERVER_UUID_STR = "50abc2a4-574d-40b3-9d66-ee4fd5fba076"
DNSSERVER_UUID = string.char(0xa4, 0xc2,0xab, 0x50, 0x4d, 0x57, 0xb3, 0x40, 0x9d, 0x66, 0xee, 0x4f, 0xd5, 0xfb, 0xa0, 0x76)
DNSSERVER_PATH = "\\DNSSERVER"
DNSSERVER_VERSION = 5

--####################################################################--
--#		2) DNS SERVER MANAGEMENT SERVICE TYPES
--####################################################################--
---The list of names that are used in (name, value) pairs in DNS Server
--Configuration information is given below.
-- * [MS-DNSP] <code>3.1.1.1 DNS Server Configuration Information</code>
DNSSERVER_ConfInfo =
	{
	DNSSERVER_IntProp = {},
	DNSSERVER_AddrArrProp = {},
	DNSSERVER_StrProp = {},
	DNSSERVER_StrLstProp = {}
	}

--####################################################################--
--#		3) DNS SERVER MANAGEMENT SERVICE OPERATIONS
--####################################################################--
local DNSSERVER_DEBUG_LVL = 2 --debug level for dnsserver operations when calling stdnse.print_debug

--####################################################################--
--- DNSSERVER operation numbers.
-- * [MS-DNSP] <code>3.1.4 Message Processing Events and Sequencing Rules</code>
--####################################################################--
DNSSERVER_Opnums = {}
DNSSERVER_Opnums['R_DnssrvOperation'] = 0
DNSSERVER_Opnums['R_DnssrvQuery'] = 1
DNSSERVER_Opnums['R_DnssrvComplexOperation'] = 2
DNSSERVER_Opnums['R_DnssrvEnumRecords'] = 3
DNSSERVER_Opnums['R_DnssrvUpdateRecord'] = 4
DNSSERVER_Opnums['R_DnssrvOperation2'] = 5
DNSSERVER_Opnums['R_DnssrvQuery2'] = 6
DNSSERVER_Opnums['R_DnssrvComplexOperation2'] = 7
DNSSERVER_Opnums['R_DnssrvEnumRecords2'] = 8
DNSSERVER_Opnums['R_DnssrvUpdateRecord2'] = 9

--####################################################################--
--[[
LONG R_DnssrvQuery(
  [in, unique, string] LPCWSTR pwszServerName,
  [in, unique, string] LPCSTR pszZone,
  [in, unique, string] LPCSTR pszOperation,
  [out] PDWORD pdwTypeId,
  [out, switch_is(*pdwTypeId)] DNSSRV_RPC_UNION* ppData);
--]]
---Issues type specific information queries to server. This method is
--obsoleted by R_DnssrvQuery2.
-- @param smbstate The smb object.
-- @param server_name String that designates a fully qualified domain
--name of the target server. The server MUST ignore this value.
-- @param zone String that designates the name of the zone to be queried.
--For operations specific to a particular zone, this field MUST contain
--the name of the zone. For all other operations, this field MUST be nil.
-- @param operation String that designates the name of the operation to
--be performed on the server. These are two sets of allowed values for
--pszOperation:
--* <code>zone == nil</code> -> see DNSSERVER_ConfInfo table.
--* <code>zone == "some_zone"</code> -> see DNSSERVER_ZoneInfo table.
-- @return (status, result)
--* <code>status == true</code> ->
--that indicates the type of <code>result['data']</code>.
--** <code>result['data']</code> - A DNSSRV_RPC_UNION blob that contains a
--** <code>result['type_id']</code> - Integer that on success contains a value of type DNS_RPC_TYPEID
--data-structure as indicated by <code>result['type_id']</code>.
--* <code>status == false</code> ->
--** <code>result</code> - Is a error message that caused the fuzz.
-- * [MS-DNSP] <code>3.1.4.2 R_DnssrvQuery (Opnum 1)</code>
--####################################################################--
function DNSSERVER_Query(smbstate, server_name, zone, operation)
	local status
	--call
	local req_blob, srv_name_utf16, zone_ascii, operation_ascii
	--[in, unique, string] LPCWSTR pwszServerName,
	local unique_ptr
  	unique_ptr = 0x00020000
	srv_name_utf16 = msrpctypes.string_to_unicode(server_name, true)
	req_blob = bin.pack("<IIIIAA",
		unique_ptr,
		#srv_name_utf16/2,
		0,
		#srv_name_utf16/2,
		srv_name_utf16,
		get_pad(srv_name_utf16, 4))
	--[in, unique, string] LPCSTR pszZone,
  	if(zone == nil) then
		req_blob = bin.pack("<I", 0x00000000)
	else
		zone_ascii = zone .. string.char(0x00)
		req_blob = req_blob .. bin.pack("<IIIIAA",
			unique_ptr + 1,
			#zone_ascii,
			0,
			#zone_ascii,
			zone_ascii,
			get_pad(zone_ascii, 4))
	end
	--[in, unique, string] LPCSTR pszOperation,
  	operation_ascii = operation .. string.char(0x00)
	req_blob = req_blob .. bin.pack("<IIIIAA",
		unique_ptr+2,
		#operation_ascii,
		0,
		#operation_ascii,
		operation_ascii,
		get_pad(operation_ascii, 4))

	local call_result
	stdnse.print_debug(
		DNSSERVER_DEBUG_LVL,
		"DNSSERVER_Query: Calling...")
	status, call_result = call_function(
		smbstate,
		DNSSERVER_Opnums['R_DnssrvQuery'],
		req_blob)
	--sanity check
	if(status == false) then
		stdnse.print_debug(
			DNSSERVER_DEBUG_LVL,
			"DNSSERVER_Query: Call function failed: %s",
			call_result)
		return false, call_result
	end
	stdnse.print_debug(
		DNSSERVER_DEBUG_LVL,
		"DNSSERVER_Query: Returned successfully")
	--dissect the reply
	local rep_blob, pos, ptr, result
	rep_blob = call_result['arguments']
	--[out] PDWORD pdwTypeId,
	result = {}
	pos, result['type_id'] = msrpctypes.unmarshall_int32_ptr(rep_blob)
	--[out, switch_is(*pdwTypeId)] DNSSRV_RPC_UNION* ppData) -- pointer_default(unique)
	pos, ptr, result['data']= bin.unpack("<IA", rep_blob, pos)
	return result
end

--####################################################################--
--#		UTILITY
--###################################################################--

--####################################################################--
---Makes a pad for alignment
-- @param data Data which needs to be padded for the sake of alignment.
-- @param align Integer representing the alignment boundary.
-- @param pad_byte The value for pad byte. 
-- @return Returns the amount of pad calculated by <code>(align-datalen%align)%align</code>.
--####################################################################--
function get_pad(data, align, pad_byte)
	pad_byte = pad_byte or "\00"
	return string.rep(pad_byte, (align-#data%align)%align)
end

--####################################################################--
---Generates a random string of the requested length.
--@param length The length of the string to return.
--@param charset    The set of letters to choose from. Default: ASCII letters and numbers
--@return The random string. 
--####################################################################--
function random_crap(length, charset)
	charset = charset or "0123456789abcdefghijklmnoprstuvzxwyABCDEFGHIJKLMNOPRSTUVZXWY"
	local random_str = ""
	for i = 1, length, 1 do
                local random = math.random(#charset)
                random_str = random_str .. string.sub(charset, random, random)
        end
	return random_str
end
	
