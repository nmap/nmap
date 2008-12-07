--- By making heavy use of the 'smb' library, this library will call various MSRPC 
--  functions. The functions used here can be accessed over TCP ports 445 and 139, 
--  with an established session. A NULL session (the default) will work for some 
--  functions and operating systems (or configurations), but not for others. 
--
-- To make use of these function calls, a SMB session with the server has to be
-- established. This can be done manually with the <code>smb</code> library, or the function
-- <code>start_smb</code> can be called. A session has to be created, then the IPC$ 
-- tree opened. 
--
-- Next, the interface has to be bound. The bind() function will take care of that. 
--
-- After that, you're free to call any function that's part of that interface. In
-- other words, if you bind to the SAMR interface, you can only call the samr_
-- functions, for lsa_ functions, bind to the LSA interface, etc.  Although functions 
-- can technically be called in any order, many functions depend on the
-- value returned by other functions. I indicate those in the function comments, 
-- so keep an eye out. SAMR functions, for example, require a call to 
-- <code>connect4</code>. 
--
-- Something to note is that these functions, for the most part, return a whole ton
-- of stuff in a table; basically, everything that is returned by the function. 
-- Generally, if you want to know exactly what you have access to, either display the
-- returned data with a print_table-type function, or check the documentation (Samba 4.0's
-- .idl files (in samba_4.0/source/librpc/idl; see below for link) are what I based 
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
-- "idl" files for reference:
--  http://websvn.samba.org/cgi-bin/viewcvs.cgi/branches/SAMBA_4_0/source/librpc/idl/ 
-- I'm not a lawyer, but I don't expect that this is a breach of Samba's copyright -- 
-- if it is, please talk to me and I'll make arrangements to re-license this or to 
-- remove references to Samba. 
--
--@author Ron Bowes <ron@skullsecurity.net>
--@copyright See nmap's COPYING for licence
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

-- This is the only transfer syntax I've seen in the wild, not that I've looked hard. It seems to work well. 
TRANSFER_SYNTAX = string.char(0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60)

-- The 'referent_id' value is ignored, as far as I can tell, so this value is passed for it. No, it isn't random. :)
REFERENT_ID = 0x50414d4e

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
--@param smbstate The SMB state table. 
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

	stdnse.print_debug(3, "MSRPC: Received Bind() result")

	-- Make these easier to access. 
	parameters = result['parameters']
	data = result['data']

	-- Extract the first part from the resposne
	pos, result['version_major'], result['version_minor'], result['packet_type'], result['packet_flags'], result['data_representation'], result['frag_length'], result['auth_length'], result['call_id'] = bin.unpack("<CCCC>I<SSI", data)

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
	pos, result['max_transmit_frag'], result['max_receive_frag'], result['assoc_group'], result['secondary_address_length'] = bin.unpack("SSIS", data, pos)

	-- Read the secondary address
	pos, result['secondary_address'] = bin.unpack(string.format("<A%d", result['secondary_address_length']), data, pos)
	pos = pos + ((4 - ((pos - 1) % 4)) % 4); -- Alignment -- don't ask how I came up with this, it was a lot of drawing, and there's probably a far better way

	-- Read the number of results
	pos, result['num_results'] = bin.unpack("<C", data, pos)
	pos = pos + ((4 - ((pos - 1) % 4)) % 4); -- Alignment

	-- Verify we got back what we expected
	if(result['num_results'] ~= 1) then
		return false, "Bind() returned the incorrect number of result"
	end

	-- Read in the last bits
	pos, result['ack_result'], result['align'], result['transfer_syntax'], result['syntax_version'] = bin.unpack("<SSA16I", data, pos)

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
--        useful one being 'arguments', which are the values returned by the server. 
local function call_function(smbstate, opnum, arguments)
	local i
	local status, result
	local parameters, data
	local pos, align
	local result

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
	pos, result['version_major'], result['version_minor'], result['packet_type'], result['packet_flags'], result['data_representation'], result['frag_length'], result['auth_length'], result['call_id'] = bin.unpack("<CCCC>I<SSI", data)

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
	if(bit.band(result['packet_flags'], 0x03) ~= 0x03) then
		return false, "MSRPC call returned a fragmented packet, which we don't know how to handle"
	end
	if(result['packet_type'] ~= 0x02) then
		return false, "MSRPC call returned an unexpected packet type (not RESPONSE)"
	end
	if(result['call_id'] ~= 0x41414141) then
		return false, "MSRPC call returned an incorrect 'call_id' value"
	end

	-- Extract some more
	pos, result['alloc_hint'], result['context_id'], result['cancel_count'], align = bin.unpack("<ISCC", data, pos)

	-- Rest is the arguments
	result['arguments'] = string.sub(data, pos)
	stdnse.print_debug(3, "MSRPC: Function call successful, %d bytes of returned argumenst", string.len(result['arguments']))

	return true, result

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
	arguments = msrpctypes.marshall_unicode_ptr(server_unc, true)

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
--@return (status, result) If status is false, result is an error message. Otherwise, result is a table of values, the most
--        useful ones being 'names', a list of all the usernames, and 'details', a further list of tables with the elements
--        'name', 'fullname', and 'description' (note that any of them can be nil if the server didn't return a value). Finally,
--        'flags' is the numeric flags for the user, while 'flags_list' is an array of strings, representing the flags.
function samr_querydisplayinfo(smbstate, domain_handle, index)
	local i, j
	local status, result
	local arguments
	local pos, align

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
	arguments = arguments .. msrpctypes.marshall_int32(1)

--		[in]        uint32 buf_size,
	arguments = arguments .. msrpctypes.marshall_int32(0)

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
--@param result       [optional] A 'result' to add the entries to. This lets us call this function multiple times, 
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
	arguments = arguments .. msrpctypes.marshall_winreg_StringBuf({name=name}, 520)

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
	arguments = arguments .. msrpctypes.marshall_winreg_String("", 2048)

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
	arguments = arguments .. msrpctypes.marshall_int8_array_ptr("", 520)

--		[in,out] uint32 *size,
	arguments = arguments .. msrpctypes.marshall_int32_ptr(520)

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
	pos, 
	pos = pos + 4
	pos, result['type'] = msrpctypes.unmarshall_winreg_Type(arguments, pos)

--		[in,out,size_is(*size),length_is(*length)] uint8 *data,
	pos, result['data'] = msrpctypes.unmarshall_int8_array_ptr(arguments, pos)

	-- Format the type properly and put it in "value"
	if(result['data'] ~= nil) then
		if(result['type'] == "REG_DWORD") then
			_, result['value'] = bin.unpack("<I", result['data'])
		elseif(result['type'] == "REG_SZ" or result['type'] == "REG_MULTI_SZ" or result['type'] == "REG_EXPAND_SZ") then
			_, result['value'] = msrpctypes.unicode_to_string(result['data'], 1, #result['data'] / 2)
		else
			io.write(string.format("Unknown type: %s\n\n", result['type']))
			result['value'] = "FIX ME!"
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
 
