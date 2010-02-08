---
-- This module was written by Patrik Karlsson and facilitates communication
-- with the Apple AFP Service. It is not feature complete and is missing several 
-- functions and parameters.
--
-- The library currently has enough functionality to query share names and access controls.
-- More functionality will be added once more scripts that depend on it are developed.
--
--

-- Version 0.2
-- Created 01/03/2010 - v0.1 - created by Patrik Karlsson
-- Revised 01/20/2010 - v0.2 - updated all bitmaps to hex for better readability

module(... or "afp",package.seeall)

-- Table of valid REQUESTs
local REQUEST = {
	OpenSession = 0x04,
	Command = 0x02
}

-- Table of headers flags to be set accordingly in requests and responses
local FLAGS = {
	Request = 0,
	Response = 1
}

-- Table of possible AFP_COMMANDs
COMMAND = {
	FPCloseVol = 0x02,
	FPLogin = 0x12,
	FPGetUserInfo = 0x25,
	FPGetSrvParms = 0x10,
	FPOpenVol = 0x18,
	FPOpenFork = 0x1a,
	FPGetFileDirParams = 0x22,
	FPReadExt = 0x3c,
	FPEnumerateExt2 = 0x44
}

USER_BITMAP = {
	UserId = 0x01,
	PrimaryGroupId = 0x2,
	UUID = 0x4
}

VOL_BITMAP = {
	Attributes = 0x1,
	Signature = 0x2,
	CreationDate = 0x4,
	ModificationDate = 0x8,
	BackupDate = 0x10,
	ID = 0x20,
	BytesFree = 0x40,
	BytesTotal = 0x80,
	Name = 0x100,
	ExtendedBytesFree = 0x200,
	ExtendedBytesTotal = 0x400,
	BlockSize = 0x800
}

FILE_BITMAP = {
	Attributes = 0x1,
	DID = 0x2,
	CreationDate = 0x4,
	ModificationDate = 0x8,
	BackupDate = 0x10,
	FinderInfo = 0x20,
	LongName = 0x40,
	ShortName = 0x80,
	FileId = 0x100,
	DataForkSize = 0x200,
	ResourceForkSize = 0x400,
	ExtendedDataForkSize = 0x800,
	LaunchLimit = 0x1000,
	UTF8Name = 0x2000,
	ExtendedResourceForkSize = 0x4000,
	UnixPrivileges = 0x8000
}

DIR_BITMAP = {
	Attributes = 0x1,
	DID = 0x2,
	CreationDate = 0x4,
	ModificationDate = 0x8,
	BackupDate = 0x10,
	FinderInfo = 0x20,
	LongName = 0x40,
	ShortName = 0x80,
	FileId = 0x100,
	OffspringCount = 0x200,
	OwnerId = 0x400,
	GroupId = 0x800,
	AccessRights = 0x1000,
	UTF8Name = 0x2000,
	UnixPrivileges = 0x8000	
}

PATH_TYPE = {
	LongNames = 2,
	UnicodeNames = 3
}

ACCESS_MODE = {
	Read = 0x1,
	Write = 0x2,
	DenyRead = 0x10,
	DenyWrite = 0x20
}

ACLS = {
	OwnerSearch = 0x1,
	OwnerRead = 0x2,
	OwnerWrite = 0x4,
	
	GroupSearch = 0x100,
	GroupRead = 0x200,
	GroupWrite = 0x400,
	
	EveryoneSearch = 0x10000,
	EveryoneRead = 0x20000,
	EveryoneWrite = 0x40000,
	
	UserSearch = 0x100000,
	UserRead = 0x200000,
	UserWrite = 0x400000,
	
	BlankAccess = 0x10000000,
	UserIsOwner = 0x80000000
}

-- Each packet contains a sequential request id
-- this number is used within <code>create_fp_packet</code> and increased by one in each call
request_id = 1


--- Creates an AFP packet
--
-- @param command number should be one of the commands in the COMMAND table
-- @param data_offset number holding the offset to the data
-- @param data the actual data of the request
function create_fp_packet( command, data_offset, data )
	
	local reserved = 0
	local data = data or ""
	local data_len = data:len()
	local header = bin.pack("CC>SIII", FLAGS.Request, command, request_id, data_offset, data_len, reserved)
	local packet = header .. data

	request_id = request_id + 1
	return packet
end

--- Parses the FP header (first 16-bytes of packet)
--
-- @param packet string containing the raw packet
-- @return table with header data containing <code>flags</code>, <code>command</code>,
-- <code>request_id</code>, <code>error_code</code>, <code>length</code> and <code>reserved</code> fields
function parse_fp_header( packet )
	
	local header = {}
	local pos
	
	pos, header.flags, header.command, header.request_id = bin.unpack( "CC>S", packet )
	pos, header.error_code, header.length, header.reserved = bin.unpack( "I>II", packet:sub(5) )
	header.raw = packet:sub(1,16)
		
	return header
	
end

--- Sends an OpenSession AFP request to the server and handles the response
--
-- @param socket already connected to the server
-- @return status (true or false)
-- @return nil (if status is true) or error string (if status is false) 
function open_session( socket )

	local data_offset = 0
	local option = 0x01 -- Attention Quantum
	local option_len = 4
	local quantum = 1024
	
	local data = bin.pack( "CCI", option, option_len, quantum  )
	local packet = create_fp_packet( REQUEST.OpenSession, data_offset, data )
	
	send_fp_packet( socket, packet )
	packet = read_fp_packet( socket )

	if packet.header.error_code ~= 0 then
		return false, string.format("OpenSession error: %d", packet.header.error_code)
	end
		
	return true, nil
end



--- Sends an FPGetUserInfo AFP request to the server and handles the response
--
-- @param socket already connected to the server
-- @return status (true or false)
-- @return table with user information containing <code>user_bitmap</code> and 
-- <code>uid</code> fields (if status is true) or error string (if status is false) 
function fp_get_user_info( socket )

	local packet
	local data_offset = 0
	local flags = 1 -- Default User
	local uid = 0
	local bitmap = USER_BITMAP.UserId
	local response = {}
	local pos
		
	local data = bin.pack( "CCI>S", COMMAND.FPGetUserInfo, flags, uid, bitmap )
	packet = create_fp_packet( REQUEST.Command, data_offset, data )

	send_fp_packet( socket, packet )
	packet = read_fp_packet( socket )

	if packet.header.error_code ~= 0 then
		return false, string.format("OpenSession error: %d", packet.header.error_code)
	end

	pos, response.user_bitmap, response.uid = bin.unpack(">S>I", packet.data)

	return true, response
end

--- Sends an FPGetSrvrParms AFP request to the server and handles the response
--
-- @param socket already connected to the server
-- @return status (true or false)
-- @return table with server parameters containing <code>server_time</code>,
-- <code>vol_count</code>, <code>volumes</code> fields (if status is true) or error string (if status is false) 
--
function fp_get_srvr_parms(socket)

	local packet
	local data_offset = 0
	local response = {}
	local pos = 0

	local data = bin.pack("CC", COMMAND.FPGetSrvParms, 0)
	packet = create_fp_packet( REQUEST.Command, data_offset, data )
	send_fp_packet( socket, packet )
	packet = read_fp_packet( socket )

	if packet.header.error_code ~= 0 then
		return false, string.format("FPGetSrvrParms error: %d", packet.header.error_code)
	end

	data = packet.data
	pos, response.server_time, response.vol_count = bin.unpack("IC", data)
		
	-- we should now be at the leading zero preceeding the first volume name
	-- next is the length of the volume name, move pos there
	pos = pos + 1

	stdnse.print_debug("Volumes: %d", response.vol_count )
	response.volumes = {}
	
	for i=1, response.vol_count do
		local _, vol_len = bin.unpack("C", data:sub(pos))
		local volume_name = data:sub(pos + 1, pos + 1 + vol_len)
		pos = pos + vol_len + 2
		table.insert(response.volumes, string.format("%s", volume_name) )
		stdnse.print_debug("Volume name: %s", volume_name)
	end

	return true, response
end


--- Sends an FPLogin request to the server and handles the response
--
-- This function currently only supports the 3.1 through 3.3 protocol versions
-- It does not support authentication so the uam parameter is currently ignored
--
-- @param socket already connected to the server--
-- @param afp_version string (AFP3.3|AFP3.2|AFP3.1)
-- @param uam string containing authentication information (currently ignored)
-- @return status (true or false)
-- @return nil (if status is true) or error string (if status is false) 
function fp_login( socket, afp_version, uam )

	local packet
	local data_offset = 0

	-- currently we only support AFP3.3
	if afp_version == nil or ( afp_version ~= "AFP3.3" and afp_version ~= "AFP3.2" and afp_version ~= "AFP3.1" ) then
		return
	end
	
	uam = "No User Authent"
	
	local data = bin.pack( "CCACA", COMMAND.FPLogin, afp_version:len(), afp_version, uam:len(), uam )
	packet = create_fp_packet( REQUEST.Command, data_offset, data )
	send_fp_packet( socket, packet )
	packet = read_fp_packet( socket )

	if packet.header.error_code ~= 0 then
		return false, string.format("FPLogin error: %d", packet.header.error_code)
	end
	
	return true, nil
end

--- Reads a AFP packet of the socket
--
-- @param socket socket connected to the server
-- @return table containing <code>data</code> and <code>header</code> fields
function read_fp_packet( socket )

	local packet = {}
	local buf = ""
	
	local catch = function()
		socket:close()
	end
	
	local try = nmap.new_try(catch)

	repeat
		buf = buf .. try( socket:receive(16) )
	until buf:len() >= 16 -- make sure we have got atleast the header
		
	packet.header = parse_fp_header( buf )
	
	-- if we didn't get the whole packet when reading the header, try to read the rest
	while buf:len() < packet.header.length + packet.header.raw:len() do
		buf = buf .. try( socket:receive(packet.header.length) )
	end

	packet.data = buf:len() > 16 and buf:sub( 17 ) or ""
	
	return packet
	
end

--- Sends an FPOpenVol request to the server and handles the response
--
-- @param socket already connected to the server
-- @param bitmap number bitmask of volume information to request
-- @param volume_name string containing the volume name to query
-- @return status (true or false)
-- @return table containing <code>bitmap</code> and <code>volume_id</code> fields
-- (if status is true) or error string (if status is false)
function fp_open_vol( socket, bitmap, volume_name )

	local packet
	local data_offset = 0
	local pad = 0
	local response = {}
	local pos
	
	local data = bin.pack("CC>SCA", COMMAND.FPOpenVol, pad, bitmap, volume_name:len(), volume_name )
	packet = create_fp_packet( REQUEST.Command, data_offset, data )
	send_fp_packet( socket, packet )
	packet = read_fp_packet( socket )

	if packet.header.error_code ~= 0 then
		return false, string.format("FPOpenVol error: %d", packet.header.error_code )
	end

	pos, response.bitmap, response.volume_id = bin.unpack(">S>S", packet.data)

	return true, response
		
end

--- Sends an FPGetFileDirParms request to the server and handles the response
--
-- Currently only handles a request for the Access rights (file_bitmap must be 0 and dir_bitmap must be 0x1000)
--
-- @param socket already connected to the server
-- @param volume_id number containing the id of the volume to query
-- @param did number containing the id of the directory to query
-- @param file_bitmap number bitmask of file information to query
-- @param dir_bitmap number bitmask of directory information to query
-- @param path string containing the name of the directory to query
-- @return status (true or false)
-- @return table containing <code>file_bitmap</code>, <code>dir_bitmap</code>,
-- <code>file_type</code> and <code>acls</code> fields
-- (if status is true) or error string (if status is false)
function fp_get_file_dir_parms( socket, volume_id, did, file_bitmap, dir_bitmap, path )

	local packet
	local data_offset = 0
	local pad = 0
	local response = {}
	local pos
	
	if file_bitmap ~= 0 or dir_bitmap ~= DIR_BITMAP.AccessRights then
		return false, "Only AccessRights querys are supported (file_bitmap=0, dir_bitmap=DIR_BITMAP.AccessRights)"
	end
	
	local data = bin.pack("CC>S>I>S>SCCAC", COMMAND.FPGetFileDirParams, pad, volume_id, did, file_bitmap, dir_bitmap, path.type, path.len, path.name, 0)
	packet = create_fp_packet( REQUEST.Command, data_offset, data )
	send_fp_packet( socket, packet )
	packet = read_fp_packet( socket )

	if packet.header.error_code ~= 0 then
		return false, string.format("FPGetFileDirParms error: %d", packet.header.error_code )
	end

	pos, response.file_bitmap, response.dir_bitmap, response.file_type, pad, response.acls = bin.unpack( ">S>SCC>I", packet.data )

	return true, response
end

--- Sends an FPEnumerateExt2 request to the server and handles the response
--
-- @param socket already connected to the server
-- @param volume_id number containing the id of the volume to query
-- @param did number containing the id of the directory to query
-- @param file_bitmap number bitmask of file information to query
-- @param dir_bitmap number bitmask of directory information to query
-- @param req_count number
-- @param start_index number
-- @param reply_size number
-- @param path string containing the name of the directory to query
-- @return status (true or false)
-- @return table containing <code>file_bitmap</code>, <code>dir_bitmap</code>,
-- <code>req_count</code> fields
-- (if status is true) or error string (if status is false)
function fp_enumerate_ext2( socket, volume_id, did, file_bitmap, dir_bitmap, req_count, start_index, reply_size, path )
	
	local _
	local packet
	local data_offset = 0
	local pad = 0
	local response = {}
	
	local data = bin.pack( "CC>S>I>S>S", COMMAND.FPEnumerateExt2, pad, volume_id, did, file_bitmap, dir_bitmap )
	data = data .. bin.pack( ">S>I>IC>SA", req_count, start_index, reply_size, path.type, path.len, path.name )
	packet = create_fp_packet( REQUEST.Command, data_offset, data )

	send_fp_packet( socket, packet )
	packet = read_fp_packet( socket )

	if packet.header.error_code ~= 0 then
		return false, string.format("FPEnumerateExt2 error: %d", packet.header.error_code )
	end
	
	_, response.file_bitmap, response.dir_bitmap, response.req_count = bin.unpack(">S>S>S", packet.data)

	return true, response

end

--- Sends an FPOpenFork request to the server and handles the response
--
-- @param socket already connected to the server
-- @param fork number
-- @param volume_id number containing the id of the volume to query
-- @param did number containing the id of the directory to query
-- @param file_bitmap number bitmask of file information to query
-- @param access_mode number containing bitmask of options from <code>ACCESS_MODE</code>
-- @param path string containing the name of the directory to query
-- @return status (true or false)
-- @return table containing <code>file_bitmap</code> and <code>fork</code> fields (if status is true) or 
-- error string (if status is false)
function fp_open_fork( socket, fork, volume_id, did, file_bitmap, access_mode, path )

	local _
	local packet
	local data_offset = 0
	local pad = 0
	local response = {}
	
	local data = bin.pack( "CC>S>I>S>S", COMMAND.FPOpenFork, fork, volume_id, did, file_bitmap, access_mode )
	
	if path.type == PATH_TYPE.LongNames then
		data = data .. bin.pack( "C>SA", path.type, path.len, path.name )
	end
	
	if path.type == PATH_TYPE.UnicodeNames then
		local unicode_hint = 0x08000103
		data = data .. bin.pack( "C>I>SA", path.type, unicode_hint, path.len, path.name )		
	end
	
	packet = create_fp_packet( REQUEST.Command, data_offset, data )
	send_fp_packet( socket, packet )
	packet = read_fp_packet( socket )
	
	if packet.header.error_code ~= 0 then
		return false, string.format("FPOpenFork error: %d", packet.header.error_code )
	end
	
	_, response.file_bitmap, response.fork = bin.unpack(">S>S", packet.data)

	return true, response
	
end

--- Sends an FPCloseVol request to the server and handles the response
--
-- @param socket already connected to the server
-- @param volume_id number containing the id of the volume to close
-- @return status (true or false)
-- @return nil (if status is true) or error string (if status is false) 
function fp_close_vol( socket, volume_id )

	local packet
	local data_offset = 0
	local pad = 0
	local response = {}
	
	local data = bin.pack( "CC>S>", COMMAND.FPCloseVol, pad, volume_id )

	packet = create_fp_packet( REQUEST.Command, data_offset, data )
	send_fp_packet( socket, packet )
	packet = read_fp_packet( socket )
	
	if packet.header.error_code ~= 0 then
		return false, string.format("FPCloseVol error: %d", packet.header.error_code )
	end
	
	return true, nil

end

--- Sends the raw packet over the socket
--
-- @param socket already connected to the server
-- @param packet containing the raw data
function send_fp_packet( socket, packet )

	local catch = function()
		socket:close()
	end

	local try = nmap.new_try(catch)
	try( socket:send(packet) )

end


function fp_read_ext( fork, offset, count )

	local packet
	local data_offset = 0
	local pad = 0
	
	local data = bin.pack( "CC>S>L>L", COMMAND.FPReadExt, pad, fork, offset, count  )
	packet = create_fp_packet( REQUEST.Command, data_offset, data )

	return packet
	
end
