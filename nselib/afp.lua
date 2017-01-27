---
-- This library was written by Patrik Karlsson <patrik@cqure.net> to facilitate
-- communication with the Apple AFP Service. It is not feature complete and
-- still missing several functions.
--
-- The library currently supports
-- * Authentication using the DHX UAM (CAST128)
-- * File reading and writing
-- * Listing sharepoints
-- * Listing directory contents
-- * Querying ACLs and mapping user identities (UIDs)
--
-- The library was built based on the following reference:
-- http://developer.apple.com/mac/library/documentation/Networking/Reference/AFP_Reference/Reference/reference.html
-- http://developer.apple.com/mac/library/documentation/Networking/Conceptual/AFP/AFPSecurity/AFPSecurity.html#//apple_ref/doc/uid/TP40000854-CH232-CHBBAGCB
--
-- Most functions have been tested against both Mac OS X 10.6.2 and Netatalk 2.0.3
--
-- The library contains the following four classes
-- * <code>Response</code>
-- ** A class used as return value by functions in the <code>Proto</code> class.
-- ** The response class acts as a wrapper and holds the response data and any error information.
-- * <code>Proto</code>
-- ** This class contains all the AFP specific functions and calls.
-- ** The functions can be accessed directly but the preferred method is through the <code>Helper</code> class.
-- ** The function names closely resemble those described in the Apple documentation.
-- ** Some functions may lack some of the options outlined in Apple's documentation.
-- * <code>Helper</code>
-- ** The helper class wraps the <code>Proto</code> class using functions with a more descriptive name.
-- ** Functions are task-oriented. For example, <code>ReadFile</code> and usually call several functions in the <code>Proto</code> class.
-- ** The purpose of this class is to give developers easy access to some of the common AFP tasks.
-- * <code>Util</code>
-- ** The <code>Util</code> class contains a number of static functions mainly used to convert data.
--
-- The following information will describe how to use the AFP Helper class to communicate with an AFP server.
--
-- The short version:
-- <code>
-- helper = afp.Helper:new()
-- status, response = helper:OpenSession( host, port )
-- status, response = helper:Login()
-- .. do some fancy AFP stuff ..
-- status, response = helper:Logout()
-- status, response = helper:CloseSession()
-- </code>
--
-- Here's the longer version, with some explanatory text. To start using the Helper class,
-- the script has to create its own instance. We do this by issuing the following:
-- <code>
-- helper = afp.Helper:new()
-- </code>
--
-- Next a session to the AFP server must be established, this is done using the OpenSession method of the
-- Helper class, like this:
-- <code>
-- status, response = helper:OpenSession( host, port )
-- </code>
--
-- The next step needed to be performed is to authenticate to the server. We need to do this even for
-- functions that are available publicly. In order to authenticate as the public user simply
-- authenticate using nil for both username and password. This can be achieved by calling the Login method
-- without any parameters, like this:
-- <code>
-- status, response = helper:Login()
-- </code>
--
-- To authenticate to the server using the username 'admin' and password 'nimda' we do this instead:
-- <code>
-- status, response = helper:Login('admin', 'nimda')
-- </code>
--
-- At this stage we're authenticated and can call any of the AFP functions we're authorized to.
-- For the purpose of this documentation, we will attempt to list the servers share points.
-- We do this by issuing the following:
-- <code>
-- status, shares = helper:ListShares()
-- </code>
--
-- Once we're finished, we need to logout and close the AFP session this is done by calling the
-- following two methods of the Helper class:
-- <code>
-- status, response = helper:Logout()
-- status, response = helper:CloseSession()
-- </code>
--
-- Consult the documentation of each function to learn more about their respective return values.
--
--@author Patrik Karlsson <patrik@cqure.net>
--@copyright Same as Nmap--See https://nmap.org/book/man-legal.html
--
-- @args afp.username The username to use for authentication.
-- @args afp.password The password to use for authentication.

--
-- Version 0.5
--
-- Created 01/03/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/20/2010 - v0.2 - updated all bitmaps to hex for better readability
-- Revised 02/15/2010 - v0.3 - added a bunch of new functions and re-designed the code to be OO
--
--   New functionality added as of v0.3
--    o File reading, writing
--    o Authentication
--    o Helper functions for most AFP functions
--    o More robust error handling
--
-- Revised 03/05/2010 - v0.4 - changed output table of Helper:Dir to include type and ID
--                           - added support for --without-openssl
--
-- Revised 03/09/2010 - v0.5 - documentation, documentation and more documentation
-- Revised 04/03/2011 - v0.6 - add support for getting file- sizes, dates and Unix ACLs
--                           - moved afp.username & afp.password arguments to library

local bin = require "bin"
local bit = require "bit"
local nmap = require "nmap"
local os = require "os"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("afp", stdnse.seeall);

local HAVE_SSL, openssl = pcall(require,'openssl')

-- Table of valid REQUESTs
local REQUEST = {
  CloseSession = 0x01,
  OpenSession = 0x04,
  Command = 0x02,
  GetStatus = 0x03,
  Write = 0x06,
}

-- Table of headers flags to be set accordingly in requests and responses
local FLAGS = {
  Request = 0,
  Response = 1
}

-- Table of possible AFP_COMMANDs
COMMAND = {
  FPCloseVol = 0x02,
  FPCloseFork = 0x04,
  FPCopyFile = 0x05,
  FPCreateDir = 0x06,
  FPCreateFile = 0x07,
  FPGetSrvrInfo = 0x0f,
  FPGetSrvParms = 0x10,
  FPLogin = 0x12,
  FPLoginCont = 0x13,
  FPLogout = 0x14,
  FPMapId = 0x15,
  FPMapName = 0x16,
  FPGetUserInfo = 0x25,
  FPOpenVol = 0x18,
  FPOpenFork = 0x1a,
  FPGetFileDirParams = 0x22,
  FPChangePassword = 0x24,
  FPReadExt = 0x3c,
  FPWriteExt = 0x3d,
  FPGetAuthMethods = 0x3e,
  FPLoginExt = 0x3f,
  FPEnumerateExt2 = 0x44,
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
  ParentDirId = 0x2,
  CreationDate = 0x4,
  ModificationDate = 0x8,
  BackupDate = 0x10,
  FinderInfo = 0x20,
  LongName = 0x40,
  ShortName = 0x80,
  NodeId = 0x100,
  DataForkSize = 0x200,
  ResourceForkSize = 0x400,
  ExtendedDataForkSize = 0x800,
  LaunchLimit = 0x1000,
  UTF8Name = 0x2000,
  ExtendedResourceForkSize = 0x4000,
  UnixPrivileges = 0x8000,
  ALL = 0xFFFF
}

DIR_BITMAP = {
  Attributes = 0x1,
  ParentDirId = 0x2,
  CreationDate = 0x4,
  ModificationDate = 0x8,
  BackupDate = 0x10,
  FinderInfo = 0x20,
  LongName = 0x40,
  ShortName = 0x80,
  NodeId = 0x100,
  OffspringCount = 0x200,
  OwnerId = 0x400,
  GroupId = 0x800,
  AccessRights = 0x1000,
  UTF8Name = 0x2000,
  UnixPrivileges = 0x8000,
  ALL = 0xBFFF,
}

PATH_TYPE = {
  ShortName = 1,
  LongName = 2,
  UTF8Name = 3,
}

ACCESS_MODE = {
  Read = 0x1,
  Write = 0x2,
  DenyRead = 0x10,
  DenyWrite = 0x20
}

-- Access controls
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

-- User authentication modules
UAM =
{
  NoUserAuth = "No User Authent",
  ClearText = "Cleartxt Passwrd",
  RandNum = "Randnum Exchange",
  TwoWayRandNum = "2-Way Randnum",
  DHCAST128 = "DHCAST128",
  DHX2 = "DHX2",
  Kerberos = "Client Krb v2",
  Reconnect = "Recon1",
}

ERROR =
{
  SocketError = 1000,
  CustomError = 0xdeadbeef,

  FPNoErr = 0,
  FPAccessDenied = -5000,
  FPAuthContinue = -5001,
  FPBadUAM = -5002,
  FPBadVersNum = -5003,
  FPBitmapErr = - 5004,
  FPCantMove = - 5005,
  FPEOFErr = -5009,
  FPItemNotFound = -5012,
  FPLockErr = -5013,
  FPMiscErr = -5014,
  FPObjectExists = -5017,
  FPObjectNotFound = -5018,
  FPParamErr = -5019,
  FPUserNotAuth = -5023,
  FPCallNotSupported = -5024,
}

MAP_ID =
{
  UserIDToName = 1,
  GroupIDToName = 2,
  UserIDToUTF8Name = 3,
  GroupIDToUTF8Name = 4,
  UserUUIDToUTF8Name = 5,
  GroupUUIDToUTF8Name = 6
}

MAP_NAME =
{
  NameToUserID = 1,
  NameToGroupID = 2,
  UTF8NameToUserID = 3,
  UTF8NameToGroupID = 4,
  UTF8NameToUserUUID = 5,
  UTF8NameToGroupUUID = 6
}


SERVERFLAGS =
{
  CopyFile = 0x01,
  ChangeablePasswords = 0x02,
  NoPasswordSaving = 0x04,
  ServerMessages = 0x08,
  ServerSignature = 0x10,
  TCPoverIP = 0x20,
  ServerNotifications = 0x40,
  Reconnect = 0x80,
  OpenDirectory = 0x100,
  UTF8ServerName = 0x200,
  UUIDs = 0x400,
  SuperClient = 0x8000
}

local ERROR_MSG = {
  [ERROR.FPAccessDenied]="Access Denied",
  [ERROR.FPAuthContinue]="Authentication is not yet complete",
  [ERROR.FPBadUAM]="Specified UAM is unknown",
  [ERROR.FPBadVersNum]="Server does not support the specified AFP version",
  [ERROR.FPBitmapErr]="Attempt was made to get or set a parameter that cannot be obtained or set with this command, or a required bitmap is null",
  [ERROR.FPCantMove]="Attempt was made to move a directory into one of its descendant directories.",
  [ERROR.FPEOFErr]="No more matches or end of fork reached.",
  [ERROR.FPLockErr]="Some or all of the requested range is locked by another user; a lock range conflict exists.",
  [ERROR.FPMiscErr]="Non-AFP error occurred.",
  [ERROR.FPObjectNotFound]="Input parameters do not point to an existing directory, file, or volume.",
  [ERROR.FPParamErr]="Parameter error.",
  [ERROR.FPObjectExists] = "File or directory already exists.",
  [ERROR.FPUserNotAuth] = "UAM failed (the specified old password doesn't match); no user is logged in yet for the specified session; authentication failed; password is incorrect.",
  [ERROR.FPItemNotFound] = "Specified APPL mapping, comment, or icon was not found in the Desktop database; specified ID is unknown.",
  [ERROR.FPCallNotSupported] = "Server does not support this command.",
}

-- Check if all the bits in flag are set in bitmap.
local function flag_is_set(bitmap, flag)
  return bit.band(bitmap, flag) == flag
end

-- Response class returned by all functions in Proto
Response = {

  new = function(self,o)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Sets the error code
  --
  -- @param code number containing the error code
  setErrorCode = function( self, code )
    self.error_code = code
  end,

  --- Gets the error code
  --
  -- @return code number containing the error code
  getErrorCode = function( self )
    return self.error_code
  end,

  --- Gets the error message
  --
  -- @return msg string containing the error
  getErrorMessage = function(self)
    if self.error_msg then
      return self.error_msg
    else
      return ERROR_MSG[self.error_code] or ("Unknown error (%d) occurred"):format(self.error_code)
    end
  end,

  --- Sets the error message
  --
  -- @param msg string containing the error message
  setErrorMessage = function(self, msg)
    self.error_code = ERROR.CustomError
    self.error_msg = msg
  end,

  --- Sets the result
  --
  -- @param result result to set
  setResult = function(self, result)
    self.result = result
  end,

  --- Get the result
  --
  -- @return result
  getResult = function(self)
    return self.result
  end,

  --- Sets the packet
  setPacket = function( self, packet )
    self.packet = packet
  end,

  getPacket = function( self )
    return self.packet
  end,

  --- Gets the packet data
  getPacketData = function(self)
    return self.packet.data
  end,

  --- Gets the packet header
  getPacketHeader = function(self)
    return self.packet.header
  end,
}

--- Proto class containing all AFP specific code
--
-- For more details consult:
-- http://developer.apple.com/mac/library/documentation/Networking/Reference/AFP_Reference/Reference/reference.html
Proto = {

  RequestId = 1,

  new = function(self,o)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  setSocket = function(self, socket)
    self.socket = socket
  end,

  --- Creates an AFP packet
  --
  -- @param command number should be one of the commands in the COMMAND table
  -- @param data_offset number holding the offset to the data
  -- @param data the actual data of the request
  create_fp_packet = function( self, command, data_offset, data )
    local reserved = 0
    local data = data or ""
    local data_len = data:len()
    local header = bin.pack("CC>SIII", FLAGS.Request, command, self.RequestId, data_offset, data_len, reserved)

    self.RequestId = self.RequestId + 1
    return header .. data
  end,

  --- Parses the FP header (first 16-bytes of packet)
  --
  -- @param packet string containing the raw packet
  -- @return table with header data containing <code>flags</code>, <code>command</code>,
  -- <code>request_id</code>, <code>error_code</code>, <code>length</code> and <code>reserved</code> fields
  parse_fp_header = function( self, packet )
    local header = {}
    local pos

    pos, header.flags, header.command, header.request_id = bin.unpack( "CC>S", packet )
    pos, header.error_code, header.length, header.reserved = bin.unpack( ">i>II", packet:sub(5) )

    if header.error_code ~= 0 then
      header.error_msg = ERROR_MSG[header.error_code] or ("Unknown error: %d"):format(header.error_code)
      header.error_msg = "ERROR: " .. header.error_msg
    end
    header.raw = packet:sub(1,16)
    return header
  end,

  --- Reads a AFP packet of the socket
  --
  -- @return Response object
  read_fp_packet = function( self )

    local packet = {}
    local buf = ""
    local status, response

    status, buf = self.socket:receive_bytes(16)
    if ( not status ) then
      response = Response:new()
      response:setErrorCode(ERROR.SocketError)
      response:setErrorMessage(buf)
      return response
    end

    packet.header = self:parse_fp_header( buf )
    while buf:len() < packet.header.length + packet.header.raw:len() do
      local tmp
      status, tmp = self.socket:receive_bytes( packet.header.length + 16 - buf:len() )
      if not status then
        response = Response:new()
        response:setErrorCode(ERROR.SocketError)
        response:setErrorMessage(buf)
        return response
      end
      buf = buf .. tmp
    end

    packet.data = buf:len() > 16 and buf:sub( 17 ) or ""
    response = Response:new()
    response:setErrorCode(packet.header.error_code)
    response:setPacket(packet)

    return response
  end,

  --- Sends the raw packet over the socket
  --
  -- @param packet containing the raw data
  -- @return Response object
  send_fp_packet = function( self, packet )
    return self.socket:send(packet)
  end,

  --- Sends an DSIOpenSession request to the server and handles the response
  --
  -- @return Response object
  dsi_open_session = function( self, host, port )
    local data_offset = 0
    local option = 0x01 -- Attention Quantum
    local option_len = 4
    local quantum = 1024
    local data, packet, status

    data = bin.pack( "CCI", option, option_len, quantum  )
    packet = self:create_fp_packet( REQUEST.OpenSession, data_offset, data )

    self:send_fp_packet( packet )
    return self:read_fp_packet()
  end,

  --- Sends an DSICloseSession request to the server and handles the response
  dsi_close_session = function( self )
    local data_offset = 0
    local option = 0x01 -- Attention Quantum
    local option_len = 4
    local quantum = 1024
    local data, packet, status

    data = ""
    packet = self:create_fp_packet( REQUEST.CloseSession, data_offset, data )

    self:send_fp_packet( packet )
  end,

  -- Sends an FPCopyFile request to the server
  --
  -- @param src_vol number containing the ID of the src file volume
  -- @param srd_did number containing the directory id of the src file
  -- @param src_path string containing the file path/name of the src file
  -- @param dst_vol number containing the ID of the dst file volume
  -- @param dst_did number containing the id of the dest. directory
  -- @param dst_path string containing the dest path (can be nil or "")
  -- @param new_name string containing the new name of the destination
  -- @return Response object
  fp_copy_file = function(self, src_vol, src_did, src_path, dst_vol, dst_did, dst_path, new_name )
    local pad, data_offset = 0, 0
    local unicode_names, unicode_hint = 0x03, 0x08000103
    local data, packet, response

    -- make sure we have empty names rather than nil values
    local dst_path = dst_path or ""
    local src_path = src_path or ""
    local new_name = new_name or ""

    data = bin.pack(">CCSISI", COMMAND.FPCopyFile, pad, src_vol, src_did, dst_vol, dst_did )
    .. bin.pack(">CIP", unicode_names, unicode_hint, src_path )
    .. bin.pack(">CIP", unicode_names, unicode_hint, dst_path )
    .. bin.pack(">CIP", unicode_names, unicode_hint, new_name )

    packet = self:create_fp_packet( REQUEST.Command, data_offset, data )
    self:send_fp_packet( packet )
    return self:read_fp_packet()
  end,

  --- Sends an GetStatus DSI request (which is basically a FPGetSrvrInfo
  -- AFP request) to the server and handles the response
  --
  -- @return status (true or false)
  -- @return table with server information (if status is true) or error string
  -- (if status is false)
  fp_get_server_info = function(self)
    local packet
    local data_offset = 0
    local pad = 0
    local response, result = {}, {}
    local offsets = {}
    local pos
    local _
    local status

    local data = bin.pack("CC", COMMAND.FPGetSrvrInfo, 0)
    packet = self:create_fp_packet(REQUEST.GetStatus, data_offset, data)
    self:send_fp_packet(packet)
    response = self:read_fp_packet()

    if response:getErrorCode() ~= ERROR.FPNoErr then
      return response
    end

    packet = response.packet

    -- parse and store the offsets in the 'header'
    pos, offsets.machine_type, offsets.afp_version_count,
      offsets.uam_count, offsets.volume_icon_and_mask
      = bin.unpack(">SSSS", packet.data, pos)

    -- the flags are directly in the 'header'
    result.flags = {}
    pos, result.flags.raw = bin.unpack(">S", packet.data, pos)

    -- the short server name is stored directly in the 'header' as
    -- well
    pos, result.server_name = bin.unpack("p", packet.data, pos)

    -- Server offset should begin at an even boundary see link below
    -- http://developer.apple.com/mac/library/documentation/Networking/Reference/AFP_Reference/Reference/reference.html#//apple_ref/doc/uid/TP40003548-CH3-CHDIEGED
    if (pos + 1) % 2 ~= 0 then
      pos = pos + 1
    end

    -- and some more offsets
    pos, offsets.server_signature, offsets.network_addresses_count,
    offsets.directory_names_count, offsets.utf8_server_name
      = bin.unpack(">SSSS", packet.data, pos)

    -- this sets up all the server flags in the response table as booleans
    result.flags.SuperClient = flag_is_set(result.flags.raw, SERVERFLAGS.SuperClient)
    result.flags.UUIDs = flag_is_set(result.flags.raw, SERVERFLAGS.UUIDs)
    result.flags.UTF8ServerName = flag_is_set(result.flags.raw, SERVERFLAGS.UTF8ServerName)
    result.flags.OpenDirectory = flag_is_set(result.flags.raw, SERVERFLAGS.OpenDirectory)
    result.flags.Reconnect = flag_is_set(result.flags.raw, SERVERFLAGS.Reconnect)
    result.flags.ServerNotifications = flag_is_set(result.flags.raw, SERVERFLAGS.ServerNotifications)
    result.flags.TCPoverIP = flag_is_set(result.flags.raw, SERVERFLAGS.TCPoverIP)
    result.flags.ServerSignature = flag_is_set(result.flags.raw, SERVERFLAGS.ServerSignature)
    result.flags.ServerMessages = flag_is_set(result.flags.raw, SERVERFLAGS.ServerMessages)
    result.flags.NoPasswordSaving = flag_is_set(result.flags.raw, SERVERFLAGS.NoPasswordSaving)
    result.flags.ChangeablePasswords = flag_is_set(result.flags.raw, SERVERFLAGS.ChangeablePasswords)
    result.flags.CopyFile = flag_is_set(result.flags.raw, SERVERFLAGS.CopyFile)

    -- store the machine type
    _, result.machine_type = bin.unpack("p", packet.data, offsets.machine_type + 1)

    -- this tells us the number of afp versions supported
    pos, result.afp_version_count = bin.unpack("C", packet.data, offsets.afp_version_count + 1)

    -- now we loop through them all, storing for the response
    result.afp_versions = {}
    for i = 1,result.afp_version_count do
      pos, _ = bin.unpack("p", packet.data, pos)
      table.insert(result.afp_versions, _)
    end

    -- same idea as the afp versions here
    pos, result.uam_count = bin.unpack("C", packet.data, offsets.uam_count + 1)

    result.uams = {}
    for i = 1,result.uam_count do
      pos, _ = bin.unpack("p", packet.data, pos)
      table.insert(result.uams, _)
    end

    -- volume_icon_and_mask would normally be parsed out here,
    -- however the apple docs say it is deprecated in Mac OS X, so
    -- we don't bother with it

    -- server signature is 16 bytes
    result.server_signature = string.sub(packet.data, offsets.server_signature + 1, offsets.server_signature + 16)

    -- this is the same idea as afp_version and uam above
    pos, result.network_addresses_count = bin.unpack("C", packet.data, offsets.network_addresses_count + 1)

    result.network_addresses = {}

    -- gets a little complicated in here, basically each entry has
    -- a length byte, a tag byte, and then the data. We parse
    -- differently based on the tag
    for i = 1, result.network_addresses_count do
      local length
      local tag

      pos, length = bin.unpack("C", packet.data, pos)
      pos, tag = bin.unpack("C", packet.data, pos)

      if tag == 0x00 then
        -- reserved, shouldn't ever come up, maybe this should
        -- return an error? maybe not, lets just ignore this
      elseif tag == 0x01 then
        -- four byte ip
        local octet = {}
        pos, octet[1], octet[2], octet[3], octet[4] = bin.unpack("CCCC", packet.data, pos)
        table.insert(result.network_addresses, string.format("%d.%d.%d.%d", octet[1], octet[2], octet[3], octet[4]))
      elseif tag == 0x02 then
        -- four byte ip and two byte port
        local octet = {}
        local port
        pos, octet[1], octet[2], octet[3], octet[4], port = bin.unpack(">CCCCS", packet.data, pos)
        table.insert(result.network_addresses, string.format("%d.%d.%d.%d:%d", octet[1], octet[2], octet[3], octet[4], port))
      elseif tag == 0x03 then
        -- ddp address (two byte network, one byte
        -- node, one byte socket) not tested, anyone
        -- use ddp anymore?
        local network
        local node
        local socket
        pos, network = bin.unpack(">S", packet.data, pos)
        pos, node = bin.unpack("C", packet.data, pos)
        pos, socket = bin.unpack("C", packet.data, pos)
        table.insert(result.network_addresses, string.format("ddp %d.%d:%d", network, node, socket))
      elseif tag == 0x04 then
        -- dns name (string)
        local temp
        pos, temp = bin.unpack("z", packet.data:sub(1,pos+length-3), pos)
        table.insert(result.network_addresses, temp)
      elseif tag == 0x05 then
        -- four byte ip and two byte port, client
        -- should use ssh. not tested, should work as it
        -- is the same as tag 0x02
        local octet = {}
        local port
        pos, octet[1], octet[2], octet[3], octet[4], port = bin.unpack(">CCCCS", packet.data, pos)
        table.insert(result.network_addresses, string.format("ssh://%d.%d.%d.%d:%d", octet[1], octet[2], octet[3], octet[4], port))
      elseif tag == 0x06 then
        -- 16 byte ipv6
        -- not tested, but should work (next tag is
        -- tested)
        local octet = {}

        for j = 1, 8 do
          local o
          pos, o = bin.unpack(">S", packet.data, pos)
          octet[j] = string.format("%04x", o)
        end

        table.insert(result.network_addresses, table.concat(octet, ':'))
      elseif tag == 0x07 then
        -- 16 byte ipv6 and two byte port
        local octet = {}
        local port

        for j = 1, 8 do
          local o
          pos, o = bin.unpack(">S", packet.data, pos)
          octet[j] = string.format("%04x", o)
        end
        pos, port = bin.unpack(">S", packet.data, pos)

        table.insert(result.network_addresses,
          string.format("[%s]:%d", table.concat(octet, ':'), port))
      end
    end

    -- same idea as the others here
    pos, result.directory_names_count = bin.unpack("C", packet.data, offsets.directory_names_count + 1)

    result.directory_names = {}
    for i = 1, result.directory_names_count do
      local dirname
      pos, dirname = bin.unpack("p", packet.data, pos)
      table.insert(result.directory_names, dirname)
    end

    -- only one utf8 server name. note this string has a two-byte length.
    _, result.utf8_server_name = bin.unpack(">P", packet.data, offsets.utf8_server_name + 1)
    response.result = result

    return response
  end,


  --- Sends an FPGetUserInfo AFP request to the server and handles the response
  --
  -- @return response object with the following result <code>user_bitmap</code> and
  --     <code>uid</code> fields
  fp_get_user_info = function( self )

    local packet, pos, status, response
    local data_offset = 0
    local flags = 1 -- Default User
    local uid = 0
    local bitmap = USER_BITMAP.UserId
    local result = {}

    local data = bin.pack( "CCI>S", COMMAND.FPGetUserInfo, flags, uid, bitmap )
    packet = self:create_fp_packet( REQUEST.Command, data_offset, data )

    self:send_fp_packet( packet )
    response = self:read_fp_packet()
    if response:getErrorCode() ~= ERROR.FPNoErr then
      return response
    end

    pos, response.result.user_bitmap, response.result.uid = bin.unpack(">S>I", packet.data)

    return response
  end,

  --- Sends an FPGetSrvrParms AFP request to the server and handles the response
  --
  -- @return response object with the following result <code>server_time</code>,
  -- <code>vol_count</code>, <code>volumes</code> fields
  fp_get_srvr_parms = function(self)
    local packet, status, data
    local data_offset = 0
    local response = {}
    local pos = 0
    local parms = {}

    data = bin.pack("CC", COMMAND.FPGetSrvParms, 0)
    packet = self:create_fp_packet( REQUEST.Command, data_offset, data )
    self:send_fp_packet( packet )
    response = self:read_fp_packet()

    if response:getErrorCode() ~= ERROR.FPNoErr then
      return response
    end

    data = response:getPacketData()
    pos, parms.server_time, parms.vol_count = bin.unpack("IC", data)

    -- we should now be at the leading zero preceding the first volume name
    -- next is the length of the volume name, move pos there
    pos = pos + 1

    parms.volumes = {}

    for i=1, parms.vol_count do
      local _, vol_len = bin.unpack("C", data:sub(pos))
      local volume_name = data:sub(pos + 1, pos + 1 + vol_len)
      pos = pos + vol_len + 2
      table.insert(parms.volumes, string.format("%s", volume_name) )
    end

    response:setResult(parms)

    return response
  end,


  --- Sends an FPLogin request to the server and handles the response
  --
  -- This function currently only supports the 3.1 through 3.3 protocol versions
  -- It currently supports the following authentication methods:
  --   o No User Authent
  --   o DHCAST128
  --
  -- The DHCAST128 UAM should work against most servers even though it's
  -- superceded by the DHX2 UAM.
  --
  -- @param afp_version string (AFP3.3|AFP3.2|AFP3.1)
  -- @param uam string containing authentication information
  -- @return Response object
  fp_login = function( self, afp_version, uam, username, password, options )
    local packet, status, data
    local data_offset = 0
    local status, response

    if not HAVE_SSL then
      response = Response:new()
      response:setErrorMessage("OpenSSL not available, aborting ...")
      return response
    end

    -- currently we only support AFP3.3
    if afp_version == nil or ( afp_version ~= "AFP3.3" and afp_version ~= "AFP3.2" and afp_version ~= "AFP3.1" ) then
      response = Response:new()
      response:setErrorMessage("Incorrect AFP version")
      return response
    end

    if ( uam == "No User Authent" ) then
      data = bin.pack( "CCACA", COMMAND.FPLogin, afp_version:len(), afp_version, uam:len(), uam )
      packet = self:create_fp_packet( REQUEST.Command, data_offset, data )
      self:send_fp_packet( packet )
      return self:read_fp_packet( )
    elseif( uam == "DHCAST128" ) then
      local dhx_s2civ, dhx_c2civ = 'CJalbert', 'LWallace'
      local p, g, Ra, Ma, Mb, K, nonce
      local EncData, PlainText, K_bin, auth_response
      local _, Id
      local username = username or ""
      local password = password or ""

      username = username .. string.rep('\0', (#username + 1) % 2)

      p = openssl.bignum_hex2bn("BA2873DFB06057D43F2024744CEEE75B")
      g = openssl.bignum_dec2bn("7")
      Ra = openssl.bignum_hex2bn("86F6D3C0B0D63E4B11F113A2F9F19E3BBBF803F28D30087A1450536BE979FD42")
      Ma = openssl.bignum_mod_exp(g, Ra, p)

      data = bin.pack( "CpppA", COMMAND.FPLogin, afp_version, uam, username, openssl.bignum_bn2bin(Ma) )
      packet = self:create_fp_packet( REQUEST.Command, data_offset, data )
      self:send_fp_packet( packet )
      response = self:read_fp_packet( )
      if ( response:getErrorCode() ~= ERROR.FPAuthContinue ) then
        return response
      end

      if ( response.packet.header.length ~= 50 ) then
        response:setErrorMessage("LoginContinue packet contained invalid data")
        return response
      end

      _, Id, Mb, EncData = bin.unpack(">SH16A32", response.packet.data )

      Mb = openssl.bignum_hex2bn( Mb )
      K = openssl.bignum_mod_exp (Mb, Ra, p)
      K_bin = openssl.bignum_bn2bin(K)
      nonce = openssl.decrypt("cast5-cbc", K_bin, dhx_s2civ, EncData, false ):sub(1,16)
      nonce = openssl.bignum_add( openssl.bignum_bin2bn(nonce), openssl.bignum_dec2bn("1") )
      PlainText = openssl.bignum_bn2bin(nonce) .. Util.ZeroPad(password, 64)
      auth_response = openssl.encrypt( "cast5-cbc", K_bin, dhx_c2civ, PlainText, true)

      data = bin.pack( "CC>SA", COMMAND.FPLoginCont, 0, Id, auth_response )
      packet = self:create_fp_packet( REQUEST.Command, data_offset, data )
      self:send_fp_packet( packet )
      response = self:read_fp_packet( )
      if ( response:getErrorCode() ~= ERROR.FPNoErr ) then
        return response
      end
      return response
    end
    response:setErrorMessage("Unsupported uam: " .. uam or "nil")
    return response
  end,

  -- Terminates sessions and frees server resources established by FPLoginand FPLoginExt.
  --
  -- @return response object
  fp_logout = function( self )
    local packet, data, response
    local data_offset, pad = 0, 0

    data = bin.pack("CC", COMMAND.FPLogout, pad)
    packet = self:create_fp_packet( REQUEST.Command, data_offset, data )
    self:send_fp_packet( packet )
    return self:read_fp_packet( )
  end,

  --- Sends an FPOpenVol request to the server and handles the response
  --
  -- @param bitmap number bitmask of volume information to request
  -- @param volume_name string containing the volume name to query
  -- @return response object with the following result <code>bitmap</code> and
  --     <code>volume_id</code> fields
  fp_open_vol = function( self, bitmap, volume_name )
    local packet, status, pos, data
    local data_offset, pad = 0, 0
    local response, volume = {}, {}

    data = bin.pack("CC>SCA", COMMAND.FPOpenVol, pad, bitmap, volume_name:len(), volume_name )
    packet = self:create_fp_packet( REQUEST.Command, data_offset, data )
    self:send_fp_packet( packet )
    response = self:read_fp_packet()
    if response:getErrorCode() ~= ERROR.FPNoErr then
      return response
    end

    pos, volume.bitmap, volume.volume_id = bin.unpack(">S>S", response.packet.data)
    response:setResult(volume)
    return response
  end,


  --- Sends an FPGetFileDirParms request to the server and handles the response
  --
  -- @param volume_id number containing the id of the volume to query
  -- @param did number containing the id of the directory to query
  -- @param file_bitmap number bitmask of file information to query
  -- @param dir_bitmap number bitmask of directory information to query
  -- @param path string containing the name of the directory to query
  -- @return response object with the following result <code>file_bitmap</code>, <code>dir_bitmap</code>,
  --     <code>file_type</code> and (<code>dir<code> or <code>file</code> tables) depending on whether
  --     <code>did</code> is a file or directory
  fp_get_file_dir_parms = function( self, volume_id, did, file_bitmap, dir_bitmap, path )

    local packet, status, data
    local data_offset = 0
    local pad = 0
    local response, parms = {}, {}
    local pos

    if ( did == nil ) then
      response = Response:new()
      response:setErrorMessage("No Directory Id supplied")
      return response
    end

    if ( volume_id == nil ) then
      response = Response:new()
      response:setErrorMessage("No Volume Id supplied")
      return response
    end

    data = bin.pack("CC>S>I>S>SCCAC", COMMAND.FPGetFileDirParams, pad, volume_id, did, file_bitmap, dir_bitmap, path.type, path.len, path.name, 0)
    packet = self:create_fp_packet( REQUEST.Command, data_offset, data )
    self:send_fp_packet( packet )
    response = self:read_fp_packet()

    if response:getErrorCode() ~= ERROR.FPNoErr then
      return response
    end

    pos, parms.file_bitmap, parms.dir_bitmap, parms.file_type, pad = bin.unpack( ">S>SCC", response.packet.data )

    -- file or dir?
    if ( parms.file_type == 0x80 ) then
      pos, parms.dir = Util.decode_dir_bitmap( parms.dir_bitmap, response.packet.data, pos )
    else
      -- file
      pos, parms.file = Util.decode_file_bitmap( parms.file_bitmap, response.packet.data, pos )
    end

    response:setResult(parms)
    return response
  end,

  --- Sends an FPEnumerateExt2 request to the server and handles the response
  --
  -- @param volume_id number containing the id of the volume to query
  -- @param did number containing the id of the directory to query
  -- @param file_bitmap number bitmask of file information to query
  -- @param dir_bitmap number bitmask of directory information to query
  -- @param req_count number
  -- @param start_index number
  -- @param reply_size number
  -- @param path string containing the name of the directory to query
  -- @return response object with the following result set to a table of tables containing
  --   <code>file_bitmap</code>, <code>dir_bitmap</code>, <code>req_count</code> fields
  fp_enumerate_ext2 = function( self, volume_id, did, file_bitmap, dir_bitmap, req_count, start_index, reply_size, path )

    local packet, pos, _, status
    local data_offset = 0
    local pad = 0
    local response,records = {}, {}

    local data = bin.pack( "CC>S>I>S>S", COMMAND.FPEnumerateExt2, pad, volume_id, did, file_bitmap, dir_bitmap )
    .. bin.pack( ">S>I>ICCA", req_count, start_index, reply_size, path.type, path.len, path.name )
    packet = self:create_fp_packet( REQUEST.Command, data_offset, data )

    self:send_fp_packet( packet )
    response = self:read_fp_packet( )

    if response:getErrorCode() ~= ERROR.FPNoErr then
      return response
    end

    pos, file_bitmap, dir_bitmap, req_count = bin.unpack(">S>S>S", response.packet.data)

    records = {}

    for i=1, req_count do
      local record = {}
      local len, _, ftype

      pos, len, ftype, _ = bin.unpack(">SCC", response.packet.data, pos)

      if ( ftype == 0x80 ) then
        _, record = Util.decode_dir_bitmap( dir_bitmap, response.packet.data, pos )
      else
        -- file
        _, record = Util.decode_file_bitmap( file_bitmap, response.packet.data, pos )
      end

      if bit.mod( len, 2 ) ~= 0 then
        len = len + 1
      end

      pos = pos + ( len - 4 )

      record.type = ftype
      table.insert(records, record)
    end

    response:setResult(records)
    return response
  end,

  --- Sends an FPOpenFork request to the server and handles the response
  --
  -- @param flag number
  -- @param volume_id number containing the id of the volume to query
  -- @param did number containing the id of the directory to query
  -- @param file_bitmap number bitmask of file information to query
  -- @param access_mode number containing bitmask of options from <code>ACCESS_MODE</code>
  -- @param path string containing the name of the directory to query
  -- @return response object with the following result contents <code>file_bitmap</code> and <code>fork_id</code>
  fp_open_fork = function( self, flag, volume_id, did, file_bitmap, access_mode, path )

    local packet, _
    local data_offset = 0
    local pad = 0
    local response, fork = {}, {}

    local data = bin.pack( "CC>S>I>S>S", COMMAND.FPOpenFork, flag, volume_id, did, file_bitmap, access_mode )

    if path.type == PATH_TYPE.LongName then
      data = data .. bin.pack( "CCA", path.type, path.len, path.name )
    end

    if path.type == PATH_TYPE.UTF8Name then
      local unicode_hint = 0x08000103
      data = data .. bin.pack( "C>I>SA", path.type, unicode_hint, path.len, path.name )
    end

    packet = self:create_fp_packet( REQUEST.Command, data_offset, data )
    self:send_fp_packet( packet )
    response = self:read_fp_packet()

    if response:getErrorCode() ~= ERROR.FPNoErr then
      return response
    end

    _, fork.file_bitmap, fork.fork_id = bin.unpack(">S>S", response.packet.data)
    response:setResult(fork)
    return response
  end,

  --- FPCloseFork
  --
  -- @param fork number containing the fork to close
  -- @return response object
  fp_close_fork = function( self, fork )
    local packet
    local data_offset = 0
    local pad = 0
    local response = {}

    local data = bin.pack( "CC>S", COMMAND.FPCloseFork, pad, fork )

    packet = self:create_fp_packet( REQUEST.Command, data_offset, data )
    self:send_fp_packet( packet )
    return self:read_fp_packet( )
  end,

  --- FPCreateDir
  --
  -- @param vol_id number containing the volume id
  -- @param dir_id number containing the directory id
  -- @param path string containing the name of the directory
  -- @return response object
  fp_create_dir = function( self, vol_id, dir_id, path )
    local packet
    local data_offset, pad = 0, 0
    local response = {}

    local data = bin.pack( "CC>S>ICp", COMMAND.FPCreateDir, pad, vol_id, dir_id, path.type, path.name )

    packet = self:create_fp_packet( REQUEST.Command, data_offset, data )
    self:send_fp_packet( packet )
    return self:read_fp_packet( )
  end,

  --- Sends an FPCloseVol request to the server and handles the response
  --
  -- @param volume_id number containing the id of the volume to close
  -- @return response object
  fp_close_vol = function( self, volume_id )
    local packet
    local data_offset, pad = 0, 0
    local response = {}

    local data = bin.pack( "CC>S", COMMAND.FPCloseVol, pad, volume_id )

    packet = self:create_fp_packet( REQUEST.Command, data_offset, data )
    self:send_fp_packet( packet )
    return self:read_fp_packet( )
  end,

  --- FPReadExt
  --
  -- @param fork number containing the open fork
  -- @param offset number containing the offset from where writing should start. Negative value indicates offset from the end of the fork
  -- @param count number containing the number of bytes to be written
  -- @return response object
  fp_read_ext = function( self, fork, offset, count )
    local pad = 0
    local packet, response
    local data_offset = 0
    local block_size = 1024
    local data = bin.pack( "CC>S>L>L", COMMAND.FPReadExt, pad, fork, offset, count  )

    packet = self:create_fp_packet( REQUEST.Command, data_offset, data )
    self:send_fp_packet( packet )
    response = self:read_fp_packet( )

    if ( response:getErrorCode() == ERROR.FPEOFErr and response.packet.header.length > 0 ) then
      response:setErrorCode( ERROR.FPNoErr )
    end

    response:setResult( response.packet.data )
    return response
  end,

  --- FPWriteExt
  --
  -- @param flag number indicates whether Offset is relative to the beginning or end of the fork.
  -- @param fork number containing the open fork
  -- @param offset number containing the offset from where writing should start. Negative value indicates offset from the end of the fork
  -- @param count number containing the number of bytes to be written
  -- @param fdata string containing the data to be written
  -- @return response object
  fp_write_ext = function( self, flag, fork, offset, count, fdata )
    local packet
    local data_offset = 20
    local data

    if count > fdata:len() then
      local err = Response:new()
      err:setErrorMessage("fp_write_ext: Count is greater than the amount of data")
      return err
    end
    if count < 0 then
      local err = Response:new()
      err:setErrorMessage("fp_write_ext: Count must exceed zero")
      return err
    end

    data = bin.pack( "CC>S>L>LA", COMMAND.FPWriteExt, flag, fork, offset, count, fdata  )
    packet = self:create_fp_packet( REQUEST.Write, data_offset, data )
    self:send_fp_packet( packet )
    return self:read_fp_packet( )
  end,

  --- FPCreateFile
  --
  -- @param flag number where 0 indicates a soft create and 1 indicates a hard create.
  -- @param vol_id number containing the volume id
  -- @param did number containing the ancestor directory id
  -- @param path string containing the path, including the volume, path and file name
  -- @return response object
  fp_create_file = function(self, flag, vol_id, did, path )
    local packet
    local data_offset = 0
    local data = bin.pack( "CC>S>ICCA" , COMMAND.FPCreateFile, flag, vol_id, did, path.type, path.len, path.name  )

    packet = self:create_fp_packet( REQUEST.Command, data_offset, data )
    self:send_fp_packet( packet )
    return self:read_fp_packet()
  end,

  --- FPMapId
  --
  -- @param subfunc number containing the subfunction to call
  -- @param id number containing th id to translate
  -- @return response object with the id in the <code>result</code> field
  fp_map_id = function( self, subfunc, id )
    local packet, response
    local data_offset = 0
    local data = bin.pack( "CC", COMMAND.FPMapId, subfunc )
    local _, len

    if ( subfunc == MAP_ID.UserUUIDToUTF8Name or subfunc == MAP_ID.GroupUUIDToUTF8Name ) then
      data = data .. bin.pack(">L", id)
    else
      data = data .. bin.pack(">I", id)
    end

    packet = self:create_fp_packet( REQUEST.Command, data_offset, data )
    self:send_fp_packet( packet )
    response = self:read_fp_packet( )

    if response:getErrorCode() ~= ERROR.FPNoErr then
      return response
    end

    -- Netatalk returns the name with 1-byte length prefix,
    -- Mac OS has a 2-byte (UTF-8) length prefix
    local _, len = bin.unpack("C", response.packet.data)

    -- if length is zero assume 2-byte length (UTF-8 name)
    if len == 0 then
      response:setResult( select(2, bin.unpack(">P", response.packet.data )) )
    else
      response:setResult( select(2, bin.unpack("p", response.packet.data )) )
    end
    return response
  end,

  --- FPMapName
  --
  -- @param subfunc number containing the subfunction to call
  -- @param name string containing name to map
  -- @return response object with the mapped name in the <code>result</code> field
  fp_map_name = function( self, subfunc, name )
    local packet
    local data_offset = 0
    local data = bin.pack( "CC>SA", COMMAND.FPMapName, subfunc, name:len(), name )
    local response

    packet = self:create_fp_packet( REQUEST.Command, data_offset, data )
    self:send_fp_packet( packet )
    response = self:read_fp_packet( )

    if response:getErrorCode() ~= ERROR.FPNoErr then
      return response
    end

    response:setResult( select(2, bin.unpack(">I", response.packet.data)))
    return response
  end,
}

--- The helper class wraps the protocol class and their functions. It contains
-- high-level functions with descriptive names, facilitating the use and
-- minimizing the need to fully understand the AFP low-level protocol details.
Helper = {

  --- Creates a new helper object
  new = function(self,o)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.username = stdnse.get_script_args("afp.username")
    o.password = stdnse.get_script_args("afp.password")
    return o
  end,

  --- Connects to the remote server and establishes a new AFP session
  --
  -- @param host table as received by the action function of the script
  -- @param port table as received by the action function of the script
  -- @return status boolean
  -- @return string containing error message (if status is false)
  OpenSession = function( self, host, port )
    local status, response

    self.socket = nmap.new_socket()
    self.socket:set_timeout( 5000 )
    status = self.socket:connect(host, port)
    if not status then
      return false, "Socket connection failed"
    end

    self.proto = Proto:new( { socket=self.socket} )
    response = self.proto:dsi_open_session(self.socket)

    if response:getErrorCode() ~= ERROR.FPNoErr then
      self.socket:close()
      return false, response:getErrorMessage()
    end

    return true
  end,

  --- Closes the AFP session and then the socket
  --
  -- @return status boolean
  -- @return string containing error message (if status is false)
  CloseSession = function( self )
    local status, packet = self.proto:dsi_close_session( )
    self.socket:close()

    return status, packet
  end,

  --- Terminates the connection, without closing the AFP session
  --
  -- @return status (always true)
  -- @return string (always "")
  Terminate = function( self )
    self.socket:close()
    return true,""
  end,

  --- Logs in to an AFP service
  --
  -- @param username (optional) string containing the username
  -- @param password (optional) string containing the user password
  -- @param options table containing additional options <code>uam</code>
  Login = function( self, username, password, options )
    local uam = ( options and options.UAM ) and options.UAM or "DHCAST128"
    local response

    -- username and password arguments override the ones supplied using the
    -- script arguments afp.username and afp.password
    local username = username or self.username
    local password = password or self.password

    if ( username and uam == "DHCAST128" ) then
      response = self.proto:fp_login( "AFP3.1", "DHCAST128", username, password )
    elseif( username ) then
      return false, ("Unsupported UAM: %s"):format(uam)
    else
      response = self.proto:fp_login( "AFP3.1", "No User Authent" )
    end

    if response:getErrorCode() ~= ERROR.FPNoErr then
      return false, response:getErrorMessage()
    end

    return true, "Success"
  end,

  --- Logs out from the AFP service
  Logout = function(self)
    return self.proto:fp_logout()
  end,

  --- Walks the directory tree specified by <code>str_path</code> and returns the node information
  --
  -- @param str_path string containing the directory
  -- @return status boolean true on success, otherwise false
  -- @return item table containing node information <code>DirectoryId</code> and <code>DirectoryName</code>
  WalkDirTree = function( self, str_path )
    local status, response, path
    local elements = stdnse.strsplit( "/", str_path )
    local f_bm = FILE_BITMAP.NodeId + FILE_BITMAP.ParentDirId + FILE_BITMAP.LongName
    local d_bm = DIR_BITMAP.NodeId + DIR_BITMAP.ParentDirId + DIR_BITMAP.LongName
    local item = { DirectoryId = 2 }

    response = self.proto:fp_open_vol( VOL_BITMAP.ID, elements[1] )
    if response:getErrorCode() ~= ERROR.FPNoErr then
      return false, response:getErrorMessage()
    end

    item.VolumeId = response.result.volume_id
    item.DirectoryName = str_path

    for i=2, #elements do
      path = { ['type']=PATH_TYPE.LongName, name=elements[i], len=elements[i]:len() }
      response = self.proto:fp_get_file_dir_parms( item.VolumeId, item.DirectoryId, f_bm, d_bm, path )
      if response:getErrorCode() ~= ERROR.FPNoErr then
        return false, response:getErrorMessage()
      end
      item.DirectoryId = response.result.dir.NodeId
      item.DirectoryName = response.result.dir.LongName
    end

    return true, item
  end,

  --- Reads a file on the AFP server
  --
  -- @param str_path string containing the AFP sharepoint, path and filename eg. HR/Documents/File.doc
  -- @return status boolean true on success, false on failure
  -- @return content string containing the file contents
  ReadFile = function( self, str_path )
    local status, response, fork, content, vol_name
    local offset, count, did = 0, 1024, 2
    local status, path, vol_id
    local p = Util.SplitPath( str_path )

    status, response = self:WalkDirTree( p.dir )
    if ( not status ) then
      return false, response
    end

    vol_id = response.VolumeId
    did = response.DirectoryId

    path = { ['type']=PATH_TYPE.LongName, name=p.file, len=p.file:len() }

    response = self.proto:fp_open_fork(0, vol_id, did, 0, ACCESS_MODE.Read, path )
    if response:getErrorCode() ~= ERROR.FPNoErr then
      return false, response:getErrorMessage()
    end

    fork = response.result.fork_id
    content = ""

    while true do
      response = self.proto:fp_read_ext( fork, offset, count )
      if response:getErrorCode() ~= ERROR.FPNoErr then
        break
      end
      content = content .. response.result
      offset = offset + count
    end

    response = self.proto:fp_close_fork( fork )
    if response:getErrorCode() ~= ERROR.FPNoErr then
      return false, response:getErrorMessage()
    end

    return true, content
  end,

  --- Writes a file to the AFP server
  --
  -- @param str_path string containing the AFP sharepoint, path and filename eg. HR/Documents/File.doc
  -- @param fdata string containing the data to write to the file
  -- @return status boolean true on success, false on failure
  -- @return error string containing error message if status is false
  WriteFile = function( self, str_path, fdata )
    local status, response, fork, content
    local offset, count = 1, 1024
    local status, vol_id, did, path
    local p = Util.SplitPath( str_path )

    status, response = self:WalkDirTree( p.dir )
    vol_id = response.VolumeId
    did = response.DirectoryId

    if ( not status ) then
      return false, response
    end

    path = { ['type']=PATH_TYPE.LongName, name=p.file, len=p.file:len() }

    status, response = self.proto:fp_create_file( 0, vol_id, did, path )
    if not status then
      if ( response.header.error_code ~= ERROR.FPObjectExists ) then
        return false, response.header.error_msg
      end
    end

    response = self.proto:fp_open_fork( 0, vol_id, did, 0, ACCESS_MODE.Write, path )
    if response:getErrorCode() ~= ERROR.FPNoErr then
      return false, response:getErrorMessage()
    end

    fork = response.result.fork_id

    response = self.proto:fp_write_ext( 0, fork, 0, fdata:len(), fdata )

    return true, nil
  end,

  --- Maps a user id (uid) to a user name
  --
  -- @param uid number containing the uid to resolve
  -- @return status boolean true on success, false on failure
  -- @return username string on success
  --         error string on failure
  UIDToName = function( self, uid )
    local response = self.proto:fp_map_id( MAP_ID.UserIDToName, uid )
    if response:getErrorCode() ~= ERROR.FPNoErr then
      return false, response:getErrorMessage()
    end
    return true, response.result
  end,

  --- Maps a group id (gid) to group name
  --
  -- @param gid number containing the gid to lookup
  -- @return status boolean true on success, false on failure
  -- @return groupname string on success
  --         error string on failure
  GIDToName = function( self, gid )
    local response = self.proto:fp_map_id( MAP_ID.GroupIDToName, gid )
    if response:getErrorCode() ~= ERROR.FPNoErr then
      return false, response:getErrorMessage()
    end
    return true, response.result
  end,

  --- Maps a username to a UID
  --
  -- @param name string containing the username to map to an UID
  -- @return status boolean true on success, false on failure
  -- @return UID number on success
  --         error string on failure
  NameToUID = function( self, name )
    local response = self.proto:fp_map_name( MAP_NAME.NameToUserID, name )
    if response:getErrorCode() ~= ERROR.FPNoErr then
      return false, response:getErrorMessage()
    end
    return true, response.result
  end,

  --- List the contents of a directory
  --
  -- @param str_path string containing the sharepoint and directory names
  -- @param options table options containing zero or more of the options
  -- <code>max_depth</code> and <code>dironly</code>
  -- @param depth number containing the current depth (used when called recursively)
  -- @param parent table containing information about the parent object (used when called recursively)
  -- @return status boolean true on success, false on failure
  -- @return dir table containing a table for each directory item with the following <code>type</code>,
  --         <code>name</code> and <code>id</code>
  Dir = function( self, str_path, options, depth, parent )
    local status, result
    local depth = depth or 1
    local options = options or { max_depth = 1 }
    local response, records
    local f_bm = FILE_BITMAP.NodeId + FILE_BITMAP.ParentDirId + FILE_BITMAP.LongName
    local d_bm = DIR_BITMAP.NodeId + DIR_BITMAP.ParentDirId + DIR_BITMAP.LongName
    local path = { ['type']=PATH_TYPE.LongName, name="", len=0 }

    local TYPE_DIR = 0x80

    if ( parent == nil ) then
      status, response = self:WalkDirTree( str_path )
      if ( not status ) then
        return false, response
      end

      parent = {}
      parent.vol_id = response.VolumeId
      parent.did = response.DirectoryId
      parent.dir_name = response.DirectoryName or ""
      parent.out_tbl = {}
    end

    if ( options and options.max_depth and options.max_depth > 0 and options.max_depth < depth ) then
      return false, "Max Depth Reached"
    end

    response = self.proto:fp_enumerate_ext2( parent.vol_id, parent.did, f_bm, d_bm, 1000, 1, 52800, path)

    if response:getErrorCode() ~= ERROR.FPNoErr then
      return false, response:getErrorMessage()
    end

    records = response.result or {}
    local dir_item = {}

    for _, record in ipairs( records ) do
      if ( options and options.dironly ) then
        if ( record.type == TYPE_DIR ) then
          table.insert( dir_item, { ['type'] = record.type, ['name'] = record.LongName, ['id'] = record.NodeId } )
        end
      else
        table.insert( dir_item, { ['type'] = record.type, ['name'] = record.LongName, ['id'] = record.NodeId } )
      end
      if ( record.type == TYPE_DIR ) then
        self:Dir("", options, depth + 1, { vol_id = parent.vol_id, did=record.NodeId, dir_name=record.LongName, out_tbl=dir_item} )
      end
    end

    table.insert( parent.out_tbl, dir_item )

    return true, parent.out_tbl
  end,

  --- Displays a directory tree
  --
  -- @param str_path string containing the sharepoint and the directory
  -- @param options table options containing zero or more of the options
  -- <code>max_depth</code> and <code>dironly</code>
  -- @return dirtree table containing the directories
  DirTree = function( self, str_path, options )
    local options = options or {}
    options.dironly = true
    return self:Dir( str_path, options )
  end,

  --- List the AFP sharepoints
  --
  -- @return volumes table containing the sharepoints
  ListShares = function( self )
    local response
    response = self.proto:fp_get_srvr_parms( )

    if response:getErrorCode() ~= ERROR.FPNoErr then
      return false, response:getErrorMessage()
    end

    return true, response.result.volumes
  end,

  --- Determine the sharepoint permissions
  --
  -- @param vol_name string containing the name of the volume
  -- @return status boolean true on success, false on failure
  -- @return acls table containing the volume acls as returned by <code>acls_to_long_string</code>
  GetSharePermissions = function( self, vol_name )
    local status, response, vol_id, acls

    response = self.proto:fp_open_vol( VOL_BITMAP.ID, vol_name )

    if response:getErrorCode() == ERROR.FPNoErr then
      local vol_id
      local path = {}

      vol_id = response.result.volume_id
      path.type = PATH_TYPE.LongName
      path.name = ""
      path.len = path.name:len()

      response = self.proto:fp_get_file_dir_parms( vol_id, 2, FILE_BITMAP.ALL, DIR_BITMAP.ALL, path )
      if response:getErrorCode() == ERROR.FPNoErr then
        if ( response.result.dir and response.result.dir.AccessRights ) then
          acls = Util.acls_to_long_string(response.result.dir.AccessRights)
          acls.name = nil
        end
      end
      self.proto:fp_close_vol( vol_id )
    end

    return true, acls
  end,

  --- Gets the Unix permissions of a file
  -- @param vol_name string containing the name of the volume
  -- @param str_path string containing the name of the file
  -- @return status true on success, false on failure
  -- @return acls table (on success) containing the following fields
  --  <code>uid</code> - a numeric user identifier
  --  <code>gid</code> - a numeric group identifier
  --  <code>privs</code> - a string value representing the permissions
  --                       eg: drwx------
  -- @return err string (on failure) containing the error message
  GetFileUnixPermissions = function(self, vol_name, str_path)
    local response = self.proto:fp_open_vol( VOL_BITMAP.ID, vol_name )

    if ( response:getErrorCode() ~= ERROR.FPNoErr ) then
      return false, response:getErrorMessage()
    end

    local vol_id = response.result.volume_id
    local path = { type = PATH_TYPE.LongName, name = str_path, len = #str_path }
    response = self.proto:fp_get_file_dir_parms( vol_id, 2, FILE_BITMAP.UnixPrivileges, DIR_BITMAP.UnixPrivileges, path )
    if ( response:getErrorCode() ~= ERROR.FPNoErr ) then
      return false, response:getErrorMessage()
    end

    local item = ( response.result.file ) and response.result.file or response.result.dir
    local item_type = ( response.result.file ) and "-" or "d"
    local privs = ( item.UnixPrivileges and item.UnixPrivileges.ua_permissions ) and
      item.UnixPrivileges.ua_permissions
    if ( privs ) then
      local uid = item.UnixPrivileges.uid
      local gid = item.UnixPrivileges.gid
      local str_privs = item_type .. Util.decode_unix_privs(privs)
      return true, { uid = uid, gid = gid, privs = str_privs }
    end
  end,

  --- Gets the Unix permissions of a file
  -- @param vol_name string containing the name of the volume
  -- @param str_path string containing the name of the file
  -- @return status true on success, false on failure
  -- @return size containing the size of the file in bytes
  -- @return err string (on failure) containing the error message
  GetFileSize = function( self, vol_name, str_path )
    local response = self.proto:fp_open_vol( VOL_BITMAP.ID, vol_name )

    if ( response:getErrorCode() ~= ERROR.FPNoErr ) then
      return false, response:getErrorMessage()
    end

    local vol_id = response.result.volume_id
    local path = { type = PATH_TYPE.LongName, name = str_path, len = #str_path }
    response = self.proto:fp_get_file_dir_parms( vol_id, 2, FILE_BITMAP.ExtendedDataForkSize, 0, path )
    if ( response:getErrorCode() ~= ERROR.FPNoErr ) then
      return false, response:getErrorMessage()
    end

    return true, ( response.result.file and
      response.result.file.ExtendedDataForkSize) and
      response.result.file.ExtendedDataForkSize or 0
  end,


  --- Returns the creation, modification and backup dates of a file
  -- @param vol_name string containing the name of the volume
  -- @param str_path string containing the name of the file
  -- @return status true on success, false on failure
  -- @return dates table containing the following fields:
  --  <code>create</code> - Creation date of the file
  --  <code>modify</code> - Modification date of the file
  --  <code>backup</code> - Date of last backup
  -- @return err string (on failure) containing the error message
  GetFileDates = function( self, vol_name, str_path )
    local response = self.proto:fp_open_vol( VOL_BITMAP.ID, vol_name )

    if ( response:getErrorCode() ~= ERROR.FPNoErr ) then
      return false, response:getErrorMessage()
    end

    local vol_id = response.result.volume_id
    local path = { type = PATH_TYPE.LongName, name = str_path, len = #str_path }
    local f_bm = FILE_BITMAP.CreationDate + FILE_BITMAP.ModificationDate + FILE_BITMAP.BackupDate
    local d_bm = DIR_BITMAP.CreationDate + DIR_BITMAP.ModificationDate + DIR_BITMAP.BackupDate
    response = self.proto:fp_get_file_dir_parms( vol_id, 2, f_bm, d_bm, path )
    if ( response:getErrorCode() ~= ERROR.FPNoErr ) then
      return false, response:getErrorMessage()
    end

    local item = ( response.result.file ) and response.result.file or response.result.dir

    local diff = os.time{year=2000, month=1, day=1, hour=0} - os.time{year=1970, month=1, day=1, hour=0}
    local create = os.date("%Y-%m-%d %H:%M", item.CreationDate + diff)
    local backup = os.date("%Y-%m-%d %H:%M", item.BackupDate )
    local modify = os.date("%Y-%m-%d %H:%M", item.ModificationDate + diff )

    return true, { create = create, backup = backup, modify = modify }
  end,

  --- Creates a new directory on the AFP sharepoint
  --
  -- @param str_path containing the sharepoint and the directory
  -- @return status boolean true on success, false on failure
  -- @return dirId number containing the new directory id
  CreateDir = function( self, str_path )
    local status, response, vol_id, did
    local p = Util.SplitPath( str_path )
    local path = { ['type']=PATH_TYPE.LongName, name=p.file, len=p.file:len() }


    status, response = self:WalkDirTree( p.dir )
    if not status then
      return false, response
    end

    response = self.proto:fp_create_dir( response.VolumeId, response.DirectoryId, path )
    if response:getErrorCode() ~= ERROR.FPNoErr then
      return false, response:getErrorMessage()
    end

    return true, response
  end,

}

--- Util class, containing some static functions used by Helper and Proto
Util =
{
  --- Pads a string with zeroes
  --
  -- @param str string containing the string to be padded
  -- @param len number containing the length of the new string
  -- @return str string containing the new string
  ZeroPad = function( str, len )
    return str .. string.rep('\0', len - str:len())
  end,

  --- Splits a path into two pieces, directory and file
  --
  -- @param str_path string containing the path to split
  -- @return dir table containing <code>dir</code> and <code>file</code>
  SplitPath = function( str_path )
    local elements = stdnse.strsplit("/", str_path)
    local dir, file = "", ""

    if #elements < 2 then
      return nil
    end

    file = elements[#elements]

    table.remove( elements, #elements )
    dir = stdnse.strjoin( "/", elements )

    return { ['dir']=dir, ['file']=file }

  end,

  --- Converts a group bitmask of Search, Read and Write to table
  --
  -- @param acls number containing bitmasked acls
  -- @return table of ACLs
  acl_group_to_long_string = function(acls)

    local acl_table = {}

    if bit.band( acls, ACLS.OwnerSearch ) == ACLS.OwnerSearch then
      table.insert( acl_table, "Search")
    end

    if bit.band( acls, ACLS.OwnerRead ) == ACLS.OwnerRead then
      table.insert( acl_table, "Read")
    end

    if bit.band( acls, ACLS.OwnerWrite ) == ACLS.OwnerWrite then
      table.insert( acl_table, "Write")
    end

    return acl_table
  end,


  --- Converts a numeric acl to string
  --
  -- @param acls number containing acls as received from <code>fp_get_file_dir_parms</code>
  -- @return table of long ACLs
  acls_to_long_string = function( acls )

    local owner = Util.acl_group_to_long_string( bit.band( acls, 255 ) )
    local group = Util.acl_group_to_long_string( bit.band( bit.rshift(acls, 8), 255 ) )
    local everyone = Util.acl_group_to_long_string( bit.band( bit.rshift(acls, 16), 255 ) )
    local user = Util.acl_group_to_long_string( bit.band( bit.rshift(acls, 24), 255 ) )

    local blank = bit.band( acls, ACLS.BlankAccess ) == ACLS.BlankAccess and "Blank" or nil
    local isowner = bit.band( acls, ACLS.UserIsOwner ) == ACLS.UserIsOwner and "IsOwner" or nil

    local options = {}

    if blank then
      table.insert(options, "Blank")
    end

    if isowner then
      table.insert(options, "IsOwner")
    end

    local acls_tbl = {}

    table.insert( acls_tbl, string.format( "Owner: %s", stdnse.strjoin(",", owner) ) )
    table.insert( acls_tbl, string.format( "Group: %s", stdnse.strjoin(",", group) ) )
    table.insert( acls_tbl, string.format( "Everyone: %s", stdnse.strjoin(",", everyone) ) )
    table.insert( acls_tbl, string.format( "User: %s", stdnse.strjoin(",", user) ) )

    if #options > 0 then
      table.insert( acls_tbl, string.format( "Options: %s", stdnse.strjoin(",", options ) ) )
    end

    return acls_tbl

  end,


  --- Decodes the UnixPrivileges.ua_permissions value
  --
  -- @param privs number containing the UnixPrivileges.ua_permissions value
  -- @return string containing the ACL characters
  decode_unix_privs = function( privs )
    local owner = ( bit.band( privs, ACLS.OwnerRead ) == ACLS.OwnerRead ) and "r" or "-"
    owner = owner .. (( bit.band( privs, ACLS.OwnerWrite ) == ACLS.OwnerWrite ) and "w" or "-")
    owner = owner .. (( bit.band( privs, ACLS.OwnerSearch ) == ACLS.OwnerSearch ) and "x" or "-")

    local group = ( bit.band( privs, ACLS.GroupRead ) == ACLS.GroupRead ) and "r" or "-"
    group = group .. (( bit.band( privs, ACLS.GroupWrite ) == ACLS.GroupWrite ) and "w" or "-")
    group = group .. (( bit.band( privs, ACLS.GroupSearch ) == ACLS.GroupSearch ) and "x" or "-")

    local other = ( bit.band( privs, ACLS.EveryoneRead ) == ACLS.EveryoneRead ) and "r" or "-"
    other = other .. (( bit.band( privs, ACLS.EveryoneWrite ) == ACLS.EveryoneWrite ) and "w" or "-")
    other = other .. (( bit.band( privs, ACLS.EveryoneSearch ) == ACLS.EveryoneSearch ) and "x" or "-")

    return owner .. group .. other
  end,


  --- Decodes a file bitmap
  --
  -- @param bitmap number containing the bitmap
  -- @param data string containing the data to be decoded
  -- @param pos number containing the offset into data
  -- @return pos number containing the new offset after decoding
  -- @return file table containing the decoded values
  decode_file_bitmap = function( bitmap, data, pos )
    local file = {}

    if ( bit.band( bitmap, FILE_BITMAP.Attributes ) == FILE_BITMAP.Attributes ) then
      pos, file.Attributes = bin.unpack(">S", data, pos )
    end
    if ( bit.band( bitmap, FILE_BITMAP.ParentDirId ) == FILE_BITMAP.ParentDirId ) then
      pos, file.ParentDirId = bin.unpack(">I", data, pos )
    end
    if ( bit.band( bitmap, FILE_BITMAP.CreationDate ) == FILE_BITMAP.CreationDate ) then
      pos, file.CreationDate = bin.unpack(">I", data, pos )
    end
    if ( bit.band( bitmap, FILE_BITMAP.ModificationDate ) == FILE_BITMAP.ModificationDate ) then
      pos, file.ModificationDate = bin.unpack(">I", data, pos )
    end
    if ( bit.band( bitmap, FILE_BITMAP.BackupDate ) == FILE_BITMAP.BackupDate ) then
      pos, file.BackupDate = bin.unpack(">I", data, pos )
    end
    if ( bit.band( bitmap, FILE_BITMAP.FinderInfo ) == FILE_BITMAP.FinderInfo ) then
      pos, file.FinderInfo = bin.unpack("A32", data, pos )
    end
    if ( bit.band( bitmap, FILE_BITMAP.LongName ) == FILE_BITMAP.LongName ) then
      local offset, p, name
      pos, offset = bin.unpack(">S", data, pos)
      p, file.LongName = bin.unpack("p", data, offset + pos - 1)
    end
    if ( bit.band( bitmap, FILE_BITMAP.ShortName ) == FILE_BITMAP.ShortName ) then
      local offset, p, name
      pos, offset = bin.unpack(">S", data, pos)
      p, file.ShortName = bin.unpack("p", data, offset + pos - 1)
    end
    if ( bit.band( bitmap, FILE_BITMAP.NodeId ) == FILE_BITMAP.NodeId ) then
      pos, file.NodeId = bin.unpack(">I", data, pos )
    end
    if ( bit.band( bitmap, FILE_BITMAP.DataForkSize ) == FILE_BITMAP.DataForkSize ) then
      pos, file.DataForkSize = bin.unpack(">I", data, pos )
    end
    if ( bit.band( bitmap, FILE_BITMAP.ResourceForkSize ) == FILE_BITMAP.ResourceForkSize ) then
      pos, file.ResourceForkSize = bin.unpack(">I", data, pos )
    end
    if ( bit.band( bitmap, FILE_BITMAP.ExtendedDataForkSize ) == FILE_BITMAP.ExtendedDataForkSize ) then
      pos, file.ExtendedDataForkSize = bin.unpack(">L", data, pos )
    end
    if ( bit.band( bitmap, FILE_BITMAP.LaunchLimit ) == FILE_BITMAP.LaunchLimit ) then
      -- should not be set as it's deprecated according to:
      -- http://developer.apple.com/mac/library/documentation/Networking/Reference/AFP_Reference/Reference/reference.html#//apple_ref/doc/c_ref/kFPLaunchLimitBit
    end
    if ( bit.band( bitmap, FILE_BITMAP.UTF8Name ) == FILE_BITMAP.UTF8Name ) then
      local offset, p, name
      pos, offset = bin.unpack(">S", data, pos)
      p, file.UTF8Name = bin.unpack("p", data, offset + pos - 1)
    end
    if ( bit.band( bitmap, FILE_BITMAP.ExtendedResourceForkSize ) == FILE_BITMAP.ExtendedResourceForkSize ) then
      pos, file.ExtendedResourceForkSize = bin.unpack(">L", data, pos )
    end
    if ( bit.band( bitmap, FILE_BITMAP.UnixPrivileges ) == FILE_BITMAP.UnixPrivileges ) then
      local unixprivs = {}
      pos, unixprivs.uid, unixprivs.gid,
        unixprivs.permissions, unixprivs.ua_permissions = bin.unpack(">IIII", data, pos )
      file.UnixPrivileges = unixprivs
    end
    return pos, file
  end,

  --- Decodes a directory bitmap
  --
  -- @param bitmap number containing the bitmap
  -- @param data string containing the data to be decoded
  -- @param pos number containing the offset into data
  -- @return pos number containing the new offset after decoding
  -- @return dir table containing the decoded values
  decode_dir_bitmap = function( bitmap, data, pos )
    local dir = {}

    if ( bit.band( bitmap, DIR_BITMAP.Attributes ) == DIR_BITMAP.Attributes ) then
      pos, dir.Attributes = bin.unpack(">S", data, pos )
    end
    if ( bit.band( bitmap, DIR_BITMAP.ParentDirId ) == DIR_BITMAP.ParentDirId ) then
      pos, dir.ParentDirId = bin.unpack(">I", data, pos )
    end
    if ( bit.band( bitmap, DIR_BITMAP.CreationDate ) == DIR_BITMAP.CreationDate ) then
      pos, dir.CreationDate = bin.unpack(">I", data, pos )
    end
    if ( bit.band( bitmap, DIR_BITMAP.ModificationDate ) == DIR_BITMAP.ModificationDate ) then
      pos, dir.ModificationDate = bin.unpack(">I", data, pos )
    end
    if ( bit.band( bitmap, DIR_BITMAP.BackupDate ) == DIR_BITMAP.BackupDate ) then
      pos, dir.BackupDate = bin.unpack(">I", data, pos )
    end
    if ( bit.band( bitmap, DIR_BITMAP.FinderInfo ) == DIR_BITMAP.FinderInfo ) then
      pos, dir.FinderInfo = bin.unpack("A32", data, pos )
    end
    if ( bit.band( bitmap, DIR_BITMAP.LongName ) == DIR_BITMAP.LongName ) then
      local offset, p, name
      pos, offset = bin.unpack(">S", data, pos)

      -- TODO: This really needs to be addressed someway
      -- Barely, never, ever happens, which makes it difficult to pin down
      -- http://developer.apple.com/mac/library/documentation/Networking/Reference/
      -- AFP_Reference/Reference/reference.html#//apple_ref/doc/uid/TP40003548-CH3-CHDBEHBG [URL is wrapped]
      local justkidding = select(2, bin.unpack(">I", data, pos + 4))
      if ( justkidding ~= 0 ) then
        offset = 5
      end

      p, dir.LongName = bin.unpack("p", data, offset + pos - 1)
    end
    if ( bit.band( bitmap, DIR_BITMAP.ShortName ) == DIR_BITMAP.ShortName ) then
      local offset, p, name
      pos, offset = bin.unpack(">S", data, pos)
      p, dir.ShortName = bin.unpack("p", data, offset + pos - 1)
    end
    if ( bit.band( bitmap, DIR_BITMAP.NodeId ) == DIR_BITMAP.NodeId ) then
      pos, dir.NodeId = bin.unpack(">I", data, pos )
    end
    if ( bit.band( bitmap, DIR_BITMAP.OffspringCount ) == DIR_BITMAP.OffspringCount ) then
      pos, dir.OffspringCount = bin.unpack(">S", data, pos )
    end
    if ( bit.band( bitmap, DIR_BITMAP.OwnerId ) == DIR_BITMAP.OwnerId ) then
      pos, dir.OwnerId = bin.unpack(">I", data, pos )
    end
    if ( bit.band( bitmap, DIR_BITMAP.GroupId ) == DIR_BITMAP.GroupId ) then
      pos, dir.GroupId = bin.unpack(">I", data, pos )
    end
    if ( bit.band( bitmap, DIR_BITMAP.AccessRights ) == DIR_BITMAP.AccessRights ) then
      pos, dir.AccessRights = bin.unpack(">I", data, pos )
    end
    if ( bit.band( bitmap, DIR_BITMAP.UTF8Name ) == DIR_BITMAP.UTF8Name ) then
      local offset, p, name
      pos, offset = bin.unpack(">S", data, pos)
      p, dir.UTF8Name = bin.unpack("p", data, offset + pos - 1)
    end
    if ( bit.band( bitmap, DIR_BITMAP.UnixPrivileges ) == DIR_BITMAP.UnixPrivileges ) then
      local unixprivs = {}

      pos, unixprivs.uid, unixprivs.gid,
      unixprivs.permissions, unixprivs.ua_permissions = bin.unpack(">I>I>I>I", data, pos )
      dir.UnixPrivileges = unixprivs
    end
    return pos, dir
  end,

}




return _ENV;
