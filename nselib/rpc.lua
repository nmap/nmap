---
-- RPC Library supporting a very limited subset of operations.
--
-- The library works over both the UDP and TCP protocols. A subset of nfs and
-- mountd procedures are supported. The nfs and mountd programs support
-- versions 1 through 3. Authentication is supported using the NULL RPC
-- Authentication protocol
--
-- The library contains the following classes:
-- * <code>Comm </code>
-- ** Handles network connections.
-- ** Handles low-level packet sending, receiving, decoding and encoding.
-- ** Stores rpc programs info: socket, protocol, program name, id and version.
-- ** Used by Mount, NFS, RPC and Portmap.
-- * <code>Portmap</code>
-- ** Contains RPC constants.
-- ** Handles communication with the portmap RPC program.
-- * <code>Mount</code>
-- ** Handles communication with the mount RPC program.
-- * <code>NFS</code>
-- ** Handles communication with the nfs RPC program.
-- * <code>Helper</code>
-- ** Provides easy access to common RPC functions.
-- ** Implemented as a static class where most functions accept host and port parameters.
-- * <code>Util</code>
-- ** Mostly static conversion routines.
--
-- The portmapper dynamically allocates TCP/UDP ports to RPC programs. So in
-- in order to request a list of NFS shares from the server we need to:
-- * Make sure that we can talk to the portmapper on port 111 TCP or UDP.
-- * Query the portmapper for the ports allocated to the NFS program.
-- * Query the NFS program for a list of shares on the ports returned by the portmap program.
--
-- The Helper class contains functions that facilitate access to common
-- RPC program procedures through static class methods. Most functions accept
-- host and port parameters. As the Helper functions query the portmapper to
-- get the correct RPC program port, the port supplied to these functions
-- should be the rpcbind port 111/tcp or 111/udp.
--
-- The following sample code illustrates how scripts can use the <code>Helper</code> class
-- to interface the library:
--
-- <code>
-- -- retrieve a list of NFS export
-- status, mounts = rpc.Helper.ShowMounts( host, port )
--
-- -- iterate over every share
-- for _, mount in ipairs( mounts ) do
--
--    -- get the NFS attributes for the share
--    status, attribs = rpc.Helper.GetAttributes( host, port, mount.name )
--    .... process NFS attributes here ....
-- end
-- </code>
--
-- RPC transaction IDs (XID) are not properly implemented as a random ID is
-- generated for each client call. The library makes no attempt to verify
-- whether the returned XID is valid or not.
--
-- Therefore TCP is the preferred method of communication and the library
-- always attempts to connect to the TCP port of the RPC program first.
-- This behaviour can be overridden by setting the rpc.protocol argument.
-- The portmap service is always queried over the protocol specified in the
-- port information used to call the Helper function from the script.
--
-- When multiple versions exists for a specific RPC program the library
-- always attempts to connect using the highest available version.
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
--
-- @author Patrik Karlsson <patrik@cqure.net>
--
-- @args nfs.version number If set overrides the detected version of nfs
-- @args mount.version number If set overrides the detected version of mountd
-- @args rpc.protocol table If set overrides the preferred order in which
--       protocols are tested. (ie. "tcp", "udp")

local datafiles = require "datafiles"
local datetime = require "datetime"
local math = require "math"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tableaux = require "tableaux"
_ENV = stdnse.module("rpc", stdnse.seeall)

-- Version 0.3
--
-- Created 01/24/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 02/22/2010 - v0.2 - cleanup, revised the way TCP/UDP are handled fo
--                             encoding an decoding
-- Revised 03/13/2010 - v0.3 - re-worked library to be OO
-- Revised 04/18/2010 - v0.4 - Applied patch from Djalal Harouni with improved
--                             error checking and re-designed Comm class. see:
--                             http://seclists.org/nmap-dev/2010/q2/232
-- Revised 06/02/2010 - v0.5 - added code to the Util class to check for file
--                             types and permissions.
-- Revised 06/04/2010 - v0.6 - combined Portmap and RPC classes in the
--                             same Portmap class.
--


-- RPC args using the nmap.registry.args
RPC_args = {
  ["rpcbind"] = { proto = 'rpc.protocol' },
  ["nfs"] = { ver = 'nfs.version' },
  ["mountd"] = { ver = 'mount.version' },
}

-- Defines the order in which to try to connect to the RPC programs
-- TCP appears to be more stable than UDP in most cases, so try it first
local RPC_PROTOCOLS = (nmap.registry.args and nmap.registry.args[RPC_args['rpcbind'].proto] and
  type(nmap.registry.args[RPC_args['rpcbind'].proto]) == 'table') and
nmap.registry.args[RPC_args['rpcbind'].proto] or { "tcp", "udp" }

-- used to cache the contents of the rpc datafile
local RPC_PROGRAMS, RPC_NUMBERS

-- local mutex to synchronize I/O operations on nmap.registry[host.ip]['portmapper']
local mutex = nmap.mutex("rpc")

-- Supported protocol versions
RPC_version = {
  ["rpcbind"] = { min=2, max=4 },
  ["nfs"] = { min=1, max=3 },
  ["mountd"] = { min=1, max=3 },
}

-- Low-level communication class
Comm = {

  --- Creates a new rpc Comm object
  --
  -- @param program name string
  -- @param version number containing the program version to use
  -- @return a new Comm object
  new = function(self, program, version)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.program = program
    o.program_id = Util.ProgNameToNumber(program)
    o.checkprogver = true
    o:SetVersion(version)
    return o
  end,

  --- Connects to the remote program
  --
  -- @param host table
  -- @param port table
  -- @param timeout [optional] socket timeout in ms
  -- @return status boolean true on success, false on failure
  -- @return string containing error message (if status is false)
  Connect = function(self, host, port, timeout)
    local status, err, socket
    status, err = self:ChkProgram()
    if (not(status)) then
      return status, err
    end
    status, err = self:ChkVersion()
    if (not(status)) then
      return status, err
    end
    timeout = timeout or stdnse.get_timeout(host, 10000)
    local new_socket = function(...)
      local socket = nmap.new_socket(...)
      socket:set_timeout(timeout)
      return socket
    end
    if ( port.protocol == "tcp" ) then
      if nmap.is_privileged() then
        -- Try to bind to a reserved port
        for i = 1, 10, 1 do
          local resvport = math.random(512, 1023)
          socket = new_socket()
          status, err = socket:bind(nil, resvport)
          if status then
            status, err = socket:connect(host, port)
            if status or err == "TIMEOUT" then break end
            socket:close()
          end
        end
      else
        socket = new_socket()
        status, err = socket:connect(host, port)
      end
    else
      if nmap.is_privileged() then
        -- Try to bind to a reserved port
        for i = 1, 10, 1 do
          local resvport = math.random(512, 1023)
          socket = new_socket("udp")
          status, err = socket:bind(nil, resvport)
          if status then
            status, err = socket:connect(host, port)
            if status or err == "TIMEOUT" then break end
            socket:close()
          end
        end
      else
        socket = new_socket("udp")
        status, err = socket:connect(host, port)
      end
    end
    if (not(status)) then
      return status, string.format("%s connect error: %s",
        self.program, err)
    else
      self.socket = socket
      self.host = host
      self.ip = host.ip
      self.port = port.number
      self.proto = port.protocol
      return status, nil
    end
  end,

  --- Disconnects from the remote program
  --
  -- @return status boolean true on success, false on failure
  -- @return string containing error message (if status is false)
  Disconnect = function(self)
    local status, err = self.socket:close()
    if (not(status)) then
      return status, string.format("%s disconnect error: %s",
        self.program, err)
    end
    self.socket=nil
    return status, nil
  end,

  --- Checks if the rpc program is supported
  --
  -- @return status boolean true on success, false on failure
  -- @return string containing error message (if status is false)
  ChkProgram = function(self)
    if (not(RPC_version[self.program])) then
      return false, string.format("RPC library does not support: %s protocol",
        self.program)
    end
    return true, nil
  end,

  --- Checks if the rpc program version is supported
  --
  -- @return status boolean true on success, false on failure
  -- @return string containing error message (if status is false)
  ChkVersion = function(self)
    if not self.checkprogver then return true end
    if ( self.version > RPC_version[self.program].max or
        self.version < RPC_version[self.program].min ) then
      return false, string.format("RPC library does not support: %s version %d",
        self.program,self.version)
    end
    return true, nil
  end,

  --- Sets the rpc program version
  --
  -- @return status boolean true
  SetVersion = function(self, version)
    if self.checkprogver then
      if (RPC_version[self.program] and RPC_args[self.program] and
          nmap.registry.args and nmap.registry.args[RPC_args[self.program].ver]) then
        self.version = tonumber(nmap.registry.args[RPC_args[self.program].ver])
      elseif (not(self.version) and version) then
        self.version = version
      end
    else
      self.version = version
    end
    return true, nil
  end,

  --- Sets the verification of the specified program and version support
  -- before trying to connecting.
  -- @param check boolean to enable or disable checking of program and version support.
  SetCheckProgVer = function(self, check)
    self.checkprogver = check
  end,

  --- Sets the RPC program ID to use.
  -- @param progid number Program ID to set.
  SetProgID = function(self, progid)
    self.program_id = progid
  end,

  --- Checks if <code>data</code> contains enough bytes to read the <code>needed</code> amount
  --
  --  If it doesn't it attempts to read the remaining amount of bytes from the
  --  socket. Unlike <code>socket.receive_bytes</code>, reading less than
  --  <code>needed</code> is treated as an error.
  --
  -- @param data string containing the current buffer
  -- @param pos number containing the current offset into the buffer
  -- @param needed number containing the number of bytes needed to be available
  -- @return status success or failure
  -- @return data string containing the data passed to the function and the additional data appended to it or error message on failure
  GetAdditionalBytes = function( self, data, pos, needed )
    local toread =  needed - ( data:len() - pos + 1 )
    -- Do the loop ourselves instead of receive_bytes. Pathological case:
    -- * read less than needed and timeout
    -- * receive_bytes returns short but we don't know if it's eof or timeout
    -- * Try again. If it was timeout, we've doubled the timeout waiting for bytes that aren't coming.
    while toread > 0 do
      local status, tmp = self.socket:receive()
      if status then
        toread = toread - #tmp
        data = data .. tmp
      else
        return false, string.format("getAdditionalBytes read %d bytes before error: %s",
          needed - toread, tmp)
      end
    end
    return true, data
  end,

  --- Creates a RPC header
  --
  -- @param xid number. If no xid was provided, a random one will be used.
  -- @param procedure number containing the procedure to call. Defaults to <code>0</code>.
  -- @param auth table containing the authentication data to use. Defaults to NULL authentication.
  -- @return status boolean true on success, false on failure
  -- @return string of bytes on success, error message on failure
  CreateHeader = function( self, xid, procedure, auth )
    local RPC_VERSION = 2
    local packet
    -- Defaulting to NULL Authentication
    local auth = auth or {type = Portmap.AuthType.NULL}
    local xid = xid or math.random(1234567890)
    local procedure = procedure or 0

    packet = string.pack( ">I4 I4 I4 I4 I4 I4", xid, Portmap.MessageType.CALL, RPC_VERSION,
      self.program_id, self.version, procedure )
    if auth.type == Portmap.AuthType.NULL then
      packet = packet .. string.pack( ">I4 I4 I4 I4", 0, 0, 0, 0 )
    elseif auth.type == Portmap.AuthType.UNIX then
      packet = packet .. Util.marshall_int32(auth.type)
      local blob = (
        Util.marshall_int32(math.floor(nmap.clock())) --time
        .. Util.marshall_vopaque(auth.hostname or 'localhost')
        .. Util.marshall_int32(auth.uid or 0)
        .. Util.marshall_int32(auth.gid or 0)
        )
      if auth.gids then --len prefix gid list
        blob = blob .. Util.marshall_int32(#auth.gids)
        for _,gid in ipairs(auth.gids) do
          blob = blob .. Util.marshall_int32(gid)
        end
      else
        blob = blob .. Util.marshall_int32(0)
      end
      packet = (packet .. Util.marshall_vopaque(blob)
        .. string.pack( ">I4 I4", 0, 0 ) --AUTH_NULL verf
        )
    else
      return false, "Comm.CreateHeader: invalid authentication type specified"
    end
    return true, packet
  end,

  --- Decodes the RPC header (without the leading 4 bytes as received over TCP)
  --
  -- @param data string containing the buffer of bytes read so far
  -- @param pos number containing the current offset into data
  -- @return pos number containing the offset after the decoding
  -- @return header table containing <code>xid</code>, <code>type</code>, <code>state</code>,
  -- <code>verifier</code> and ( <code>accept_state</code> or <code>denied_state</code> )
  DecodeHeader = function( self, data, pos )
    local header = {}
    local status

    local HEADER_LEN = 20

    header.verifier = {}

    pos = pos or 1
    if ( data:len() - pos + 1 < HEADER_LEN ) then
      local tmp
      status, tmp = self:GetAdditionalBytes( data, pos, HEADER_LEN - ( data:len() - pos ) )
      if not status then
        stdnse.debug4("Comm.DecodeHeader: failed to call GetAdditionalBytes")
        return -1, nil
      end
      data = data .. tmp
    end

    header.xid, header.type, header.state, pos = string.unpack(">I4 I4 I4", data, pos)

    if ( header.state == Portmap.State.MSG_DENIED ) then
      header.denied_state, pos = string.unpack(">I4", data, pos )
      return pos, header
    end

    header.verifier.flavor, pos = string.unpack(">I4", data, pos)
    header.verifier.length, pos = string.unpack(">I4", data, pos)

    if header.verifier.length - 8 > 0 then
      status, data = self:GetAdditionalBytes( data, pos, header.verifier.length - 8 )
      if not status then
        stdnse.debug4("Comm.DecodeHeader: failed to call GetAdditionalBytes")
        return -1, nil
      end
      header.verifier.data, pos = string.unpack("c" .. header.verifier.length - 8, data, pos )
    end
    header.accept_state, pos = string.unpack(">I4", data, pos )

    return pos, header
  end,

  --- Reads the response from the socket
  --
  -- @return status true on success, false on failure
  -- @return data string containing the raw response or error message on failure
  ReceivePacket = function( self )
    local status

    if ( self.proto == "udp" ) then
      -- There's not much we can do in here to check if we received all data
      -- as the packet contains no length field. It's up to each decoding function
      -- to do appropriate checks
      return self.socket:receive_bytes(1)
    else
      local tmp, lastfragment, length
      local data, pos = "", 1

      -- Maximum number of allowed attempts to parse the received bytes. This
      -- prevents the code from looping endlessly on invalid content.
      local retries = 400

      repeat
        retries = retries - 1
        lastfragment = false
        status, data = self:GetAdditionalBytes( data, pos, 4 )
        if ( not(status) ) then
          return false, "Comm.ReceivePacket: failed to call GetAdditionalBytes"
        end

        tmp, pos = string.unpack(">I4", data, pos )
        length = tmp & 0x7FFFFFFF

        if (tmp & 0x80000000) == 0x80000000 then
          lastfragment = true
        end

        status, data = self:GetAdditionalBytes( data, pos, length )
        if ( not(status) ) then
          return false, "Comm.ReceivePacket: failed to call GetAdditionalBytes"
        end

        --
        -- When multiple packets are received they look like this
        -- H = Header data
        -- D = Data
        --
        -- We don't want the Header
        --
        -- HHHHDDDDDDDDDDDDDDHHHHDDDDDDDDDDD
        -- ^   ^             ^   ^
        -- 1   5             18  22
        --
        -- eg. we want
        -- data:sub(5, 18) and data:sub(22)
        --

        local bufcopy = data:sub(pos)

        if 1 ~= pos - 4 then
          bufcopy = data:sub(1, pos - 5) .. bufcopy
          pos = pos - 4
        else
          pos = 1
        end

        pos = pos + length
        data = bufcopy
      until (lastfragment == true) or (retries == 0)

      if retries == 0 then
        return false, "Aborted after too many retries"
      end
      return true, data
    end
  end,

  --- Encodes a RPC packet
  --
  -- @param xid number containing the transaction ID
  -- @param proc number containing the procedure to call
  -- @param auth table containing authentication information
  -- @param data string containing the packet data
  -- @return packet string containing the encoded packet data
  EncodePacket = function( self, xid, proc, auth, data )
    local status, packet = self:CreateHeader( xid, proc, auth )
    local len
    if ( not(status) ) then
      return
    end

    packet = packet .. ( data or "" )
    if ( self.proto == "udp") then
      return packet
    else
      -- set the high bit as this is our last fragment
      len = 0x80000000 + packet:len()
      return string.pack(">I4", len) .. packet
    end
  end,

  SendPacket = function( self, packet )
    if ( self.host and self.port ) then
      return self.socket:sendto(self.host, self.port, packet)
    else
      return self.socket:send( packet )
    end
  end,

  GetSocketInfo = function(self)
    return self.socket:get_info()
  end,

}

--- Portmap (rpcbind) class
Portmap =
{
  PROTOCOLS = {
    ['tcp'] = 6,
    ['udp'] = 17,
  },

  -- TODO: add more Authentication Protocols
  AuthType =
  {
    NULL = 0,
    UNIX = 1,
  },

  -- TODO: complete Authentication stats and error messages
  AuthState =
  {
    AUTH_OK = 0,
    AUTH_BADCRED = 1,
    AUTH_REJECTEDCRED = 2,
    AUTH_BADVERF = 3,
    AUTH_REJECTEDVERF = 4,
    AUTH_TOOWEAK = 5,
    AUTH_INVALIDRESP = 6,
    AUTH_FAILED = 7,
  },

  AuthMsg =
  {
    [0] = "Success.",
    [1] = "bad credential (seal broken).",
    [2] = "client must begin new session.",
    [3] = "bad verifier (seal broken).",
    [4] = "verifier expired or replayed.",
    [5] = "rejected for security reasons.",
    [6] = "bogus response verifier.",
    [7] = "reason unknown.",
  },

  MessageType =
  {
    CALL = 0,
    REPLY = 1
  },

  Procedure =
  {
    [2] =
    {
      GETPORT = 3,
      DUMP = 4,
      CALLIT = 5,
    },

    [3] =
    {
      DUMP = 4,
    },

    [4] =
    {
      DUMP = 4,
    },

  },

  State =
  {
    MSG_ACCEPTED = 0,
    MSG_DENIED = 1,
  },

  AcceptState =
  {
    SUCCESS = 0,
    PROG_UNAVAIL = 1,
    PROG_MISMATCH = 2,
    PROC_UNAVAIL = 3,
    GARBAGE_ARGS = 4,
    SYSTEM_ERR = 5,
  },

  AcceptMsg =
  {
    [0] = "RPC executed successfully.",
    [1] = "remote hasn't exported program.",
    [2] = "remote can't support version.",
    [3] = "program can't support procedure.",
    [4] = "procedure can't decode params.",
    [5] = "errors like memory allocation failure.",
  },

  RejectState =
  {
    RPC_MISMATCH = 0,
    AUTH_ERROR = 1,
  },

  RejectMsg =
  {
    [0] = "RPC version number != 2.",
    [1] = "remote can't authenticate caller.",
  },

  new = function(self,o)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Dumps a list of RCP programs from the portmapper
  --
  -- @param comm object handles rpc program information and
  --  low-level packet manipulation
  -- @return status boolean true on success, false on failure
  -- @return result table containing RPC program information or error message
  --         on failure. The table has the following format:
  --
  -- <code>
  -- table[program_id][protocol]["port"] = <port number>
  -- table[program_id][protocol]["version"] = <table of versions>
  -- table[program_id][protocol]["addr"] = <IP address, for RPCv3 and higher>
  -- </code>
  --
  -- Where
  --  o program_id is the number associated with the program
  --  o protocol is one of "tcp", "udp", "tcp6", or "udp6", or another netid
  --    reported by the system.
  --
  Dump = function(self, comm)
    local status, data, packet, response, pos, header
    local program_table = setmetatable({}, { __mode = 'v' })

    packet = comm:EncodePacket( nil, Portmap.Procedure[comm.version].DUMP,
      { type=Portmap.AuthType.NULL }, data )
    if (not(comm:SendPacket(packet))) then
      return false, "Portmap.Dump: Failed to send data"
    end
    status, data = comm:ReceivePacket()
    if ( not(status) ) then
      return false, "Portmap.Dump: Failed to read data from socket"
    end

    pos, header = comm:DecodeHeader( data, 1 )
    if ( not(header) ) then
      return false, "Portmap.Dump: Failed to decode RPC header"
    end

    if header.type ~= Portmap.MessageType.REPLY then
      return false, "Portmap.Dump: Packet was not a reply"
    end

    if header.state ~= Portmap.State.MSG_ACCEPTED then
      if (Portmap.RejectMsg[header.denied_state]) then
        return false,
        string.format("Portmap.Dump: RPC call failed: %s",
          Portmap.RejectMsg[header.denied_state])
      else
        return false,
        string.format("Portmap.Dump: RPC call failed: code %d",
          header.state)
      end
    end

    if header.accept_state ~= Portmap.AcceptState.SUCCESS then
      if (Portmap.AcceptMsg[header.accept_state]) then
        return false,
        string.format("Portmap.Dump: RPC accepted state: %s",
          Portmap.AcceptMsg[header.accept_state])
      else
        return false,
        string.format("Portmap.Dump: RPC accepted state code %d",
          header.accept_state)
      end
    end

    while true do
      local vfollows
      local program, version, protocol, port

      status, data = comm:GetAdditionalBytes( data, pos, 4 )
      if ( not(status) ) then
        return false, "Portmap.Dump: Failed to call GetAdditionalBytes"
      end
      vfollows, pos = string.unpack(">I4", data, pos)
      if ( vfollows == 0 ) then
        break
      end

      program, version, pos = string.unpack(">I4 I4", data, pos)
      local addr, owner
      if comm.version > 2 then
        local len
        len, pos = string.unpack(">I4", data, pos)
        pos, protocol = Util.unmarshall_vopaque(len, data, pos)
        -- workaround for NetApp 5.0: trim trailing null bytes
        protocol = protocol:match("[^\0]*")
        len, pos = string.unpack(">I4", data, pos)
        pos, addr = Util.unmarshall_vopaque(len, data, pos)
        len, pos = string.unpack(">I4", data, pos)
        pos, owner = Util.unmarshall_vopaque(len, data, pos)
        if protocol:match("^[tu][cd]p6?$") then
            -- RFC 5665
            local upper, lower
            addr, upper, lower = addr:match("^(.-)%.(%d+)%.(%d+)$")
            if addr then
              port = tonumber(upper) * 0x100 + tonumber(lower)
            end
        end
      else
        protocol, port, pos = string.unpack(">I4 I4", data, pos)
        if ( protocol == Portmap.PROTOCOLS.tcp ) then
          protocol = "tcp"
        elseif ( protocol == Portmap.PROTOCOLS.udp ) then
          protocol = "udp"
        end
      end

      program_table[program] = program_table[program] or {}
      program_table[program][protocol] = program_table[program][protocol] or {}
      program_table[program][protocol]["port"] = port
      program_table[program][protocol]["addr"] = addr
      program_table[program][protocol]["owner"] = owner
      program_table[program][protocol]["version"] = program_table[program][protocol]["version"] or {}
      table.insert( program_table[program][protocol]["version"], version )
      -- parts of the code rely on versions being in order
      -- this way the highest version can be chosen by choosing the last element
      table.sort( program_table[program][protocol]["version"] )
    end

    nmap.registry[comm.ip]['portmapper'] = program_table
    return true, nmap.registry[comm.ip]['portmapper']
  end,

  --- Calls the portmap callit call and returns the raw response
  --
  -- @param comm object handles rpc program information and
  --  low-level packet manipulation
  -- @param program string name of the program
  -- @param protocol string containing either "tcp" or "udp"
  -- @param version number containing the version of the queried program
  -- @return status true on success, false on failure
  -- @return data string containing the raw response
  Callit = function( self, comm, program, protocol, version )
    if ( not( Portmap.PROTOCOLS[protocol] ) ) then
      return false, ("Portmap.Callit: Protocol %s not supported"):format(protocol)
    end

    if ( Util.ProgNameToNumber(program) == nil ) then
      return false, ("Portmap.Callit: Unknown program name: %s"):format(program)
    end

    local data = string.pack(">I4 I4 I4 I4", Util.ProgNameToNumber(program), version, 0, 0 )
    local packet = comm:EncodePacket(nil, Portmap.Procedure[comm.version].CALLIT,
      { type=Portmap.AuthType.NULL }, data )

    if (not(comm:SendPacket(packet))) then
      return false, "Portmap.Callit: Failed to send data"
    end

    data = ""
    local status, data = comm:ReceivePacket()
    if ( not(status) ) then
      return false, "Portmap.Callit: Failed to read data from socket"
    end

    local pos, header = comm:DecodeHeader( data, 1 )
    if ( not(header) ) then
      return false, "Portmap.Callit: Failed to decode RPC header"
    end

    if header.type ~= Portmap.MessageType.REPLY then
      return false, "Portmap.Callit: Packet was not a reply"
    end

    return true, data
  end,


  --- Queries the portmapper for the port of the selected program,
  --  protocol and version
  --
  -- @param comm object handles rpc program information and
  --  low-level packet manipulation
  -- @param program string name of the program
  -- @param protocol string containing either "tcp" or "udp"
  -- @param version number containing the version of the queried program
  -- @return number containing the port number
  GetPort = function( self, comm, program, protocol, version )
    local status, data, response, header, pos, packet
    local xid

    if ( not( Portmap.PROTOCOLS[protocol] ) ) then
      return false, ("Portmap.GetPort: Protocol %s not supported"):format(protocol)
    end

    if ( Util.ProgNameToNumber(program) == nil ) then
      return false, ("Portmap.GetPort: Unknown program name: %s"):format(program)
    end

    data = string.pack(">I4 I4 I4 I4", Util.ProgNameToNumber(program), version,
      Portmap.PROTOCOLS[protocol], 0 )
    packet = comm:EncodePacket(xid, Portmap.Procedure[comm.version].GETPORT,
      { type=Portmap.AuthType.NULL }, data )

    if (not(comm:SendPacket(packet))) then
      return false, "Portmap.GetPort: Failed to send data"
    end

    data = ""
    status, data = comm:ReceivePacket()
    if ( not(status) ) then
      return false, "Portmap.GetPort: Failed to read data from socket"
    end

    pos, header = comm:DecodeHeader( data, 1 )

    if ( not(header) ) then
      return false, "Portmap.GetPort: Failed to decode RPC header"
    end

    if header.type ~= Portmap.MessageType.REPLY then
      return false, "Portmap.GetPort: Packet was not a reply"
    end

    if header.state ~= Portmap.State.MSG_ACCEPTED then
      if (Portmap.RejectMsg[header.denied_state]) then
        return false, string.format("Portmap.GetPort: RPC call failed: %s",
          Portmap.RejectMsg[header.denied_state])
      else
        return false,
        string.format("Portmap.GetPort: RPC call failed: code %d",
          header.state)
      end
    end

    if header.accept_state ~= Portmap.AcceptState.SUCCESS then
      if (Portmap.AcceptMsg[header.accept_state]) then
        return false, string.format("Portmap.GetPort: RPC accepted state: %s",
          Portmap.AcceptMsg[header.accept_state])
      else
        return false, string.format("Portmap.GetPort: RPC accepted state code %d",
          header.accept_state)
      end
    end

    status, data = comm:GetAdditionalBytes( data, pos, 4 )
    if ( not(status) ) then
      return false, "Portmap.GetPort: Failed to call GetAdditionalBytes"
    end

    return true, string.unpack(">I4", data, pos)
  end,

}

--- Mount class handling communication with the mountd program
--
-- Currently supports versions 1 through 3
-- Can be called either directly or through the static Helper class
--
Mount = {

  StatMsg = {
    [1] = "Not owner.",
    [2] = "No such file or directory.",
    [5] = "I/O error.",
    [13] = "Permission denied.",
    [20] = "Not a directory.",
    [22] = "Invalid argument.",
    [63] = "Filename too long.",
    [10004] = "Operation not supported.",
    [10006] = "A failure on the server.",
  },

  StatCode = {
    MNT_OK = 0,
    MNTERR_PERM = 1,
    MNTERR_NOENT = 2,
    MNTERR_IO = 5,
    MNTERR_ACCES = 13,
    MNTERR_NOTDIR = 20,
    MNTERR_INVAL = 22,
    MNTERR_NAMETOOLONG = 63,
    MNTERR_NOTSUPP = 10004,
    MNTERR_SERVERFAULT = 10006,
  },

  Procedure =
  {
    MOUNT = 1,
    DUMP = 2,
    UMNT = 3,
    UMNTALL = 4,
    EXPORT = 5,
  },

  new = function(self,o)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Requests a list of NFS export from the remote server
  --
  -- @param comm object handles rpc program information and
  --  low-level packet manipulation
  -- @return status success or failure
  -- @return entries table containing a list of share names (strings)
  Export = function(self, comm)
    local msg_type = 0
    local packet
    local pos = 1
    local header = {}
    local entries = {}
    local data = ""
    local status

    if comm.proto ~= "tcp" and comm.proto ~= "udp" then
      return false, "Mount.Export: Protocol should be either udp or tcp"
    end

    packet = comm:EncodePacket(nil, Mount.Procedure.EXPORT,
      { type=Portmap.AuthType.UNIX }, nil )
    if (not(comm:SendPacket( packet ))) then
      return false, "Mount.Export: Failed to send data"
    end

    status, data = comm:ReceivePacket()
    if ( not(status) ) then
      return false, "Mount.Export: Failed to read data from socket"
    end

    -- make sure we have at least 24 bytes to unpack the header
    status, data = comm:GetAdditionalBytes( data, pos, 24 )
    if (not(status)) then
      return false, "Mount.Export: Failed to call GetAdditionalBytes"
    end
    pos, header = comm:DecodeHeader( data, pos )
    if not header then
      return false, "Mount.Export: Failed to decode header"
    end

    if header.type ~= Portmap.MessageType.REPLY then
      return false, "Mount.Export: packet was not a reply"
    end

    if header.state ~= Portmap.State.MSG_ACCEPTED then
      if (Portmap.RejectMsg[header.denied_state]) then
        return false, string.format("Mount.Export: RPC call failed: %s",
          Portmap.RejectMsg[header.denied_state])
      else
        return false, string.format("Mount.Export: RPC call failed: code %d",
          header.state)
      end
    end

    if header.accept_state ~= Portmap.AcceptState.SUCCESS then
      if (Portmap.AcceptMsg[header.accept_state]) then
        return false, string.format("Mount.Export: RPC accepted state: %s",
          Portmap.AcceptMsg[header.accept_state])
      else
        return false, string.format("Mount.Export: RPC accepted state code %d",
          header.accept_state)
      end
    end

    --  Decode directory entries
    --
    --  [entry]
    --     4 bytes   - value follows (1 if more data, 0 if not)
    --     [Directory]
    --        4 bytes   - value len
    --        len bytes - directory name
    --        ? bytes   - fill bytes (see calcFillByte)
    --     [Groups]
    --        4 bytes  - value follows (1 if more data, 0 if not)
    --         [Group] (1 or more)
    --            4 bytes   - group len
    --            len bytes - group value
    --            ? bytes   - fill bytes (see calcFillByte)
    while true do
      -- make sure we have atleast 4 more bytes to check for value follows
      status, data = comm:GetAdditionalBytes( data, pos, 4 )
      if (not(status)) then
        return false, "Mount.Export: Failed to call GetAdditionalBytes"
      end

      local data_follows
      pos, data_follows = Util.unmarshall_uint32(data, pos)

      if data_follows ~= 1 then
        break
      end

      --- Export list entry starts here
      local entry = {}
      local len

      -- make sure we have atleast 4 more bytes to get the length
      status, data = comm:GetAdditionalBytes( data, pos, 4 )
      if (not(status)) then
        return false, "Mount.Export: Failed to call GetAdditionalBytes"
      end
      pos, len = Util.unmarshall_uint32(data, pos)

      status, data = comm:GetAdditionalBytes( data, pos, len )
      if (not(status)) then
        return false, "Mount.Export: Failed to call GetAdditionalBytes"
      end
      pos, entry.name = Util.unmarshall_vopaque(len, data, pos)

      -- decode groups
      while true do
        local group

        status, data = comm:GetAdditionalBytes( data, pos, 4 )
        if (not(status)) then
          return false, "Mount.Export: Failed to call GetAdditionalBytes"
        end
        pos, data_follows = Util.unmarshall_uint32(data, pos)

        if data_follows ~= 1 then
          break
        end

        status, data = comm:GetAdditionalBytes( data, pos, 4 )
        if (not(status)) then
          return false, "Mount.Export: Failed to call GetAdditionalBytes"
        end

        pos, len = Util.unmarshall_uint32(data, pos)
        status, data = comm:GetAdditionalBytes( data, pos, len )
        if (not(status)) then
          return false, "Mount.Export: Failed to call GetAdditionalBytes"
        end
        pos, group = Util.unmarshall_vopaque(len, data, pos)
        table.insert( entry, group )
      end
      table.insert(entries, entry)
    end
    return true, entries
  end,

  --- Attempts to mount a remote export in order to get the filehandle
  --
  -- @param comm object handles rpc program information and
  --  low-level packet manipulation
  -- @param path string containing the path to mount
  -- @return status success or failure
  -- @return fhandle string containing the filehandle of the remote export
  Mount = function(self, comm, path)
    local packet, mount_status
    local status, len

    local data = Util.marshall_vopaque(path)

    packet = comm:EncodePacket( nil, Mount.Procedure.MOUNT, { type=Portmap.AuthType.UNIX }, data )
    if (not(comm:SendPacket(packet))) then
      return false, "Mount: Failed to send data"
    end

    status, data = comm:ReceivePacket()
    if ( not(status) ) then
      return false, "Mount: Failed to read data from socket"
    end

    local pos, header = comm:DecodeHeader(data)
    if not header then
      return false, "Mount: Failed to decode header"
    end

    if header.type ~= Portmap.MessageType.REPLY then
      return false, "Mount: Packet was not a reply"
    end

    if header.state ~= Portmap.State.MSG_ACCEPTED then
      if (Portmap.RejectMsg[header.denied_state]) then
        return false, string.format("Mount: RPC call failed: %s",
          Portmap.RejectMsg[header.denied_state])
      else
        return false, string.format("Mount: RPC call failed: code %d",
          header.state)
      end
    end

    if header.accept_state ~= Portmap.AcceptState.SUCCESS then
      if (Portmap.AcceptMsg[header.accept_state]) then
        return false, string.format("Mount (%s): RPC accepted state: %s",
          path, Portmap.AcceptMsg[header.accept_state])
      else
        return false, string.format("Mount (%s): RPC accepted state code %d",
          path, header.accept_state)
      end
    end

    status, data = comm:GetAdditionalBytes( data, pos, 4 )
    if (not(status)) then
      return false, "Mount: Failed to call GetAdditionalBytes"
    end
    pos, mount_status = Util.unmarshall_uint32(data, pos)

    if (mount_status ~= Mount.StatCode.MNT_OK) then
      if (Mount.StatMsg[mount_status]) then
        return false, string.format("Mount failed: %s",Mount.StatMsg[mount_status])
      else
        return false, string.format("Mount failed: code %d", mount_status)
      end
    end

    local fhandle
    if ( comm.version == 3 ) then
      status, data = comm:GetAdditionalBytes( data, pos, 4 )
      if (not(status)) then
        return false, "Mount: Failed to call GetAdditionalBytes"
      end
      len = string.unpack(">I4", data, pos)
      status, data = comm:GetAdditionalBytes( data, pos, len + 4 )
      if (not(status)) then
        return false, "Mount: Failed to call GetAdditionalBytes"
      end
      fhandle, pos = string.unpack( "c" .. len + 4, data, pos )
    elseif ( comm.version < 3 ) then
      status, data = comm:GetAdditionalBytes( data, pos, 32 )
      if (not(status)) then
        return false, "Mount: Failed to call GetAdditionalBytes"
      end
      fhandle, pos = string.unpack( "c32", data, pos )
    else
      return false, "Mount failed"
    end

    return true, fhandle
  end,

  --- Attempts to unmount a remote export in order to get the filehandle
  --
  -- @param comm object handles rpc program information and
  --  low-level packet manipulation
  -- @param path string containing the path to mount
  -- @return status success or failure
  -- @return error string containing error if status is false
  Unmount = function(self, comm, path)
    local packet, status
    local _, pos, data, header, fhandle = "", 1, "", "", {}

    data = Util.marshall_vopaque(path)

    packet = comm:EncodePacket( nil, Mount.Procedure.UMNT, { type=Portmap.AuthType.UNIX }, data )
    if (not(comm:SendPacket(packet))) then
      return false, "Unmount: Failed to send data"
    end

    status, data = comm:ReceivePacket( )
    if ( not(status) ) then
      return false, "Unmount: Failed to read data from socket"
    end

    pos, header = comm:DecodeHeader( data, pos )
    if not header then
      return false, "Unmount: Failed to decode header"
    end

    if header.type ~= Portmap.MessageType.REPLY then
      return false, "Unmount: Packet was not a reply"
    end

    if header.state ~= Portmap.State.MSG_ACCEPTED then
      if (Portmap.RejectMsg[header.denied_state]) then
        return false, string.format("Unmount: RPC call failed: %s",
          Portmap.RejectMsg[header.denied_state])
      else
        return false, string.format("Unmount: RPC call failed: code %d",
          header.state)
      end
    end

    if header.accept_state ~= Portmap.AcceptState.SUCCESS then
      if (Portmap.AcceptMsg[header.accept_state]) then
        return false, string.format("Unmount (%s): RPC accepted state: %s",
          path, Portmap.AcceptMsg[header.accept_state])
      else
        return false, string.format("Unmount (%s): RPC accepted state code %d",
          path, header.accept_state)
      end
    end

    return true, ""
  end,
}

--- NFS class handling communication with the nfsd program
--
-- Currently supports versions 1 through 3
-- Can be called either directly or through the static Helper class
--
NFS = {

  -- NFS error msg v2 and v3
  StatMsg = {
    [1] = "Not owner.",
    [2] = "No such file or directory.",
    [5] = "I/O error.",
    [6] = "I/O error. No such device or address.",
    [13] = "Permission denied.",
    [17] = "File exists.",
    [18] = "Attempt to do a cross-device hard link.",
    [19] = "No such device.",
    [20] = "Not a directory.",
    [21] = "Is a directory.",
    [22] = "Invalid argument or unsupported argument for an operation.",
    [27] = "File too large.",
    [28] = "No space left on device.",
    [30] = "Read-only file system.",
    [31] = "Too many hard links.",
    [63] = "The filename in an operation was too long.",
    [66] = "An attempt was made to remove a directory that was not empty.",
    [69] = "Resource (quota) hard limit exceeded.",
    [70] = "Invalid file handle.",
    [71] = "Too many levels of remote in path.",
    [99] = "The server's write cache used in the \"WRITECACHE\" call got flushed to disk.",
    [10001] = "Illegal NFS file handle.",
    [10002] = "Update synchronization mismatch was detected during a SETATTR operation.",
    [10003] = "READDIR or READDIRPLUS cookie is stale.",
    [10004] = "Operation is not supported.",
    [10005] = "Buffer or request is too small.",
    [10006] = "An error occurred on the server which does not map to any of the legal NFS version 3 protocol error values.",
    [10007] = "An attempt was made to create an object of a type not supported by the server.",
    [10008] = "The server initiated the request, but was not able to complete it in a timely fashion.",
  },

  StatCode = {
    -- NFS Version 1
    [1] = {
      NFS_OK        = 0,
      NFSERR_PERM   = 1,
      NFSERR_NOENT  = 2,
      NFSERR_IO     = 5,
      NFSERR_NXIO   = 6,
      NFSERR_ACCES  = 13,
      NFSERR_EXIST  = 17,
      NFSERR_NODEV  = 19,
      NFSERR_NOTDIR = 20,
      NFSERR_ISDIR  = 21,
      NFSERR_FBIG   = 27,
      NFSERR_NOSPC  = 28,
      NFSERR_ROFS   = 30,
      NFSERR_NAMETOOLONG = 63,
      NFSERR_NOTEMPTY = 66,
      NFSERR_DQUOT  = 69,
      NFSERR_STALE  = 70,
      NFSERR_WFLUSH = 99,
    },

    -- NFS Version 2
    [2] = {
      NFS_OK        = 0,
      NFSERR_PERM   = 1,
      NFSERR_NOENT  = 2,
      NFSERR_IO     = 5,
      NFSERR_NXIO   = 6,
      NFSERR_ACCES  = 13,
      NFSERR_EXIST  = 17,
      NFSERR_NODEV  = 19,
      NFSERR_NOTDIR = 20,
      NFSERR_ISDIR  = 21,
      NFSERR_FBIG   = 27,
      NFSERR_NOSPC  = 28,
      NFSERR_ROFS   = 30,
      NFSERR_NAMETOOLONG = 63,
      NFSERR_NOTEMPTY = 66,
      NFSERR_DQUOT  = 69,
      NFSERR_STALE  = 70,
      NFSERR_WFLUSH = 99,
    },

    -- NFS Version 3
    [3] = {
      NFS_OK          = 0,
      NFSERR_PERM     = 1,
      NFSERR_NOENT    = 2,
      NFSERR_IO       = 5,
      NFSERR_NXIO     = 6,
      NFSERR_ACCES    = 13,
      NFSERR_EXIST    = 17,
      NFSERR_XDEV     = 18,
      NFSERR_NODEV    = 19,
      NFSERR_NOTDIR   = 20,
      NFSERR_ISDIR    = 21,
      NFSERR_INVAL    = 22,
      NFSERR_FBIG     = 27,
      NFSERR_NOSPC    = 28,
      NFSERR_ROFS     = 30,
      NFSERR_MLINK    = 31,
      NFSERR_NAMETOOLONG = 63,
      NFSERR_NOTEMPTY = 66,
      NFSERR_DQUOT    = 69,
      NFSERR_STALE    = 70,
      NFSERR_REMOTE   = 71,
      NFSERR_BADHANDLE = 10001,
      NFSERR_NOT_SYNC = 10002,
      NFSERR_BAD_COOKIE = 10003,
      NFSERR_NOTSUPP = 10004,
      NFSERR_TOOSMALL = 10005,
      NFSERR_SERVERFAULT = 10006,
      NFSERR_BADTYPE = 10007,
      NFSERR_JUKEBOX = 10008,
    },
  },

  -- Unfortunately the NFS procedure numbers differ in between versions
  Procedure =
  {
    -- NFS Version 1
    [1] =
    {
      GETATTR = 1,
      ROOT = 3,
      LOOKUP = 4,
      EXPORT = 5,
      READDIR = 16,
      STATFS = 17,
    },

    -- NFS Version 2
    [2] =
    {
      GETATTR = 1,
      ROOT = 3,
      LOOKUP = 4,
      EXPORT = 5,
      READDIR = 16,
      STATFS = 17,
    },

    -- NFS Version 3
    [3] =
    {
      GETATTR = 1,
      SETATTR = 2,
      LOOKUP = 3,
      ACCESS = 4,
      EXPORT = 5,
      READDIR = 16,
      READDIRPLUS = 17,
      FSSTAT = 18,
      FSINFO = 19,
      PATHCONF = 20,
      COMMIT = 21,
    },
  },

  -- ACCESS values used to check the bit mask.
  AccessBits =
  {
    [3] =
    {
      ACCESS_READ    = 0x0001,
      ACCESS_LOOKUP  = 0x0002,
      ACCESS_MODIFY  = 0x0004,
      ACCESS_EXTEND  = 0x0008,
      ACCESS_DELETE  = 0x0010,
      ACCESS_EXECUTE = 0x0020,
    },
  },

  FSinfoBits =
  {
    [3] =
    {
      FSF_LINK        = 0x0001,
      FSF_SYMLINK     = 0x0002,
      FSF_HOMOGENEOUS = 0x0008,
      FSF_CANSETTIME  = 0x0010,
    },
  },

  new = function(self,o)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  CheckStat = function (self, procedurename, version, status)
    if (status ~= NFS.StatCode[version].NFS_OK) then
      if (NFS.StatMsg[status]) then
        stdnse.debug4(
          string.format("%s failed: %s", procedurename, NFS.StatMsg[status]))
      else
        stdnse.debug4(
          string.format("%s failed: code %d", procedurename, status))
      end

      return false
    end

    return true
  end,

  AccessRead = function (self, mask, version)
    return (mask & NFS.AccessBits[version].ACCESS_READ)
  end,

  AccessLookup = function (self, mask, version)
    return (mask & NFS.AccessBits[version].ACCESS_LOOKUP)
  end,

  AccessModify = function (self, mask, version)
    return (mask & NFS.AccessBits[version].ACCESS_MODIFY)
  end,

  AccessExtend = function (self, mask, version)
    return (mask & NFS.AccessBits[version].ACCESS_EXTEND)
  end,

  AccessDelete = function (self, mask, version)
    return (mask & NFS.AccessBits[version].ACCESS_DELETE)
  end,

  AccessExecute = function (self, mask, version)
    return (mask & NFS.AccessBits[version].ACCESS_EXECUTE)
  end,

  FSinfoLink = function(self, mask, version)
    return (mask & NFS.FSinfoBits[version].FSF_LINK)
  end,

  FSinfoSymlink = function(self, mask, version)
    return (mask & NFS.FSinfoBits[version].FSF_SYMLINK)
  end,

  FSinfoHomogeneous = function(self, mask, version)
    return (mask & NFS.FSinfoBits[version].FSF_HOMOGENEOUS)
  end,

  FSinfoCansettime = function(self, mask, version)
    return (mask & NFS.FSinfoBits[version].FSF_CANSETTIME)
  end,

  --- Decodes the READDIR section of a NFS ReadDir response
  --
  -- @param comm object handles rpc program information and
  --  low-level packet manipulation
  -- @param data string containing the buffer of bytes read so far
  -- @param pos number containing the current offset into data
  -- @return pos number containing the offset after the decoding
  -- @return entries table containing two table entries <code>attributes</code>
  --         and <code>entries</code>. The attributes entry is only present when
  --         using NFS version 3. The <code>entries</code> field contain one
  --         table for each file/directory entry. It has the following fields
  --         <code>file_id</code>, <code>name</code> and <code>cookie</code>
  --
  ReadDirDecode = function( self, comm, data, pos )
    local response = {}
    local value_follows
    local status, _

    status, data = comm:GetAdditionalBytes( data, pos, 4 )
    if (not(status)) then
      stdnse.debug4("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
      return -1, nil
    end

    pos, status = Util.unmarshall_uint32(data, pos)
    if (not self:CheckStat("READDIR", comm.version, status)) then
      return -1, nil
    end

    if ( 3 == comm.version ) then
      local attrib = {}
      response.attributes = {}
      status, data = comm:GetAdditionalBytes( data, pos, 4 )
      if (not(status)) then
        stdnse.debug4("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end

      pos, value_follows = Util.unmarshall_uint32(data, pos)
      if value_follows == 0 then
        return -1, nil
      end
      status, data = comm:GetAdditionalBytes( data, pos, 84 )
      if (not(status)) then
        stdnse.debug4("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end
      pos, attrib = Util.unmarshall_nfsattr(data, pos, comm.version)
      table.insert(response.attributes, attrib)
      -- opaque data
      status, data = comm:GetAdditionalBytes( data, pos, 8 )
      if (not(status)) then
        stdnse.debug4("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end
      _, pos = string.unpack(">I8", data, pos)
    end

    response.entries = {}
    while true do
      local entry = {}
      status, data = comm:GetAdditionalBytes( data, pos, 4 )
      if (not(status)) then
        stdnse.debug4("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end

      pos, value_follows = Util.unmarshall_uint32(data, pos)
      if ( value_follows == 0 ) then
        break
      end

      if ( 3 == comm.version ) then
        status, data = comm:GetAdditionalBytes( data, pos, 8 )
        if (not(status)) then
          stdnse.debug4("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
          return -1, nil
        end
        pos, entry.fileid = Util.unmarshall_uint64(data, pos )
      else
        status, data = comm:GetAdditionalBytes( data, pos, 4 )
        if (not(status)) then
          stdnse.debug4("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
          return -1, nil
        end
        pos, entry.fileid = Util.unmarshall_uint32(data, pos)
      end

      status, data = comm:GetAdditionalBytes( data, pos, 4 )
      if (not(status)) then
        stdnse.debug4("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end

      pos, entry.length = Util.unmarshall_uint32(data, pos)
      status, data = comm:GetAdditionalBytes( data, pos, entry.length )
      if (not(status)) then
        stdnse.debug4("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end

      pos, entry.name = Util.unmarshall_vopaque(entry.length, data, pos)
      if ( 3 == comm.version ) then
        status, data = comm:GetAdditionalBytes( data, pos, 8 )
        if (not(status)) then
          stdnse.debug4("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
          return -1, nil
        end
        pos, entry.cookie = Util.unmarshall_uint64(data, pos)
      else
        status, data = comm:GetAdditionalBytes(  data, pos, 4 )
        if (not(status)) then
          stdnse.debug4("NFS.ReadDirDecode: Failed to call GetAdditionalBytes")
          return -1, nil
        end
        pos, entry.cookie = Util.unmarshall_uint32(data, pos)
      end
      table.insert( response.entries, entry )
    end
    return pos, response
  end,

  --- Reads the contents inside a NFS directory
  --
  -- @param comm object handles rpc program information and
  --  low-level packet manipulation
  -- @param file_handle string containing the filehandle to query
  -- @return status true on success, false on failure
  -- @return table of file table entries as described in <code>decodeReadDir</code>
  ReadDir = function( self, comm, file_handle )
    local status, packet
    local cookie, count = 0, 8192
    local pos, data, _ = 1, "", ""
    local header, response = {}, {}

    if ( not(file_handle) ) then
      return false, "ReadDir: No filehandle received"
    end

    if ( comm.version == 3 ) then
      local opaque_data = 0
      data = file_handle .. string.pack(">I8 I8 I4", cookie, opaque_data, count)
    else
      data = file_handle .. string.pack(">I4 I4", cookie, count)
    end
    packet = comm:EncodePacket( nil, NFS.Procedure[comm.version].READDIR,
      { type=Portmap.AuthType.UNIX }, data )
    if(not(comm:SendPacket( packet ))) then
      return false, "ReadDir: Failed to send data"
    end

    status, data = comm:ReceivePacket()
    if ( not(status) ) then
      return false, "ReadDir: Failed to read data from socket"
    end

    pos, header = comm:DecodeHeader( data, pos )
    if not header then
      return false, "ReadDir: Failed to decode header"
    end
    pos, response = self:ReadDirDecode( comm, data, pos )
    if (not(response)) then
      return false, "ReadDir: Failed to decode the READDIR section"
    end
    return true, response
  end,

  LookUpDecode = function(self, comm, data, pos)
    local lookup, status, len, value_follows, _ = {}

    status, data = comm:GetAdditionalBytes(data, pos, 4)
    if not status then
      stdnse.debug4("NFS.LookUpDecode: Failed to call GetAdditionalBytes")
      return -1, nil
    end

    pos, status = Util.unmarshall_uint32(data, pos)
    if (not self:CheckStat("LOOKUP", comm.version, status)) then
      return -1, nil
    end

    if (comm.version == 3) then
      status, data = comm:GetAdditionalBytes( data, pos, 4)
      if (not(status)) then
        stdnse.debug4("NFS.LookUpDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end
      _, len = Util.unmarshall_uint32(data, pos)
      status, data = comm:GetAdditionalBytes( data, pos, len + 4)
      if (not(status)) then
        stdnse.debug4("NFS.LookUpDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end
      lookup.fhandle, pos = string.unpack( "c" .. len + 4, data, pos)

      status, data = comm:GetAdditionalBytes( data, pos, 4)
      if (not(status)) then
        stdnse.debug4("NFS.LookUpDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end

      lookup.attributes = {}
      pos, value_follows = Util.unmarshall_uint32(data, pos)
      if (value_follows ~= 0) then
        status, data = comm:GetAdditionalBytes(data, pos, 84)
        if (not(status)) then
          stdnse.debug4("NFS.LookUpDecode: Failed to call GetAdditionalBytes")
          return -1, nil
        end
        pos, lookup.attributes = Util.unmarshall_nfsattr(data, pos, comm.version)
      else
        stdnse.debug4("NFS.LookUpDecode: File Attributes follow failed")
      end

      status, data = comm:GetAdditionalBytes( data, pos, 4)
      if (not(status)) then
        stdnse.debug4("NFS.LookUpDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end

      lookup.dir_attributes = {}
      pos, value_follows = Util.unmarshall_uint32(data, pos)
      if (value_follows ~= 0) then
        status, data = comm:GetAdditionalBytes(data, pos, 84)
        if (not(status)) then
          stdnse.debug4("NFS.LookUpDecode: Failed to call GetAdditionalBytes")
          return -1, nil
        end
        pos, lookup.dir_attributes = Util.unmarshall_nfsattr(data, pos, comm.version)
      else
        stdnse.debug4("NFS.LookUpDecode: File Attributes follow failed")
      end

    elseif (comm.version < 3) then
      status, data = comm:GetAdditionalBytes( data, pos, 32)
      if (not(status)) then
        stdnse.debug4("NFS.LookUpDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end
      lookup.fhandle, pos = string.unpack("c32", data, pos)
      status, data = comm:GetAdditionalBytes( data, pos, 64 )
      if (not(status)) then
        stdnse.debug4("NFS.LookUpDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end
      pos, lookup.attributes = Util.unmarshall_nfsattr(data, pos, comm.version)

    else
      stdnse.debug1("NFS.LookUpDecode: NFS unsupported version %d", comm.version)
      return -1, nil
    end

    return pos, lookup
  end,

  LookUp = function(self, comm, dir_handle, file)
    local status, packet
    local pos, data = 1, ""
    local header, response = {}, {}

    if (not(dir_handle)) then
      return false, "LookUp: No dirhandle received"
    end

    data = Util.marshall_opaque(dir_handle) .. Util.marshall_vopaque(file)
    packet = comm:EncodePacket(nil, NFS.Procedure[comm.version].LOOKUP,
      {type=Portmap.AuthType.UNIX}, data)
    if(not(comm:SendPacket(packet))) then
      return false, "LookUp: Failed to send data"
    end

    status, data = comm:ReceivePacket()
    if ( not(status) ) then
      return false, "LookUp: Failed to read data from socket"
    end

    pos, header = comm:DecodeHeader(data, pos)
    if not header then
      return false, "LookUp: Failed to decode header"
    end
    pos, response = self:LookUpDecode(comm, data, pos)
    if (not(response)) then
      return false, "LookUp: Failed to decode the LOOKUP section"
    end

    return true, response
  end,

  ReadDirPlusDecode = function(self, comm, data, pos)
    local response, status, value_follows, _ = {}

    status, data = comm:GetAdditionalBytes(data, pos, 4)
    if not status then
      stdnse.debug4("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
      return -1, nil
    end

    pos, status = Util.unmarshall_uint32(data, pos)
    if (not self:CheckStat("READDIRPLUS", comm.version, status)) then
      return -1, nil
    end

    status, data = comm:GetAdditionalBytes(data, pos, 4)
    if not status then
      stdnse.debug4("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
      return -1, nil
    end

    value_follows, pos = string.unpack(">I4", data, pos)
    if value_follows == 0 then
      stdnse.debug4("NFS.ReadDirPlusDecode: Attributes follow failed")
      return -1, nil
    end

    status, data = comm:GetAdditionalBytes( data, pos, 84 )
    if not status then
      stdnse.debug4("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
      return -1, nil
    end

    response.attributes = {}
    pos, response.attributes = Util.unmarshall_nfsattr(data, pos, comm.version)

    status, data = comm:GetAdditionalBytes(data, pos, 8)
    if not status then
      stdnse.debug4("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
      return -1, nil
    end
    _, pos = string.unpack(">I8", data, pos)

    response.entries = {}
    while true do
      local entry, len = {}
      status, data = comm:GetAdditionalBytes(data, pos, 4)
      if not status then
        stdnse.debug4("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end

      value_follows, pos = string.unpack(">I4", data, pos)

      if (value_follows == 0) then
        break
      end
      status, data = comm:GetAdditionalBytes(data, pos, 8)
      if not status then
        stdnse.debug4("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end
      entry.fileid, pos = string.unpack(">I8", data, pos)

      status, data = comm:GetAdditionalBytes(data, pos, 4)

      if not status then
        stdnse.debug4("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end

      entry.length, pos = string.unpack(">I4", data, pos)
      status, data = comm:GetAdditionalBytes( data, pos, entry.length )
      if not status then
        stdnse.debug4("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end

      pos, entry.name = Util.unmarshall_vopaque(entry.length, data, pos)
      status, data = comm:GetAdditionalBytes(data, pos, 8)
      if not status then
        stdnse.debug4("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end
      entry.cookie, pos = string.unpack(">I8", data, pos)
      status, data = comm:GetAdditionalBytes(data, pos, 4)
      if not status then
        stdnse.debug4("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end

      entry.attributes = {}
      value_follows, pos = string.unpack(">I4", data, pos)
      if (value_follows ~= 0) then
        status, data = comm:GetAdditionalBytes(data, pos, 84)
        if not status then
          stdnse.debug4("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
          return -1, nil
        end
        pos, entry.attributes = Util.unmarshall_nfsattr(data, pos, comm.version)
      else
        stdnse.debug4("NFS.ReadDirPlusDecode: %s Attributes follow failed",
          entry.name)
      end

      status, data = comm:GetAdditionalBytes(data, pos, 4)
      if not status then
        stdnse.debug4("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end

      entry.fhandle = ""
      value_follows, pos = string.unpack(">I4", data, pos)
      if (value_follows ~= 0) then
        status, data = comm:GetAdditionalBytes(data, pos, 4)
        if not status then
          stdnse.debug4("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
          return -1, nil
        end

        len = string.unpack(">I4", data, pos)
        status, data = comm:GetAdditionalBytes(data, pos, len + 4)
        if not status then
          stdnse.debug4("NFS.ReadDirPlusDecode: Failed to call GetAdditionalBytes")
          return -1, nil
        end
        entry.fhandle, pos = string.unpack( "c" .. len + 4, data, pos )
      else
        stdnse.debug4("NFS.ReadDirPlusDecode: %s handle follow failed",
          entry.name)
      end
      table.insert(response.entries, entry)
    end

    return pos, response
  end,

  ReadDirPlus = function(self, comm, file_handle)
    local status, packet
    local cookie, opaque_data, dircount, maxcount = 0, 0, 512, 8192
    local pos, data = 1, ""
    local header, response = {}, {}

    if (comm.version < 3) then
      return false, string.format("NFS version: %d does not support ReadDirPlus",
        comm.version)
    end

    if not file_handle then
      return false, "ReadDirPlus: No filehandle received"
    end

    data = file_handle .. string.pack(">I8 I8 I4 I4", cookie, opaque_data, dircount, maxcount)

    packet = comm:EncodePacket(nil, NFS.Procedure[comm.version].READDIRPLUS,
      {type = Portmap.AuthType.UNIX }, data)

    if (not(comm:SendPacket(packet))) then
      return false, "ReadDirPlus: Failed to send data"
    end

    status, data = comm:ReceivePacket()
    if not status then
      return false, "ReadDirPlus: Failed to read data from socket"
    end

    pos, header = comm:DecodeHeader( data, pos )
    if not header then
      return false, "ReadDirPlus: Failed to decode header"
    end
    pos, response = self:ReadDirPlusDecode( comm, data, pos )
    if not response then
      return false, "ReadDirPlus: Failed to decode the READDIR section"
    end

    return true, response
  end,

  FsStatDecode = function(self, comm, data, pos)
    local fsstat, status, value_follows = {}

    status, data = comm:GetAdditionalBytes(data, pos, 4)
    if not status then
      stdnse.debug4("NFS.FsStatDecode: Failed to call GetAdditionalBytes")
      return -1, nil
    end

    pos, status = Util.unmarshall_uint32(data, pos)
    if (not self:CheckStat("FSSTAT", comm.version, status)) then
      return -1, nil
    end

    fsstat.attributes = {}
    pos, value_follows = Util.unmarshall_uint32(data, pos)
    if (value_follows ~= 0) then
      status, data = comm:GetAdditionalBytes(data, pos, 84)
      if not status then
        stdnse.debug4("NFS.FsStatDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end
      pos, fsstat.attributes = Util.unmarshall_nfsattr(data, pos, comm.version)
    else
      stdnse.debug4("NFS.FsStatDecode: Attributes follow failed")
    end

    status, data = comm:GetAdditionalBytes( data, pos, 52)
    if not status then
      stdnse.debug4("NFS.FsStatDecode: Failed to call GetAdditionalBytes")
      return -1, nil
    end

    pos, fsstat.tbytes, fsstat.fbytes, fsstat.abytes, fsstat.tfiles,
    fsstat.ffiles, fsstat.afiles = Util.unmarshall_nfssize3(data, pos, 6)
    pos, fsstat.invarsec = Util.unmarshall_uint32(data, pos)

    return pos, fsstat
  end,

  FsStat = function(self, comm, file_handle)
    local status, packet
    local pos, data = 1, ""
    local header, response = {}, {}

    if (comm.version < 3) then
      return false, string.format("NFS version: %d does not support FSSTAT",
        comm.version)
    end

    if not file_handle then
      return false, "FsStat: No filehandle received"
    end

    packet = comm:EncodePacket(nil, NFS.Procedure[comm.version].FSSTAT,
      {type = Portmap.AuthType.UNIX}, file_handle)

    if (not(comm:SendPacket(packet))) then
      return false, "FsStat: Failed to send data"
    end

    status, data = comm:ReceivePacket()
    if not status then
      return false, "FsStat: Failed to read data from socket"
    end

    pos, header = comm:DecodeHeader(data, pos)
    if not header then
      return false, "FsStat: Failed to decode header"
    end

    pos, response = self:FsStatDecode(comm, data, pos)
    if not response then
      return false, "FsStat: Failed to decode the FSSTAT section"
    end
    return true, response
  end,

  FsInfoDecode = function(self, comm, data, pos)
    local fsinfo, status, value_follows = {}

    status, data = comm:GetAdditionalBytes(data, pos, 4)
    if not status then
      stdnse.debug4("NFS.FsInfoDecode: Failed to call GetAdditionalBytes")
      return -1, nil
    end

    pos, status = Util.unmarshall_uint32(data, pos)
    if (not self:CheckStat("FSINFO", comm.version, status)) then
      return -1, nil
    end

    fsinfo.attributes = {}
    pos, value_follows = Util.unmarshall_uint32(data, pos)
    if (value_follows ~= 0) then
      status, data = comm:GetAdditionalBytes(data, pos, 84)
      if not status then
        stdnse.debug4("NFS.FsInfoDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end
      pos, fsinfo.attributes = Util.unmarshall_nfsattr(data, pos, comm.version)
    else
      stdnse.debug4("NFS.FsInfoDecode: Attributes follow failed")
    end

    status, data = comm:GetAdditionalBytes(data, pos, 48)
    if not status then
      stdnse.debug4("NFS.FsStatDecode: Failed to call GetAdditionalBytes")
      return -1, nil
    end

    pos, fsinfo.rtmax, fsinfo.rtpref, fsinfo.rtmult,
    fsinfo.wtmax, fsinfo.wtpref, fsinfo.wtmult,
    fsinfo.dtpref = Util.unmarshall_uint32(data, pos, 7)
    pos, fsinfo.maxfilesize = Util.unmarshall_nfssize3(data, pos)
    pos, fsinfo.time_delta = Util.unmarshall_nfstime(data, pos)
    pos, fsinfo.properties = Util.unmarshall_uint32(data, pos)

    return pos, fsinfo
  end,

  FsInfo = function(self, comm, file_handle)
    local status, packet
    local pos, data = 1, ""
    local header, response = {}

    if (comm.version < 3) then
      return false, string.format("NFS version: %d does not support FSINFO",
        comm.version)
    end

    if not file_handle then
      return false, "FsInfo: No filehandle received"
    end

    data = Util.marshall_opaque(file_handle)
    packet = comm:EncodePacket(nil, NFS.Procedure[comm.version].FSINFO,
      {type = Portmap.AuthType.UNIX}, data)

    if (not(comm:SendPacket(packet))) then
      return false, "FsInfo: Failed to send data"
    end

    status, data = comm:ReceivePacket()
    if not status then
      return false, "FsInfo: Failed to read data from socket"
    end

    pos, header = comm:DecodeHeader(data, pos)
    if not header then
      return false, "FsInfo: Failed to decode header"
    end

    pos, response = self:FsInfoDecode(comm, data, pos)
    if not response then
      return false, "FsInfo: Failed to decode the FSINFO section"
    end
    return true, response
  end,

  PathConfDecode = function(self, comm, data, pos)
    local pconf, status, value_follows = {}

    status, data = comm:GetAdditionalBytes(data, pos, 4)
    if not status then
      stdnse.debug4("NFS.PathConfDecode: Failed to call GetAdditionalBytes")
      return -1, nil
    end

    pos, status = Util.unmarshall_uint32(data, pos)
    if (not self:CheckStat("PATHCONF", comm.version, status)) then
      return -1, nil
    end

    pconf.attributes = {}
    pos, value_follows = Util.unmarshall_uint32(data, pos)
    if (value_follows ~= 0) then
      status, data = comm:GetAdditionalBytes(data, pos, 84)
      if not status then
        stdnse.debug4("NFS.PathConfDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end
      pos, pconf.attributes = Util.unmarshall_nfsattr(data, pos, comm.version)
    else
      stdnse.debug4("NFS.PathConfDecode: Attributes follow failed")
    end

    status, data = comm:GetAdditionalBytes(data, pos, 24)
    if not status then
      stdnse.debug4("NFS.PathConfDecode: Failed to call GetAdditionalBytes")
      return -1, nil
    end

    pos, pconf.linkmax, pconf.name_max, pconf.no_trunc,
    pconf.chown_restricted, pconf.case_insensitive,
    pconf.case_preserving = Util.unmarshall_uint32(data, pos, 6)

    return pos, pconf
  end,

  PathConf = function(self, comm, file_handle)
    local status, packet
    local pos, data = 1, ""
    local header, response = {}

    if (comm.version < 3) then
      return false, string.format("NFS version: %d does not support PATHCONF",
        comm.version)
    end

    if not file_handle then
      return false, "PathConf: No filehandle received"
    end

    data = Util.marshall_opaque(file_handle)
    packet = comm:EncodePacket(nil, NFS.Procedure[comm.version].PATHCONF,
      {type = Portmap.AuthType.UNIX}, data)

    if (not(comm:SendPacket(packet))) then
      return false, "PathConf: Failed to send data"
    end

    status, data = comm:ReceivePacket()
    if not status then
      return false, "PathConf: Failed to read data from socket"
    end

    pos, header = comm:DecodeHeader(data, pos)
    if not header then
      return false, "PathConf: Failed to decode header"
    end

    pos, response = self:PathConfDecode(comm, data, pos)
    if not response then
      return false, "PathConf: Failed to decode the PATHCONF section"
    end
    return true, response
  end,

  AccessDecode = function(self, comm, data, pos)
    local access, status, value_follows = {}

    status, data = comm:GetAdditionalBytes(data, pos, 4)
    if not status then
      stdnse.debug4("NFS.AccessDecode: Failed to call GetAdditionalBytes")
      return -1, nil
    end

    pos, status = Util.unmarshall_uint32(data, pos)
    if (not self:CheckStat("ACCESS", comm.version, status)) then
      return -1, nil
    end

    access.attributes = {}
    pos, value_follows = Util.unmarshall_uint32(data, pos)
    if (value_follows ~= 0) then
      status, data = comm:GetAdditionalBytes(data, pos, 84)
      if not status then
        stdnse.debug4("NFS.AccessDecode: Failed to call GetAdditionalBytes")
        return -1, nil
      end
      pos, access.attributes = Util.unmarshall_nfsattr(data, pos, comm.version)
    else
      stdnse.debug4("NFS.AccessDecode: Attributes follow failed")
    end

    status, data = comm:GetAdditionalBytes(data, pos, 4)
    if not status then
      stdnse.debug4("NFS.AccessDecode: Failed to call GetAdditionalBytes")
      return -1, nil
    end

    pos, access.mask = Util.unmarshall_uint32(data, pos)

    return pos, access
  end,

  Access = function(self, comm, file_handle, access)
    local status, packet
    local pos, data = 1, ""
    local header, response = {}, {}

    if (comm.version < 3) then
      return false, string.format("NFS version: %d does not support ACCESS",
        comm.version)
    end

    if not file_handle then
      return false, "Access: No filehandle received"
    end

    data = Util.marshall_opaque(file_handle) .. Util.marshall_uint32(access)
    packet = comm:EncodePacket(nil, NFS.Procedure[comm.version].ACCESS,
      {type = Portmap.AuthType.UNIX}, data)

    if (not(comm:SendPacket(packet))) then
      return false, "Access: Failed to send data"
    end

    status, data = comm:ReceivePacket()
    if not status then
      return false, "Access: Failed to read data from socket"
    end

    pos, header = comm:DecodeHeader(data, pos)
    if not header then
      return false, "Access: Failed to decode header"
    end

    pos, response = self:AccessDecode(comm, data, pos)
    if not response then
      return false, "Access: Failed to decode the FSSTAT section"
    end

    return true, response
  end,

  --- Gets filesystem stats (Total Blocks, Free Blocks and Available block) on a remote NFS share
  --
  -- @param comm object handles rpc program information and
  --  low-level packet manipulation
  -- @param file_handle string containing the filehandle to query
  -- @return status true on success, false on failure
  -- @return statfs table with the fields <code>transfer_size</code>, <code>block_size</code>,
  --  <code>total_blocks</code>, <code>free_blocks</code> and <code>available_blocks</code>
  -- @return errormsg if status is false
  StatFs = function( self, comm, file_handle )

    local status, packet
    local pos, data, _ = 1, "", ""
    local header, statfs = {}, {}

    if ( comm.version > 2 ) then
      return false, ("StatFs: Version %d not supported"):format(comm.version)
    end

    if ( not(file_handle) or file_handle:len() ~= 32 ) then
      return false, "StatFs: Incorrect filehandle received"
    end

    data = Util.marshall_opaque(file_handle)
    packet = comm:EncodePacket( nil, NFS.Procedure[comm.version].STATFS, { type=Portmap.AuthType.UNIX }, data )
    if (not(comm:SendPacket( packet ))) then
      return false, "StatFS: Failed to send data"
    end

    status, data = comm:ReceivePacket( )
    if ( not(status) ) then
      return false, "StatFs: Failed to read data from socket"
    end

    pos, header = comm:DecodeHeader( data, pos )

    if not header then
      return false, "StatFs: Failed to decode header"
    end

    pos, statfs = self:StatFsDecode( comm, data, pos )

    if not statfs then
      return false, "StatFs: Failed to decode statfs structure"
    end
    return true, statfs
  end,

  --- Attempts to decode the attributes section of the reply
  --
  -- @param comm object handles rpc program information and
  --  low-level packet manipulation
  -- @param data string containing the full statfs reply
  -- @param pos number pointing to the statfs section of the reply
  -- @return pos number containing the offset after decoding
  -- @return statfs table with the following fields: <code>type</code>, <code>mode</code>,
  --  <code>nlink</code>, <code>uid</code>, <code>gid</code>, <code>size</code>,
  --  <code>blocksize</code>, <code>rdev</code>, <code>blocks</code>, <code>fsid</code>,
  --  <code>fileid</code>, <code>atime</code>, <code>mtime</code> and <code>ctime</code>
  --
  GetAttrDecode = function( self, comm, data, pos )
    local status

    status, data = comm:GetAdditionalBytes( data, pos, 4 )
    if (not(status)) then
      stdnse.debug4("GetAttrDecode: Failed to call GetAdditionalBytes")
      return -1, nil
    end

    pos, status = Util.unmarshall_uint32(data, pos)
    if (not self:CheckStat("GETATTR", comm.version, status)) then
      return -1, nil
    end

    if ( comm.version < 3 ) then
      status, data = comm:GetAdditionalBytes( data, pos, 64 )
    elseif (comm.version == 3) then
      status, data = comm:GetAdditionalBytes( data, pos, 84 )
    else
      stdnse.debug4("GetAttrDecode: Unsupported version")
      return -1, nil
    end
    if ( not(status) ) then
      stdnse.debug4("GetAttrDecode: Failed to call GetAdditionalBytes")
      return -1, nil
    end
    return Util.unmarshall_nfsattr(data, pos, comm.version)
  end,

  --- Gets mount attributes (uid, gid, mode, etc ..) from a remote NFS share
  --
  -- @param comm object handles rpc program information and
  --  low-level packet manipulation
  -- @param file_handle string containing the filehandle to query
  -- @return status true on success, false on failure
  -- @return attribs table with the fields <code>type</code>, <code>mode</code>,
  --  <code>nlink</code>, <code>uid</code>, <code>gid</code>, <code>size</code>,
  --  <code>blocksize</code>, <code>rdev</code>, <code>blocks</code>, <code>fsid</code>,
  --  <code>fileid</code>, <code>atime</code>, <code>mtime</code> and <code>ctime</code>
  -- @return errormsg if status is false
  GetAttr = function( self, comm, file_handle )
    local data, packet, status, attribs, pos, header

    data = Util.marshall_opaque(file_handle)
    packet = comm:EncodePacket( nil, NFS.Procedure[comm.version].GETATTR, { type=Portmap.AuthType.UNIX }, data )
    if(not(comm:SendPacket(packet))) then
      return false, "GetAttr: Failed to send data"
    end

    status, data = comm:ReceivePacket()
    if ( not(status) ) then
      return false, "GetAttr: Failed to read data from socket"
    end

    pos, header = comm:DecodeHeader( data, 1 )
    if not header then
      return false, "GetAttr: Failed to decode header"
    end

    pos, attribs = self:GetAttrDecode(comm, data, pos )
    if not attribs then
      return false, "GetAttr: Failed to decode attrib structure"
    end

    return true, attribs
  end,

  --- Attempts to decode the StatFS section of the reply
  --
  -- @param comm object handles rpc program information and
  --  low-level packet manipulation
  -- @param data string containing the full statfs reply
  -- @param pos number pointing to the statfs section of the reply
  -- @return pos number containing the offset after decoding
  -- @return statfs table with the following fields: <code>transfer_size</code>, <code>block_size</code>,
  --  <code>total_blocks</code>, <code>free_blocks</code> and <code>available_blocks</code>
  StatFsDecode = function( self, comm, data, pos )
    local status
    local statfs = {}

    status, data = comm:GetAdditionalBytes( data, pos, 4 )
    if (not(status)) then
      stdnse.debug4("StatFsDecode: Failed to call GetAdditionalBytes")
      return -1, nil
    end

    pos, status = Util.unmarshall_uint32(data, pos)
    if (not self:CheckStat("STATFS", comm.version, status)) then
      return -1, nil
    end

    status, data = comm:GetAdditionalBytes( data, pos, 20 )
    if (not(status)) then
      stdnse.debug4("StatFsDecode: Failed to call GetAdditionalBytes")
      return -1, nil
    end
    pos, statfs.transfer_size, statfs.block_size,
    statfs.total_blocks, statfs.free_blocks,
    statfs.available_blocks = Util.unmarshall_uint32(data, pos, 5)
    return pos, statfs
  end,
}

Helper = {

  --- Lists the NFS exports on the remote host
  -- This function abstracts the RPC communication with the portmapper from the user
  --
  -- @param host table
  -- @param port table
  -- @return status true on success, false on failure
  -- @return result table of string entries or error message on failure
  ShowMounts = function( host, port )

    local status, result, mounts
    local mountd, mnt_comm
    local mnt = Mount:new()
    local portmap = Portmap:new()

    status, mountd = Helper.GetProgramInfo( host, port, "mountd")
    if ( not(status) ) then
      stdnse.debug4("rpc.Helper.ShowMounts: GetProgramInfo failed")
      return status, "rpc.Helper.ShowMounts: GetProgramInfo failed"
    end

    mnt_comm = Comm:new('mountd', mountd.version)
    status, result = mnt_comm:Connect(host, mountd.port)
    if ( not(status) ) then
      stdnse.debug4("rpc.Helper.ShowMounts: %s", result)
      return false, result
    end
    status, mounts = mnt:Export(mnt_comm)
    mnt_comm:Disconnect()
    if ( not(status) ) then
      stdnse.debug4("rpc.Helper.ShowMounts: %s", mounts)
    end
    return status, mounts
  end,

  --- Mounts a remote NFS export and returns the file handle
  --
  -- This is a high level function to be used by NSE scripts
  -- To close the mounted NFS export use UnmountPath() function
  --
  -- @param host table
  -- @param port table
  -- @param path string containing the path to mount
  -- @return on success a Comm object which can be
  --         used later as a parameter by low level Mount
  --         functions, on failure returns nil.
  -- @return on success the filehandle of the NFS export as
  --         a string, on failure returns the error message.
  MountPath = function(host, port, path)
    local fhandle, status, err
    local mountd, mnt_comm
    local mnt = Mount:new()

    status, mountd = Helper.GetProgramInfo( host, port, "mountd")
    if not status then
      stdnse.debug4("rpc.Helper.MountPath: GetProgramInfo failed")
      return nil, "rpc.Helper.MountPath: GetProgramInfo failed"
    end

    mnt_comm = Comm:new("mountd", mountd.version)

    status, err = mnt_comm:Connect(host, mountd.port)
    if not status then
      stdnse.debug4("rpc.Helper.MountPath: %s", err)
      return nil, err
    end

    status, fhandle = mnt:Mount(mnt_comm, path)
    if not status then
      mnt_comm:Disconnect()
      stdnse.debug4("rpc.Helper.MountPath: %s", fhandle)
      return nil, fhandle
    end

    return mnt_comm, fhandle
  end,

  --- Unmounts a remote mounted NFS export
  --
  -- This is a high level function to be used by NSE scripts
  -- This function must be used to unmount a NFS point
  -- mounted by MountPath()
  --
  -- @param mnt_comm object returned from a previous call to
  --        MountPath()
  -- @param path string containing the path to unmount
  -- @return true on success or nil on failure
  -- @return error message on failure
  UnmountPath = function(mnt_comm, path)
    local mnt = Mount:new()
    local status, ret = mnt:Unmount(mnt_comm, path)
    mnt_comm:Disconnect()
    if not status then
      stdnse.debug4("rpc.Helper.UnmountPath: %s", ret)
      return nil, ret
    end

    return status, nil
  end,

  --- Connects to a remote NFS server
  --
  -- This is a high level function to open NFS connections
  -- To close the NFS connection use NfsClose() function
  --
  -- @param host table
  -- @param port table
  -- @return on success a Comm object which can be
  --         used later as a parameter by low level NFS
  --         functions, on failure returns nil.
  -- @return error message on failure.
  NfsOpen = function(host, port)
    local nfs_comm, nfsd, status, err

    status, nfsd = Helper.GetProgramInfo(host, port, "nfs")
    if not status then
      stdnse.debug4("rpc.Helper.NfsOpen: GetProgramInfo failed")
      return nil, "rpc.Helper.NfsOpen: GetProgramInfo failed"
    end

    nfs_comm = Comm:new('nfs', nfsd.version)
    status, err = nfs_comm:Connect(host, nfsd.port)
    if not status then
      stdnse.debug4("rpc.Helper.NfsProc: %s", err)
      return nil, err
    end

    return nfs_comm, nil
  end,

  --- Closes the NFS connection
  --
  -- This is a high level function to close NFS connections
  -- This function must be used to close the NFS connection
  --  opened by the NfsOpen() call
  --
  -- @param nfs_comm object returned by NfsOpen()
  -- @return true on success or nil on failure
  -- @return error message on failure
  NfsClose = function(nfs_comm)
    local status, ret = nfs_comm:Disconnect()
    if not status then
      stdnse.debug4("rpc.Helper.NfsClose: %s", ret)
      return nil, ret
    end

    return status, nil
  end,

  --- Retrieves NFS storage statistics
  --
  -- @param host table
  -- @param port table
  -- @param path string containing the nfs export path
  -- @return status true on success, false on failure
  -- @return statfs table with the fields <code>transfer_size</code>, <code>block_size</code>,
  --  <code>total_blocks</code>, <code>free_blocks</code> and <code>available_blocks</code>
  ExportStats = function( host, port, path )
    local fhandle
    local stats, status, result
    local mnt_comm, nfs_comm
    local mountd, nfsd = {}, {}
    local mnt, nfs = Mount:new(), NFS:new()

    status, mountd = Helper.GetProgramInfo( host, port, "mountd", 2)
    if ( not(status) ) then
      stdnse.debug4("rpc.Helper.ExportStats: GetProgramInfo failed")
      return status, "rpc.Helper.ExportStats: GetProgramInfo failed"
    end

    status, nfsd = Helper.GetProgramInfo( host, port, "nfs", 2)
    if ( not(status) ) then
      stdnse.debug4("rpc.Helper.ExportStats: GetProgramInfo failed")
      return status, "rpc.Helper.ExportStats: GetProgramInfo failed"
    end
    mnt_comm = Comm:new('mountd', mountd.version)
    nfs_comm = Comm:new('nfs', nfsd.version)

    -- TODO: recheck the version mismatch when adding NFSv4
    if (nfs_comm.version <= 2  and mnt_comm.version > 2) then
      stdnse.debug4("rpc.Helper.ExportStats: versions mismatch, nfs v%d - mount v%d",
        nfs_comm.version, mnt_comm.version)
      return false, string.format("versions mismatch, nfs v%d - mount v%d",
        nfs_comm.version, mnt_comm.version)
    end
    status, result = mnt_comm:Connect(host, mountd.port)
    if ( not(status) ) then
      stdnse.debug4("rpc.Helper.ExportStats: %s", result)
      return status, result
    end
    status, result = nfs_comm:Connect(host, nfsd.port)
    if ( not(status) ) then
      mnt_comm:Disconnect()
      stdnse.debug4("rpc.Helper.ExportStats: %s", result)
      return status, result
    end

    status, fhandle = mnt:Mount(mnt_comm, path)
    if ( not(status) ) then
      mnt_comm:Disconnect()
      nfs_comm:Disconnect()
      stdnse.debug4("rpc.Helper.ExportStats: %s", fhandle)
      return status, fhandle
    end
    status, stats = nfs:StatFs(nfs_comm, fhandle)
    if ( not(status) ) then
      mnt_comm:Disconnect()
      nfs_comm:Disconnect()
      stdnse.debug4("rpc.Helper.ExportStats: %s", stats)
      return status, stats
    end

    status, fhandle = mnt:Unmount(mnt_comm, path)
    mnt_comm:Disconnect()
    nfs_comm:Disconnect()
    if ( not(status) ) then
      stdnse.debug4("rpc.Helper.ExportStats: %s", fhandle)
      return status, fhandle
    end
    return true, stats
  end,

  --- Retrieves a list of files from the NFS export
  --
  -- @param host table
  -- @param port table
  -- @param path string containing the nfs export path
  -- @return status true on success, false on failure
  -- @return table of file table entries as described in <code>decodeReadDir</code>
  Dir = function( host, port, path )
    local fhandle
    local dirs, status, result
    local mountd, nfsd = {}, {}
    local mnt_comm, nfs_comm
    local mnt, nfs = Mount:new(), NFS:new()

    status, mountd = Helper.GetProgramInfo( host, port, "mountd")
    if ( not(status) ) then
      stdnse.debug4("rpc.Helper.Dir: GetProgramInfo failed")
      return status, "rpc.Helper.Dir: GetProgramInfo failed"
    end

    status, nfsd = Helper.GetProgramInfo( host, port, "nfs")
    if ( not(status) ) then
      stdnse.debug4("rpc.Helper.Dir: GetProgramInfo failed")
      return status, "rpc.Helper.Dir: GetProgramInfo failed"
    end

    mnt_comm = Comm:new('mountd', mountd.version)
    nfs_comm = Comm:new('nfs', nfsd.version)

    -- TODO: recheck the version mismatch when adding NFSv4
    if (nfs_comm.version <= 2  and mnt_comm.version > 2) then
      stdnse.debug4("rpc.Helper.Dir: versions mismatch, nfs v%d - mount v%d",
        nfs_comm.version, mnt_comm.version)
      return false, string.format("versions mismatch, nfs v%d - mount v%d",
        nfs_comm.version, mnt_comm.version)
    end
    status, result = mnt_comm:Connect(host, mountd.port)
    if ( not(status) ) then
      stdnse.debug4("rpc.Helper.Dir: %s", result)
      return status, result
    end

    status, result = nfs_comm:Connect(host, nfsd.port)
    if ( not(status) ) then
      mnt_comm:Disconnect()
      stdnse.debug4("rpc.Helper.Dir: %s", result)
      return status, result
    end

    status, fhandle = mnt:Mount(mnt_comm, path )
    if ( not(status) ) then
      mnt_comm:Disconnect()
      nfs_comm:Disconnect()
      stdnse.debug4("rpc.Helper.Dir: %s", fhandle)
      return status, fhandle
    end

    status, dirs = nfs:ReadDir(nfs_comm, fhandle )
    if ( not(status) ) then
      mnt_comm:Disconnect()
      nfs_comm:Disconnect()
      stdnse.debug4("rpc.Helper.Dir: %s", dirs)
      return status, dirs
    end

    status, fhandle = mnt:Unmount(mnt_comm, path)
    mnt_comm:Disconnect()
    nfs_comm:Disconnect()
    if ( not(status) ) then
      stdnse.debug4("rpc.Helper.Dir: %s", fhandle)
      return status, fhandle
    end
    return true, dirs
  end,

  --- Retrieves NFS Attributes
  --
  -- @param host table
  -- @param port table
  -- @param path string containing the nfs export path
  -- @return status true on success, false on failure
  -- @return statfs table with the fields <code>transfer_size</code>, <code>block_size</code>,
  --  <code>total_blocks</code>, <code>free_blocks</code> and <code>available_blocks</code>
  GetAttributes = function( host, port, path )
    local fhandle
    local attribs, status, result
    local mnt_comm, nfs_comm
    local mountd, nfsd = {}, {}
    local mnt, nfs = Mount:new(), NFS:new()

    status, mountd = Helper.GetProgramInfo( host, port, "mountd")
    if ( not(status) ) then
      stdnse.debug4("rpc.Helper.GetAttributes: GetProgramInfo failed")
      return status, "rpc.Helper.GetAttributes: GetProgramInfo failed"
    end

    status, nfsd = Helper.GetProgramInfo( host, port, "nfs")
    if ( not(status) ) then
      stdnse.debug4("rpc.Helper.GetAttributes: GetProgramInfo failed")
      return status, "rpc.Helper.GetAttributes: GetProgramInfo failed"
    end

    mnt_comm, result = Comm:new('mountd', mountd.version)
    nfs_comm, result = Comm:new('nfs', nfsd.version)

    -- TODO: recheck the version mismatch when adding NFSv4
    if (nfs_comm.version <= 2  and mnt_comm.version > 2) then
      stdnse.debug4("rpc.Helper.GetAttributes: versions mismatch, nfs v%d - mount v%d",
        nfs_comm.version, mnt_comm.version)
      return false, string.format("versions mismatch, nfs v%d - mount v%d",
        nfs_comm.version, mnt_comm.version)
    end

    status, result = mnt_comm:Connect(host, mountd.port)
    if ( not(status) ) then
      stdnse.debug4("rpc.Helper.GetAttributes: %s", result)
      return status, result
    end

    status, result = nfs_comm:Connect(host, nfsd.port)
    if ( not(status) ) then
      mnt_comm:Disconnect()
      stdnse.debug4("rpc.Helper.GetAttributes: %s", result)
      return status, result
    end

    status, fhandle = mnt:Mount(mnt_comm, path)
    if ( not(status) ) then
      mnt_comm:Disconnect()
      nfs_comm:Disconnect()
      stdnse.debug4("rpc.Helper.GetAttributes: %s", fhandle)
      return status, fhandle
    end

    status, attribs = nfs:GetAttr(nfs_comm, fhandle)
    if ( not(status) ) then
      mnt_comm:Disconnect()
      nfs_comm:Disconnect()
      stdnse.debug4("rpc.Helper.GetAttributes: %s", attribs)
      return status, attribs
    end

    status, fhandle = mnt:Unmount(mnt_comm, path)

    mnt_comm:Disconnect()
    nfs_comm:Disconnect()
    if ( not(status) ) then
      stdnse.debug4("rpc.Helper.GetAttributes: %s", fhandle)
      return status, fhandle
    end

    return true, attribs
  end,

  --- Queries the portmapper for a list of programs
  --
  -- @param host table
  -- @param port table
  -- @return status true on success, false on failure
  -- @return table containing the portmapper information as returned by
  -- <code>Portmap.Dump</code>
  RpcInfo = function( host, port )
    local status, result
    local portmap = Portmap:new()

    mutex "lock"

    if nmap.registry[host.ip] == nil then
      nmap.registry[host.ip] = {}
    end
    if nmap.registry[host.ip]['portmapper'] == nil then
      nmap.registry[host.ip]['portmapper'] = {}
    elseif next(nmap.registry[host.ip]['portmapper']) ~= nil then
      mutex "done"
      return true, nmap.registry[host.ip]['portmapper']
    end

    local pversion = 4
    while pversion >= 2 do
      local comm = Comm:new('rpcbind', pversion)
      status, result = comm:Connect(host, port)
      if (not(status)) then
        mutex "done"
        stdnse.debug4("rpc.Helper.RpcInfo: %s", result)
        return status, result
      end

      status, result = portmap:Dump(comm)
      comm:Disconnect()

      if status then
        break
      end
      stdnse.debug4("rpc.Helper.RpcInfo: %s", result)
      pversion = pversion - 1
    end

    mutex "done"
    return status, result
  end,

  --- Queries the portmapper for a port for the specified RPC program
  --
  -- @param host table
  -- @param port table
  -- @param program string containing the RPC program name
  -- @param protocol string containing either "tcp" or "udp"
  -- @return status true on success, false on failure
  -- @return table containing the portmapper information as returned by
  -- <code>Portmap.Dump</code>
  GetPortForProgram = function( host, port, program, protocol )
    local status, result
    local portmap = Portmap:new()
    local comm = Comm:new('rpcbind', 2)

    status, result = comm:Connect(host, port)
    if (not(status)) then
      stdnse.debug4("rpc.Helper.GetPortForProgram: %s", result)
      return status, result
    end

    status, result = portmap:GetPort(comm, program, protocol, 1 )
    comm:Disconnect()
    if (not(status)) then
      stdnse.debug4("rpc.Helper.GetPortForProgram: %s", result)
    end

    return status, result
  end,

  --- Get RPC program information
  --
  -- @param host table
  -- @param port table
  -- @param program string containing the RPC program name
  -- @param max_version (optional) number containing highest version to retrieve
  -- @return status true on success, false on failure
  -- @return info table containing <code>port</code>, <code>port.number</code>
  -- <code>port.protocol</code> and <code>version</code>
  GetProgramInfo = function( host, port, program, max_version )
    local status, portmap_table = Helper.RpcInfo(host, port)
    if ( not(status) ) then
      return status, portmap_table
    end

    -- assume failure
    status = false

    local tmp = portmap_table[Util.ProgNameToNumber(program)]
    if not tmp then
      return false, "Program not supported by target"
    end

    local info = {}
    local proginfo
    local ipv6 = nmap.address_family() == "inet6"
    ::AF_FALLBACK::
    for _, p in ipairs( RPC_PROTOCOLS ) do
      if ipv6 then
        proginfo = tmp[p .. "6"]
      else
        proginfo = tmp[p]
      end
      if proginfo then
        info.port = {}
        info.port.number = proginfo.port
        info.port.protocol = p
        break
      end
    end
    if ipv6 and not proginfo then
      -- Fall back to trying IPv4
      ipv6 = false
      goto AF_FALLBACK
    end

    if not proginfo then
      return false, "No transport protocol supported"
    end

    -- choose the highest version available
    if ( not(RPC_version[program]) ) then
      info.version = proginfo.version[#proginfo.version]
      status = true
    else
      for i=#proginfo.version, 1, -1 do
        if ( RPC_version[program].max >= proginfo.version[i] ) then
          if ( not(max_version) ) then
            info.version = proginfo.version[i]
            status = true
            break
          else
            if ( max_version >= proginfo.version[i] ) then
              info.version = proginfo.version[i]
              status = true
              break
            end
          end
        end
      end
    end

    return status, info
  end,
}

--- Static class containing mostly conversion functions
--  and File type codes and permissions emulation
Util =
{
  -- Symbolic letters for file permission codes
  Fperm =
  {
    owner =
    {
      -- S_IRUSR
      [0x00000100] = { idx = 1, char = "r" },
      -- S_IWUSR
      [0x00000080] = { idx = 2, char = "w" },
      -- S_IXUSR
      [0x00000040] = { idx = 3, char = "x" },
      -- S_ISUID
      [0x00000800] = { idx = 3, char = "S" },
    },
    group =
    {
      -- S_IRGRP
      [0x00000020] = { idx = 4, char = "r" },
      -- S_IWGRP
      [0x00000010] = { idx = 5, char = "w" },
      -- S_IXGRP
      [0x00000008] = { idx = 6, char = "x" },
      -- S_ISGID
      [0x00000400] = { idx = 6, char = "S" },
    },
    other =
    {
      -- S_IROTH
      [0x00000004] = { idx = 7, char = "r" },
      -- S_IWOTH
      [0x00000002] = { idx = 8, char = "w" },
      -- S_IXOTH
      [0x00000001] = { idx = 9, char = "x" },
      -- S_ISVTX
      [0x00000200] = { idx = 9, char = "t" },
    },
  },

  -- bit mask used to extract the file type code from a mode
  -- S_IFMT = 00170000 (octal)
  S_IFMT = 0xF000,

  FileType =
  {
    -- S_IFSOCK
    [0x0000C000] = { char = "s", str = "socket" },
    -- S_IFLNK
    [0x0000A000] = { char = "l", str = "symbolic link" },
    -- S_IFREG
    [0x00008000] = { char = "-", str = "file" },
    -- S_IFBLK
    [0x00006000] = { char = "b", str = "block device" },
    -- S_IFDIR
    [0x00004000] = { char = "d", str = "directory" },
    -- S_IFCHR
    [0x00002000] = { char = "c", str = "char device" },
    -- S_IFIFO
    [0x00001000] = { char = "p", str = "named pipe" },
  },

  --- Converts a numeric ACL mode to a file type char
  --
  -- @param mode number containing the ACL mode
  -- @return char containing the file type
  FtypeToChar = function(mode)
    local code = mode & Util.S_IFMT
    if Util.FileType[code] then
      return Util.FileType[code].char
    else
      stdnse.debug1("FtypeToChar: Unknown file type, mode: %o", mode)
      return ""
    end
  end,

  --- Converts a numeric ACL mode to a file type string
  --
  -- @param mode number containing the ACL mode
  -- @return string containing the file type name
  FtypeToString = function(mode)
    local code = mode & Util.S_IFMT
    if Util.FileType[code] then
      return Util.FileType[code].str
    else
      stdnse.debug1("FtypeToString: Unknown file type, mode: %o", mode)
      return ""
    end
  end,

  --- Converts a numeric ACL mode to a string in an octal
  -- number format.
  --
  -- @param mode number containing the ACL mode
  -- @return string containing the octal ACL mode
  FmodeToOctalString = function(mode)
    local code = mode & Util.S_IFMT
    if Util.FileType[code] then
      code = mode ~ code
    else
      code = mode
      stdnse.debug1("FmodeToOctalString: Unknown file type, mode: %o", mode)
    end
    return stdnse.tooctal(code)
  end,

  --- Converts a numeric ACL to its character equivalent eg. (rwxr-xr-x)
  --
  -- @param mode number containing the ACL mode
  -- @return string containing the ACL characters
  FpermToString = function(mode)
    local tmpacl = { "-", "-", "-", "-", "-", "-", "-", "-", "-" }

    for user,_ in pairs(Util.Fperm) do
      local t = Util.Fperm[user]
      for i in pairs(t) do
        local code = mode & i
        if t[code] then
          -- save set-ID and sticky bits
          if tmpacl[t[code].idx] == "x" then
            if t[code].char == "S" then
              tmpacl[t[code].idx] = "s"
            else
              tmpacl[t[code].idx] = t[code].char
            end
          elseif tmpacl[t[code].idx] == "S" then
            if t[code].char == "x" then
              tmpacl[t[code].idx] = "s"
            end
          else
            tmpacl[t[code].idx] = t[code].char
          end
        end
      end
    end

    return table.concat(tmpacl)
  end,

  --- Converts the NFS file attributes to a string.
  --
  -- An optional second argument is the mactime to use
  --
  -- @param attr table returned by NFS GETATTR or ACCESS
  -- @param mactime to use, the default value is mtime
  --        Possible values: mtime, atime, ctime
  -- @return string containing the file attributes
  format_nfsfattr = function(attr, mactime)
    local time = "mtime"
    if mactime then
      time = mactime
    end

    return string.format("%s%s  uid: %5d  gid: %5d  %6s  %s",
      Util.FtypeToChar(attr.mode),
      Util.FpermToString(attr.mode),
      attr.uid,
      attr.gid,
      Util.SizeToHuman(attr.size),
      Util.TimeToString(attr[time].seconds))
  end,

  marshall_int32 = function(int32)
    return string.pack(">i4", int32)
  end,

  unmarshall_int32 = function(data, pos, count)
    local ints = {}
    for i=1,(count or 1) do
      ints[i], pos = string.unpack(">i4", data, pos)
    end
    return pos, table.unpack(ints)
  end,

  marshall_uint32 = function(uint32)
    return string.pack(">I4", uint32)
  end,

  unmarshall_uint32 = function(data, pos, count)
    local ints = {}
    for i=1,(count or 1) do
      ints[i], pos = string.unpack(">I4", data, pos)
    end
    return pos, table.unpack(ints)
  end,

  marshall_int64 = function(int64)
    return string.pack(">i8", int64)
  end,

  unmarshall_int64 = function(data, pos, count)
    local ints = {}
    for i=1,(count or 1) do
      ints[i], pos = string.unpack(">i8", data, pos)
    end
    return pos, table.unpack(ints)
  end,

  marshall_uint64 = function(uint64)
    return string.pack(">I8", uint64)
  end,

  unmarshall_uint64 = function(data, pos, count)
    local ints = {}
    for i=1,(count or 1) do
      ints[i], pos = string.unpack(">I8", data, pos)
    end
    return pos, table.unpack(ints)
  end,

  marshall_opaque = function(data)
    return data .. string.rep("\0", Util.CalcFillBytes(data:len()))
  end,

  unmarshall_opaque = function(len, data, pos)
    local opaque, pos = string.unpack("c" .. len, data, pos)
    return pos, opaque
  end,

  marshall_vopaque = function(data)
    local l = data:len()
    return (
      Util.marshall_uint32(l) .. data ..
      string.rep("\0", Util.CalcFillBytes(l))
      )
  end,

  unmarshall_vopaque = function(len, data, pos)
    local opaque, pad
    pad = Util.CalcFillBytes(len)
    opaque, pos = string.unpack("c" .. len, data, pos)
    return pos + pad, opaque
  end,

  unmarshall_nfsftype = function(data, pos, count)
    return Util.unmarshall_uint32(data, pos, count)
  end,

  unmarshall_nfsfmode = function(data, pos, count)
    return Util.unmarshall_uint32(data, pos, count)
  end,

  unmarshall_nfssize3 = function(data, pos, count)
    return Util.unmarshall_uint64(data, pos, count)
  end,

  unmarshall_nfsspecdata3 = function(data, pos)
    local specdata3 = {}
    pos, specdata3.specdata1,
    specdata3.specdata2 = Util.unmarshall_uint32(data, pos, 2)
    return pos, specdata3
  end,

  --- Unmarshall NFSv3 fileid field of the NFS attributes
  --
  -- @param data   The data being processed.
  -- @param pos    The position within <code>data</code>
  -- @return pos   The new position
  -- @return uint64 The decoded fileid
  unmarshall_nfsfileid3 = function(data, pos)
    return Util.unmarshall_uint64(data, pos)
  end,

  --- Unmarshall NFS time
  --
  -- @param data   The data being processed.
  -- @param pos    The position within <code>data</code>
  -- @return pos   The new position
  -- @return table The decoded NFS time table.
  unmarshall_nfstime = function(data, pos)
    local nfstime = {}
    pos, nfstime.seconds,
    nfstime.nseconds = Util.unmarshall_uint32(data, pos, 2)
    return pos, nfstime
  end,

  --- Unmarshall NFS file attributes
  --
  -- @param data   The data being processed.
  -- @param pos    The position within <code>data</code>
  -- @param number The NFS version.
  -- @return pos   The new position
  -- @return table The decoded file attributes table.
  unmarshall_nfsattr = function(data, pos, nfsversion)
    local attr = {}
    pos, attr.type = Util.unmarshall_nfsftype(data, pos)
    pos, attr.mode = Util.unmarshall_nfsfmode(data, pos)
    pos, attr.nlink, attr.uid,
    attr.gid = Util.unmarshall_uint32(data, pos, 3)

    if (nfsversion < 3) then
      pos, attr.size, attr.blocksize, attr.rdev, attr.blocks,
      attr.fsid, attr.fileid = Util.unmarshall_uint32(data, pos, 6)
    elseif (nfsversion == 3) then
      pos, attr.size = Util.unmarshall_nfssize3(data, pos)
      pos, attr.used = Util.unmarshall_nfssize3(data, pos)
      pos, attr.rdev = Util.unmarshall_nfsspecdata3(data, pos)
      pos, attr.fsid = Util.unmarshall_uint64(data, pos)
      pos, attr.fileid = Util.unmarshall_nfsfileid3(data, pos)
    else
      stdnse.debug4("unmarshall_nfsattr: unsupported NFS version %d",
        nfsversion)
      return -1, nil
    end

    pos, attr.atime = Util.unmarshall_nfstime(data, pos)
    pos, attr.mtime = Util.unmarshall_nfstime(data, pos)
    pos, attr.ctime = Util.unmarshall_nfstime(data, pos)

    return pos, attr
  end,

  --- Returns a string containing date and time
  --
  -- @param number of seconds since some given start time
  --        (the "epoch")
  -- @return string that represents time.
  TimeToString = datetime.format_timestamp,

  --- Converts the size in bytes to a human readable format
  --
  -- An optional second argument is the size of a block
  -- @usage
  -- size_tohuman(1024) --> 1024.0B
  -- size_tohuman(926548776) --> 883.6M
  -- size_tohuman(246548, 1024) --> 240.8K
  -- size_tohuman(246548, 1000) --> 246.5K
  --
  -- @param size in bytes
  -- @param blocksize represents the number of bytes per block
  --        Possible values are: 1024 or 1000
  --        Default value is: 1024
  -- @return string containing the size in the human readable
  --        format
  SizeToHuman = function(size, blocksize)
    local bs, idx = 1024, 1
    local unit = { "B", "K", "M", "G" , "T"}
    if blocksize and blocksize == 1000 then
      bs = blocksize
    end
    for i=1, #unit do
      if (size > bs and idx < #unit) then
        size = size / bs
        idx = idx + 1
      end
    end
    return string.format("%.1f%s", size, unit[idx])
  end,

  format_access = function(mask, version)
    local ret, nfsobj = "", NFS:new()

    if nfsobj:AccessRead(mask, version) ~= 0 then
      ret = "Read "
    else
      ret = "NoRead "
    end

    if nfsobj:AccessLookup(mask, version) ~= 0 then
      ret = ret .. "Lookup "
    else
      ret = ret .. "NoLookup "
    end

    if nfsobj:AccessModify(mask, version) ~= 0 then
      ret = ret .. "Modify "
    else
      ret = ret .. "NoModify "
    end

    if nfsobj:AccessExtend(mask, version) ~= 0 then
      ret = ret .. "Extend "
    else
      ret = ret .. "NoExtend "
    end

    if nfsobj:AccessDelete(mask, version) ~= 0 then
      ret = ret .. "Delete "
    else
      ret = ret .. "NoDelete "
    end

    if nfsobj:AccessExecute(mask, version) ~= 0 then
      ret = ret .. "Execute"
    else
      ret = ret .. "NoExecute"
    end

    return ret
  end,

  --- Return the pathconf filesystem table
  --
  -- @param pconf table returned by the NFSv3 PATHCONF call
  -- @param nfsversion the version of the remote NFS server
  -- @return fs table that contains the remote filesystem
  --         pathconf information.
  calc_pathconf_table = function(pconf, nfsversion)
    local fs = {}
    if nfsversion ~= 3 then
      return nil, "ERROR: unsupported NFS version."
    end

    fs.linkmax = pconf.linkmax
    fs.name_max = pconf.name_max

    if pconf.chown_restricted then
      fs.chown_restricted = "True"
    else
      fs.chown_restricted = "False"
    end

    return fs, nil
  end,

  --- Calculate and return the fsinfo filesystem table
  --
  -- @param fsinfo table returned by the NFSv3 FSINFO call
  -- @param nfsversion the version of the remote NFS server
  -- @param human if set show the size in the human
  --        readable format.
  -- @return fs table that contains the remote filesystem
  --         information.
  calc_fsinfo_table = function(fsinfo, nfsversion, human)
    local fs = {}
    local nfsobj = NFS:new()
    if nfsversion ~= 3 then
      return nil, "ERROR: unsupported NFS version."
    end

    fs.maxfilesize = Util.SizeToHuman(fsinfo.maxfilesize)

    if nfsobj:FSinfoLink(fsinfo.properties, nfsversion) ~= 0 then
      fs.link = "True"
    else
      fs.link = "False"
    end

    if nfsobj:FSinfoSymlink(fsinfo.properties, nfsversion) ~= 0 then
      fs.symlink = "True"
    else
      fs.symlink = "False"
    end

    return fs, nil
  end,

  --- Calculate and return the fsstat filesystem table
  --
  -- @param stats table returned by the NFSv3 FSSTAT or
  --        NFSv2 STATFS calls
  -- @param nfsversion the version of the remote NFS server
  -- @param human if set show the size in the human
  --        readable format.
  -- @return df table that contains the remote filesystem
  --         attributes.
  calc_fsstat_table = function(stats, nfsversion, human)
    local df, base = {}, 1024
    local size, free, total, avail, used, use
    if (nfsversion == 3) then
      free = stats.fbytes
      size = stats.tbytes
      avail = stats.abytes
    elseif (nfsversion == 2) then
      df.bsize = stats.block_size
      free = stats.free_blocks * df.bsize
      size = stats.total_blocks * df.bsize
      avail = stats.available_blocks * df.bsize
    else
      return nil, "ERROR: unsupported NFS version."
    end

    if (human) then
      if (df.bsize) then
        df.bsize = Util.SizeToHuman(df.bsize)
      end
      df.size = Util.SizeToHuman(size)
      df.available = Util.SizeToHuman(avail)
      used = size - free
      avail = avail
      df.used = Util.SizeToHuman(used)
      total = used + avail
    else
      free = free / base
      df.size = size / base
      df.available = avail / base
      used = df.size - free
      df.used = used
      total = df.used + df.available
    end

    use = math.ceil(used * 100 / total)
    df.use = string.format("%.0f%%", use)
    return df, nil
  end,

  --- Converts a RPC program name to its equivalent number
  --
  -- @param prog_name string containing the name of the RPC program
  -- @return num number containing the program ID
  ProgNameToNumber = function(prog_name)
    local status

    if not( RPC_PROGRAMS ) then
      status, RPC_PROGRAMS = datafiles.parse_rpc()
      if ( not(status) ) then
        return
      end
    end
    if not RPC_NUMBERS then
      RPC_NUMBERS = tableaux.invert(RPC_PROGRAMS)
    end
    return RPC_NUMBERS[prog_name]
  end,

  --- Converts the RPC program number to its equivalent name
  --
  -- @param num number containing the RPC program identifier
  -- @return string containing the RPC program name
  ProgNumberToName = function( num )
    local status

    if not( RPC_PROGRAMS ) then
      status, RPC_PROGRAMS = datafiles.parse_rpc()
      if ( not(status) ) then
        return
      end
    end
    return RPC_PROGRAMS[num]
  end,

  --
  -- Calculates the number of fill bytes needed
  -- @param length contains the length of the string
  -- @return the amount of pad needed to be dividable by 4
  CalcFillBytes = function(length)
    -- calculate fill bytes
    if math.fmod( length, 4 ) ~= 0 then
      return (4 - math.fmod( length, 4))
    else
      return 0
    end
  end
}

return _ENV;
