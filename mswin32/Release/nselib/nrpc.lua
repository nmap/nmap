--- A minimalistic library to support Domino RPC
--
-- Summary
-- -------
-- The library currently only supports user enumeration and uses chunks of
-- captured data to do so.
--
-- Overview
-- --------
-- The library contains the following classes:
--
--   o DominoPacket
--    - The packet class holding the packets sent between the client and the
--        IBM Lotus Domino server
--
--   o Helper
--    - A helper class that provides easy access to the rest of the library
--
-- Example
-- -------
-- The following sample code illustrates how scripts can use the Helper class
-- to interface the library:
--
-- <code>
--  helper = nrpc.Helper:new(host, port)
--  status, err = nrpc:Connect()
--  status, res = nrpc:isValidUser("Patrik Karlsson")
--  status, err = nrpc:Close()
-- </code>
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @author Patrik Karlsson <patrik@cqure.net>
--

--
-- Version 0.1
-- Created 07/23/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--


local bin = require "bin"
local match = require "match"
local nmap = require "nmap"
local stdnse = require "stdnse"
_ENV = stdnse.module("nrpc", stdnse.seeall)

-- The Domino Packet
DominoPacket = {

  --- Creates a new DominoPacket instance
  --
  -- @param data string containing the packet data
  -- @return a new DominoPacket instance
  new = function( self, data )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.data = data
    return o
  end,

  --- Reads a packet from the socket
  --
  -- @param domsock socket connected to the server
  -- @return Status (true or false).
  -- @return Error code (if status is false).
  read = function( self, domsock )
    local status, data = domsock:receive_buf(match.numbytes(2), true)
    local pos, len = bin.unpack( "<S", data )

    return domsock:receive_buf(match.numbytes(len), true)
  end,

  --- converts the packet to a string
  __tostring = function(self)
    return bin.pack("<SA", #self.data, self.data )
  end,

}

Helper = {

  --- Creates a new Helper instance
  --
  -- @param host table as received by the script action method
  -- @param port table as received by the script action method
  new = function(self, host, port)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    o.domsock = nmap.new_socket()
    return o
  end,

  --- Connects the socket to the Domino server
  --
  -- @return status true on success, false on failure
  -- @return err error message if status is false
  connect = function( self )
    self.domsock:set_timeout(5000)
    if( not( self.domsock:connect( self.host.ip, self.port.number, "tcp" ) ) ) then
      return false, ("ERROR: Failed to connect to Domino server %s:%d\n"):format(self.host, self.port)
    end
    return true
  end,

  --- Disconnects from the Lotus Domino Server
  --
  -- @return status true on success, false on failure
  -- @return err error message if status is false
  disconnect = function( self )
    return self.domsock:close()
  end,

  --- Attempt to check whether the user exists in Domino or not
  --
  -- @param username string containing the user name to guess
  -- @return status true on success false on failure
  -- @return domino_id if it exists and status is true
  --         err if status is false
  isValidUser = function( self, username )
    local data = bin.pack("H", "00001e00000001000080000007320000700104020000fb2b2d00281f1e000000124c010000000000")
    local status, id_data
    local data_len, pos, total_len, pkt_type, valid_user

    self.domsock:send( tostring(DominoPacket:new( data )) )
    data = DominoPacket:new():read( self.domsock )

    data = bin.pack("HCHAH", "0100320002004f000100000500000900", #username + 1, "000000000000000000000000000000000028245573657273290000", username, "00")
    self.domsock:send( tostring(DominoPacket:new( data ) ) )
    status, id_data = DominoPacket:new():read( self.domsock )

    pos, pkt_type = bin.unpack("C", id_data, 3)
    pos, valid_user = bin.unpack("C", id_data, 11)
    pos, total_len = bin.unpack("<S", id_data, 13)

    if ( pkt_type == 0x16 ) then
      if ( valid_user == 0x19 ) then
        return true
      else
        return false
      end
    end

    if ( pkt_type ~= 0x7e ) then
      return false, "Failed to retrieve ID file"
    end

    status, data = DominoPacket:new():read( self.domsock )

    id_data = id_data:sub(33) .. data:sub(11, total_len - #id_data + 11)

    return true, id_data
  end,

}

return _ENV;
