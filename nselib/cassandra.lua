---
-- Library methods for handling Cassandra Thrift communication as client
--
-- @author Vlatko Kosturjak
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
--
-- Version 0.1
--

local stdnse = require "stdnse"
local string = require "string"
_ENV = stdnse.module("cassandra", stdnse.seeall)

--[[

  Cassandra Thrift protocol implementation.

  For more information about Cassandra, see:

  http://cassandra.apache.org/

]]--

-- Protocol magic strings
CASSANDRAREQ = "\x80\x01\x00\x01"
CASSANDRARESP = "\x80\x01\x00\x02"
CASSLOGINMAGIC = "\x00\x00\x00\x01\x0c\x00\x01\x0d\x00\x01\x0b\x0b\x00\x00\x00\x02"
LOGINSUCC = "\x00\x00\x00\x01\x00"
LOGINFAIL = "\x00\x00\x00\x01\x0b"
LOGINACC = "\x00\x00\x00\x01\x0c"

--Returns string in cassandra format for login
--@param username to put in format
--@param password to put in format
--@return str : string in cassandra format for login
function loginstr (username, password)
  return CASSANDRAREQ
  .. string.pack(">s4", "login")
  .. CASSLOGINMAGIC
  .. string.pack(">s4s4s4s4", "username", username, "password", password)
  .. "\x00\x00" -- add two null on the end
end

--Invokes command over socket and returns the response
--@param socket to connect to
--@param command to invoke
--@param cnt is protocol count
--@return status : true if ok; false if bad
--@return result : value if status ok, error msg if bad
function cmdstr (command,cnt)
  return CASSANDRAREQ
  .. string.pack(">s4I4", command, cnt)
  .. "\x00" -- add null on the end
end

--Invokes command over socket and returns the response
--@param socket to connect to
--@param command to invoke
--@param cnt is protocol count
--@return status : true if ok; false if bad
--@return result : value if status ok, error msg if bad
function sendcmd (socket, command, cnt)
  local cmdstr = cmdstr (command,cnt)
  local response

  local status, err = socket:send(string.pack(">I4", #cmdstr))
  if ( not(status) ) then
    return false, "error sending packet length"
  end

  status, err = socket:send(cmdstr)
  if ( not(status) ) then
    return false, "error sending packet payload"
  end

  status, response = socket:receive_bytes(4)
  if ( not(status) ) then
          return false, "error receiving length"
  end
  local size = string.unpack(">I4", response)

  if #response < size + 4 then
    local resp2
    status, resp2 = socket:receive_bytes(size + 4 - #response)
    if ( not(status) ) then
      return false, "error receiving payload"
    end
    response = response .. resp2
  end

  -- magic response starts at 5th byte for 4 bytes, 4 byte for length + length of string command
  if response:sub(5, 8 + 4 + #command) ~= CASSANDRARESP .. string.pack(">s4", command) then
    return false, "protocol response error"
  end

  return true, response
end

--Return Cluster Name
--@param socket to connect to
--@param cnt is protocol count
--@return status : true if ok; false if bad
--@return result : value if status ok, error msg if bad
function describe_cluster_name (socket,cnt)
  local cname = "describe_cluster_name"
  local status,resp = sendcmd(socket,cname,cnt)

  if (not(status)) then
    stdnse.debug1("sendcmd"..resp)
    return false, "error in communication"
  end

  -- grab the size
  -- pktlen(4) + CASSANDRARESP(4) + lencmd(4) + lencmd(v) + params(7) + next byte position
  local position = 12 + #cname + 7 + 1
  local value = string.unpack(">s4", resp, position)
  return true, value
end

--Return API version
--@param socket to connect to
--@param cnt is protocol count
--@return status : true if ok; false if bad
--@return result : value if status ok, error msg if bad
function describe_version (socket,cnt)
  local cname = "describe_version"
  local status,resp = sendcmd(socket,cname,cnt)

  if (not(status)) then
    stdnse.debug1("sendcmd"..resp)
    return false, "error in communication"
  end

  -- grab the size
  -- pktlen(4) + CASSANDRARESP(4) + lencmd(4) + lencmd(v) + params(7) + next byte position
  local position = 12 + #cname + 7 + 1
  local value = string.unpack(">s4", resp, position)
  return true, value
end

--Login to Cassandra
--@param socket to connect to
--@param username to connect to
--@param password to connect to
--@return status : true if ok; false if bad
--@return result : table of status ok, error msg if bad
--@return if status ok : remaining data read from socket but not used
function login (socket,username,password)
  local loginstr = loginstr (username, password)
  local combo = username..":"..password

  local status, err = socket:send(string.pack(">I4", #loginstr))
  if ( not(status) ) then
          stdnse.debug3("cannot send len "..combo)
          return false, "Failed to connect to server"
  end

  status, err = socket:send(loginstr)
  if ( not(status) ) then
          stdnse.debug3("Sent packet for "..combo)
          return false, err
  end

  local response
  status, response = socket:receive_bytes(22)
  if ( not(status) ) then
          stdnse.debug3("Receive packet for "..combo)
          return false, err
  end
  local size = string.unpack(">I4", response)

  local loginresp = string.sub(response,5,17)
  if (loginresp ~= CASSANDRARESP .. string.pack(">s4", "login")) then
    return false, "protocol error"
  end

  local magic = string.sub(response,18,22)
  stdnse.debug3("packet for "..combo)
  stdnse.debug3("packet hex: %s", stdnse.tohex(response) )
  stdnse.debug3("size packet hex: %s", stdnse.tohex(size) )
  stdnse.debug3("magic packet hex: %s", stdnse.tohex(magic) )

  if (magic == LOGINSUCC) then
    return true
  else
    return false, "Login failed."
  end
end

return _ENV;
