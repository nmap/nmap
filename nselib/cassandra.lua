---
-- Library methods for handling Cassandra Thrift communication as client
--
-- @author Vlatko Kosturjak
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
--
-- Version 0.1
--

local bin = require "bin"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("cassandra", stdnse.seeall)

--[[

  Cassandra Thrift protocol implementation. 

  For more information about Cassandra, see:

  http://cassandra.apache.org/

]]--

-- Protocol magic strings
CASSANDRAREQ = string.char(0x80,0x01,0x00,0x01)
CASSANDRARESP = string.char(0x80,0x01,0x00,0x02)
CASSLOGINMAGIC = string.char(0x00, 0x00,0x00,0x01,0x0c,0x00,0x01,0x0d,0x00,0x01,0x0b,0x0b,0x00,0x00,0x00,0x02)
LOGINSUCC = string.char(0x00,0x00,0x00,0x01,0x00)
LOGINFAIL = string.char(0x00,0x00,0x00,0x01,0x0b)
LOGINACC = string.char(0x00,0x00,0x00,0x01,0x0c)

--Returns string in format length+string itself
--@param str to format
--@return str : string in format length+string itself
function pack4str (str)
        return (bin.pack(">I",string.len(str)) .. str)
end

--Returns string in cassandra format for login
--@param username to put in format
--@param password to put in format
--@return str : string in cassandra format for login
function loginstr (username, password) 
        local str = CASSANDRAREQ .. pack4str ("login")
        str = str .. CASSLOGINMAGIC
        str = str .. pack4str("username")
        str = str .. pack4str(username)
        str = str .. pack4str("password")
        str = str .. pack4str(password)
        str = str .. string.char (0x00, 0x00) -- add two null on the end
        return str
end

--Invokes command over socket and returns the response
--@param socket to connect to
--@param command to invoke
--@param cnt is protocol count
--@return status : true if ok; false if bad
--@return result : value if status ok, error msg if bad
function cmdstr (command,cnt) 
        local str = CASSANDRAREQ .. pack4str (command)
        str = str .. bin.pack(">I",cnt)
        str = str .. string.char (0x00) -- add null on the end
        return str
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

  local status, err = socket:send(bin.pack(">I",string.len(cmdstr)))
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
  local  _,size = bin.unpack(">I",response,1)

  if (string.len(response) < size+4 ) then
    local resp2
    status, resp2 = socket:receive_bytes(size+4 - string.len(response))
    if ( not(status) ) then
            return false, "error receiving payload"
    end
    response = response .. resp2
  end

  -- magic response starts at 5th byte for 4 bytes, 4 byte for length + length of string commmand
  if (string.sub(response,5,8+4+string.len(command)) ~= CASSANDRARESP..pack4str(command)) then  
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
    stdnse.print_debug(1, "sendcmd"..resp)
    return false, "error in communication"
  end

  -- grab the size
  -- pktlen(4) + CASSANDRARESP(4) + lencmd(4) + lencmd(v) + params(7) + next byte position
  local position = 12+string.len(cname)+7+1
  local _,size = bin.unpack(">I",resp,position)

  -- read the string after the size
  local value = string.sub(resp,position+4,position+4+size-1)
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
    stdnse.print_debug(1, "sendcmd"..resp)
    return false, "error in communication"
  end

  -- grab the size
  -- pktlen(4) + CASSANDRARESP(4) + lencmd(4) + lencmd(v) + params(7) + next byte position
  local position = 12+string.len(cname)+7+1
  local _,size = bin.unpack(">I",resp,position)

  -- read the string after the size
  local value = string.sub(resp,position+4,position+4+size-1)
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

  local status, err = socket:send(bin.pack(">I",string.len(loginstr)))
  if ( not(status) ) then
          stdnse.print_debug(3, "cannot send len "..combo)
          return false, "Failed to connect to server"
  end

  status, err = socket:send(loginstr)
  if ( not(status) ) then
          stdnse.print_debug(3, "Sent packet for "..combo)
          return false, err
  end

  local response
  status, response = socket:receive_bytes(22)
  if ( not(status) ) then
          stdnse.print_debug(3, "Receive packet for "..combo)
          return false, err
  end
  local _, size = bin.unpack(">I", response, 1)

  local loginresp = string.sub(response,5,17)
  if (loginresp ~= CASSANDRARESP..pack4str("login")) then  
    return false, "protocol error"
  end

  local magic = string.sub(response,18,22)
  stdnse.print_debug(3, "packet for "..combo)
  stdnse.print_debug(3, "packet hex: %s", stdnse.tohex(response) )
  stdnse.print_debug(3, "size packet hex: %s", stdnse.tohex(size) )
  stdnse.print_debug(3, "magic packet hex: %s", stdnse.tohex(magic) )

  if (magic == LOGINSUCC) then
    return true
  else
    return false, "Login failed."
  end
end 

return _ENV;
