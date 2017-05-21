local bin = require "bin"
local brute = require "brute"
local creds = require "creds"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local cassandra = require "cassandra"

description = [[
Performs brute force password auditing against the Cassandra database.

For more information about Cassandra, see:
http://cassandra.apache.org/
]]

---
-- @usage
-- nmap -p 9160 <ip> --script=cassandra-brute
--
-- @output
-- PORT     STATE SERVICE VERSION
-- 9160/tcp open  apani1?
-- | cassandra-brute:
-- |   Accounts
-- |     admin:lover - Valid credentials
-- |   Statistics
-- |_    Performed 4581 guesses in 1 seconds, average tps: 4581
--

author = "Vlatko Kosturjak"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service({9160}, {"cassandra"})

Driver = {

  new = function(self, host, port, options)
    local o = { host = host, port = port, socket = nmap.new_socket() }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  connect = function(self)
    return self.socket:connect(self.host, self.port)
  end,

  -- bit faster login function than in cassandra library (no protocol error checks)
  login = function(self, username, password)
    local response, magic, size, _
    local loginstr = cassandra.loginstr (username, password)

    local status, err = self.socket:send(bin.pack(">I",string.len(loginstr)))
    local combo = username..":"..password
    if ( not(status) ) then
      local err = brute.Error:new( "couldn't send length:"..combo )
      err:setAbort( true )
      return false, err
    end

    status, err = self.socket:send(loginstr)
    if ( not(status) ) then
      local err = brute.Error:new( "couldn't send login packet: "..combo )
      err:setAbort( true )
      return false, err
    end

    status, response = self.socket:receive_bytes(22)
    if ( not(status) ) then
      local err = brute.Error:new( "couldn't receive login reply size: "..combo )
      err:setAbort( true )
      return false, err
    end

    _, size = bin.unpack(">I", response, 1)

    magic = string.sub(response,18,22)

    if (magic == cassandra.LOGINSUCC) then
      stdnse.debug3("Account SUCCESS: "..combo)
      return true, creds.Account:new(username, password, creds.State.VALID)
    elseif (magic == cassandra.LOGINFAIL) then
      stdnse.debug3("Account FAIL: "..combo)
      return false, brute.Error:new( "Incorrect password" )
    elseif (magic == cassandra.LOGINACC) then
      stdnse.debug3("Account VALID, but wrong password: "..combo)
      return false, brute.Error:new( "Good user, bad password" )
    else
      stdnse.debug3("Unrecognized packet for "..combo)
      stdnse.debug3("packet hex: %s", stdnse.tohex(response) )
      stdnse.debug3("size packet hex: %s", stdnse.tohex(size) )
      stdnse.debug3("magic packet hex: %s", stdnse.tohex(magic) )
      local err = brute.Error:new( response )
      err:setRetry( true )
      return false, err
    end
  end,

  disconnect = function(self)
    return self.socket:close()
  end,

}

local function noAuth(host, port)
  local socket = nmap.new_socket()
  local status, result = socket:connect(host, port)

  local stat,err = cassandra.login (socket,"default","")
  socket:close()
  if (stat) then
    return true
  else
    return false
  end
end

action = function(host, port)

  if ( noAuth(host, port) ) then
    return "Any username and password would do, 'default' was used to test."
  end

  local engine = brute.Engine:new(Driver, host, port )

  engine.options.script_name = SCRIPT_NAME
  engine.options.firstonly = true
  local status, result = engine:start()

  return result
end
