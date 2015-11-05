local brute = require "brute"
local comm = require "comm"
local creds = require "creds"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

local openssl = stdnse.silent_require "openssl"

description=[[
Performs brute force password auditing against a Metasploit RPC server using the XMLRPC protocol.
]]

---
-- @usage
-- nmap --script metasploit-xmlrpc-brute -p 55553 <host>
--
-- @output
-- PORT      STATE SERVICE
-- 55553/tcp open  unknown
-- | metasploit-xmlrpc-brute:
-- |   Accounts
-- |     password - Valid credentials
-- |   Statistics
-- |_    Performed 243 guesses in 2 seconds, average tps: 121
--

author = "Vlatko Kosturjak"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


portrule = shortport.port_or_service(55553, "metasploit-xmlrpc", "tcp")

Driver =
{
  new = function (self, host, port, opts)
    local o = { host = host, port = port, opts = opts }
    setmetatable (o,self)
    self.__index = self
    return o
  end,

  connect = function ( self )
    self.socket = nmap.new_socket()
    if ( not(self.socket:connect(self.host, self.port, self.opts)) ) then
      return false
    end
    return true
  end,

  login = function( self, username, password )
    local xmlreq='<?xml version="1.0" ?><methodCall><methodName>auth.login</methodName><params><param><value><string>'..username..'</string></value></param><param><value><string>'..password.."</string></value></param></params></methodCall>\n\0"
    local status, err = self.socket:send(xmlreq)

    if ( not ( status ) ) then
      local err = brute.Error:new( "Unable to send handshake" )
      err:setAbort(true)
      return false, err
    end

    -- Create a buffer and receive the first line
    local response
    status, response = self.socket:receive_buf("\r?\n", false)

    if (response == nil or string.match(response,"<name>faultString</name><value><string>authentication error</string>")) then
      stdnse.debug2("Bad login: %s/%s", username, password)
      return false, brute.Error:new( "Bad login" )
    elseif (string.match(response,"<name>result</name><value><string>success</string></value>")) then

      stdnse.debug1("Good login: %s/%s", username, password)
      return true, creds.Account:new(username, password, creds.State.VALID)
    end
    stdnse.debug1("WARNING: Unhandled response: %s", response)
    return false, brute.Error:new( "unhandled response" )
  end,

  disconnect = function( self )
    self.socket:close()
  end,
}

action = function(host, port)

  -- first determine whether we need SSL or not
  local xmlreq='<?xml version="1.0" ?><methodCall><methodName>core.version</methodName></methodCall>\n\0'
  local socket, _, opts = comm.tryssl(host, port, xmlreq, { recv_first = false } )
  if ( not(socket) ) then
    return stdnse.format_output(false, "Failed to determine whether SSL was needed or not")
  end

  local engine = brute.Engine:new(Driver, host, port, opts)
  engine.options.script_name = SCRIPT_NAME
  engine.options.firstonly = true
  local status, result = engine:start()
  return result
end

