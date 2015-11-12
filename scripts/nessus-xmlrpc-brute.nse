local brute = require "brute"
local creds = require "creds"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description=[[
Performs brute force password auditing against a Nessus vulnerability scanning daemon using the XMLRPC protocol.
]]

---
-- @output
-- PORT     STATE SERVICE REASON
-- 8834/tcp open  unknown syn-ack
-- | nessus-xmlrpc-brute:
-- |   Accounts
-- |     nessus:nessus - Valid credentials
-- |   Statistics
-- |_    Performed 1933 guesses in 26 seconds, average tps: 73
--
-- @args nessus-xmlrpc-brute.threads sets the number of threads.
-- @args nessus-xmlrpc-brute.timeout socket timeout for connecting to Nessus (default 5s)

author = "Patrik Karlsson"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"intrusive", "brute"}


portrule = shortport.port_or_service(8834, "ssl/http", "tcp")

local arg_timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME..'.timeout'))
arg_timeout = (arg_timeout or 5) * 1000
local arg_threads = stdnse.get_script_args("nessus-xmlrpc-brute.threads")

local function authenticate(host, port, username, password)
  local post_data = ("login=%s&password=%s"):format(username, password)

  local headers = {
    "POST /login HTTP/1.1",
    "User-Agent: Nmap",
    ("Host: %s:%d"):format(host.ip, port.number),
    "Accept: */*",
    ("Content-Length: %d"):format(#post_data),
    "Content-Type: application/x-www-form-urlencoded",
  }

  local data = table.concat(headers, "\r\n") .. "\r\n\r\n" .. post_data
  local socket = nmap.new_socket()
  socket:set_timeout(arg_timeout)

  local status, err = socket:connect(host, port)
  if ( not(status) ) then
    return false, "Failed to connect to server"
  end
  local status, err = socket:send(data)
  if ( not(status) ) then
    return false, "Failed to send request to server"
  end
  local status, response = socket:receive()
  socket:close()
  if ( not(status) ) then
    return false, "Failed to receive response from server"
  end
  return status, response
end

Driver =
{
  new = function (self, host, port )
    local o = { host = host, port = port }
    setmetatable (o,self)
    self.__index = self
    return o
  end,

  connect = function ( self ) return true end,

  login = function( self, username, password )

    local status, response = authenticate(self.host, self.port, username, password)
    if ( status and response ) then
      if ( response:match("^HTTP/1.1 200 OK.*<status>OK</status>") ) then
        return true, creds.Account:new(username, password, creds.State.VALID)
      elseif ( response:match("^HTTP/1.1 200 OK.*<status>ERROR</status>") ) then
        return false, brute.Error:new("incorrect login")
      end
    end
    local err = brute.Error:new( "incorrect response from server" )
    err:setRetry(true)
    return false, err
  end,

  disconnect = function( self ) return true end,
}

local function fail(err) return stdnse.format_output(false, err) end

action = function(host, port)

  local status, response = authenticate(host, port, "nmap-ssl-test-probe", "nmap-ssl-test-probe")
  if ( not(status) ) then
    return fail(response)
  end
  -- patch the protocol due to the ugly way the Nessus web server works.
  -- The server answers non-ssl connections as legitimate http stating that
  -- the server should be connected to using https on the same port. ugly.
  if ( status and response:match("^HTTP/1.1 400 Bad request\r\n") ) then
    port.protocol = "ssl"
    status, response = authenticate(host, port, "nmap-ssl-test-probe", "nmap-ssl-test-probe")
    if ( not(status) ) then
      return fail(response)
    end
  end

  if ( not(response:match("^HTTP/1.1 200 OK.*Server: NessusWWW.*<status>ERROR</status>")) ) then
    return fail("Failed to detect Nessus Web server")
  end

  local engine = brute.Engine:new(Driver, host, port)
  if ( arg_threads ) then
    engine:setMaxThreads(arg_threads)
  end
  engine.options.script_name = SCRIPT_NAME
  local result
  status, result = engine:start()
  return result
end
