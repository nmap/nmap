local brute = require "brute"
local bin = require "bin"
local creds = require "creds"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

local have_zlib, zlib = pcall(require, "zlib")

description = [[
Performs brute force password auditing against the DelugeRPC daemon.
]]

---
-- @usage
-- nmap --script deluge-rpc-brute -p 58846 <host>
--
-- @output
-- PORT      STATE SERVICE REASON  TTL
-- 58846/tcp open  unknown syn-ack 0
-- | deluge-rpc-brute:
-- |   Accounts
-- |     admin:default - Valid credentials
-- |   Statistics
-- |_    Performed 8 guesses in 1 seconds, average tps: 8

author = "Claudiu Perta <claudiu.perta@gmail.com>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service(58846, "deluge-rpc")

-- Returns an rencoded login request with the given username and password.
-- The format of the login command is the following:
--
-- ((0, 'daemon.login', ('username', 'password'), {}),)
--
-- This is inspired from deluge source code, in particular, see
-- http://git.deluge-torrent.org/deluge/tree/deluge/rencode.py
local rencoded_login_request = function(username, password)
  local INT_POS_FIXED_START = 0
  local INT_POS_FIXED_COUNT = 44

  -- Dictionaries with length embedded in typecode.
  local DICT_FIXED_START = 102
  local DICT_FIXED_COUNT = 25

  -- Strings with length embedded in typecode.
  local STR_FIXED_START = 128
  local STR_FIXED_COUNT = 64

  -- Lists with length embedded in typecode.
  local LIST_FIXED_START = 192
  local LIST_FIXED_COUNT = 64

  if #username > 0xff - STR_FIXED_START then
    return nil, "Username too long"
  elseif #password > 0xff - STR_FIXED_START then
    return nil, "Password too long"
  end

  -- Encode the login request:
  -- ((0, 'daemon.login', ('username', 'password'), {}),)
  local request = bin.pack("CCCCACCACAC",
    LIST_FIXED_START + 1,
    LIST_FIXED_START + 4,
    INT_POS_FIXED_START,
    STR_FIXED_START + string.len("daemon.login"),
    "daemon.login",
    LIST_FIXED_START + 2,
    STR_FIXED_START + string.len(username),
    username,
    STR_FIXED_START + string.len(password),
    password,
    DICT_FIXED_START
  )
  return request
end

Driver = {

  new = function(self, host, port, invalid_users)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    o.invalid_users = invalid_users
    return o
  end,

  connect = function(self)
    local status, err
    self.socket = brute.new_socket()
    self.socket:set_timeout(
      ((self.host.times and self.host.times.timeout) or 8) * 1000)

    local status, err = self.socket:connect(self.host, self.port, "ssl")
    if not status then
      return false, brute.Error:new("Failed to connect to server")
    end

    return true
  end,

  disconnect = function(self)
    self.socket:close()
  end,

  login = function(self, username, password)
    if (self.invalid_users[username]) then
      return false, brute.Error:new("Invalid user")
    end

    local request, err = rencoded_login_request(username, password)
    if not request then
      return false, brute.Error:new(err)
    end
    local status, err = self.socket:send(zlib.compress(request))

    if not status then
      return false, brute.Error:new("Login error")
    end

    local status, response = self.socket:receive()
    if not status  then

      return false, brute.Error:new("Login error")
    end

    response = zlib.decompress(response)
    if response:match("BadLoginError") then
      local error_message = "Login error"
      if response:match("Username does not exist") then
        self.invalid_users[username] = true
        error_message = "Username not found"
      elseif response:match("Password does not match") then
        error_message = "Username not found"
      end
      return false, brute.Error:new(error_message)
    end

    return true, brute.Account:new(username, password, creds.State.VALID)
  end,

  check = function(self)
    return true
  end
}

action = function(host, port)

  if not have_zlib then
    return "Error: zlib required!"
  end

  local invalid_users = {}
  local engine = brute.Engine:new(Driver, host, port, invalid_users)

  engine.options.script_name = SCRIPT_NAME
  local status, results = engine:start()

  return results
end
