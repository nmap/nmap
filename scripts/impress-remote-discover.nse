local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

-- -*- mode: lua -*-
-- vim: set filetype=lua :

description = [[
Tests for the presence of the LibreOffice Impress Remote server.
]]

---
-- @usage
-- nmap --script impress-remote-discover -p 1599 <host>
--
-- @args impress-remote-discover.pin PIN number for the remote (default is
--       <code>0000</code>).
--
-- @args impress-remote-discover.bruteforce Boolean to enable bruteforcing the PIN (default is
--       <code>false</code>).
--
-- @output
-- PORT   STATE SERVICE
-- 1599/tcp open  LibreOffice Impress
-- | impress-remote-discover:
-- |   Command: id
-- |   Results: uid=0(root) gid=0(wheel) groups=0(wheel)
-- |_

author = "Jer Hiebert"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit", "intrusive", "malware", "vuln"}

local function parse_args()
  local args = {}

  local pin = stdnse.get_script_args(SCRIPT_NAME .. '.pin')
  if pin then
    -- Sanity check the value from the user.
    pin = tonumber(pin)
    if type(pin) ~= "number" then
      return false, "pin argument must be a number."
    elseif pin < 0 or pin > 9999 then
      return false, "pin argument must be in range between 0000 and 9999 inclusive."
    end
  else
    -- Default the pin to 0.
    pin = 0
  end
  -- Pad the pin with zeros to make it four digits.
  pin = string.format("%04d", pin)
  args.pin = pin

  local bruteforce = stdnse.get_script_args(SCRIPT_NAME .. '.bruteforce')
  if bruteforce then
    -- Sanity check the value from the user.
    if type(bruteforce) ~= "string" then
      return false, "bruteforce argument must be a string."
    elseif bruteforce ~= "true" then
      return false, "bruteforce argument must be either true or left out entirely."
    end
  else
    -- Default bruteforce to false.
    bruteforce = false
  end
  args.bruteforce = bruteforce

  return true, args
end

local remote_connect = function(host, port, pin)
  local socket = nmap.new_socket()
  local result;
  local status = true;

  socket:connect(host, port)
  socket:set_timeout(5000)

  local buffer, err = stdnse.make_buffer(socket, "\n")
  if err then
    stdnse.debug1("Failed to create buffer from socket: %s", err)
    return
  end
  socket:send("LO_SERVER_CLIENT_PAIR\nFirefox OS\n"..pin.."\n\n")

  return buffer, socket
end

local remote_version = function(buffer, socket, pin)
  for j=0,3 do
    line, err = buffer()
    if not line then
      stdnse.debug1("Failed to receive line from socket: %s", err)
      return
    end

    if string.match(line, "^LO_SERVER_INFO$") then
      line, err = buffer()
      stdnse.debug1("Here's the version: %s", line)
      return "Remote PIN: "..pin.."\nImpress Version: "..line
    end
  end
end

local check_pin = function(host, port, pin)
  local buffer, socket = remote_connect(host, port, pin)

  line, err = buffer()
  if not line then
    stdnse.debug1("Failed to receive line from socket: %s", err)
    socket:close()
    return line, err
  elseif string.match(line, "^LO_SERVER_SERVER_PAIRED$") then
    return remote_version(buffer, socket, pin)
  end
  socket:close()
  
  return "Remote Server present but incorrect PIN"
end

local bruteforce = function(host, port)
  for i=0,9999 do
    local pin = string.format("%04d", i)
    local buffer, socket = remote_connect(host, port, pin)

    line, err = buffer()
    if not line then
      stdnse.debug1("Failed to receive line from socket: %s", err)
      socket:close()
      return line, err
    elseif string.match(line, "^LO_SERVER_SERVER_PAIRED$") then
      return remote_version(buffer, socket, pin)
    end
    socket:close()
  end

  return "Failed to bruteforce PIN"
end

portrule = shortport.port_or_service(1599, "libreoffice-impress-remote", "tcp")

action = function(host, port)
  local result
    -- Parse and sanity check the command line arguments.
  local status, options = parse_args()
  if not status then
    return
  end

  if options.bruteforce then
    result = bruteforce(host, port)
  else
    result = check_pin(host, port, options.pin)
  end

  if not result then
  	return
  end

  return stdnse.format_output(true, result)
end