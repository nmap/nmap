local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Tests for the presence of the LibreOffice Impress Remote server.
Checks if a PIN is valid if provided and will bruteforce the PIN
if requested.

When a remote first contacts Impress and sends a client name and PIN, the user
must open the "Slide Show -> Impress Remote" menu and enter the matching PIN at
the prompt, which shows the client name. Subsequent connections with the same
client name may then use the same PIN without user interaction.  If no PIN has
been set for the session, each PIN attempt will result in a new prompt in the
"Impress Remote" menu. Brute-forcing the PIN, therefore, requires that the user
has entered a PIN for the same client name, and will result in lots of extra
prompts in the "Impress Remote" menu.
]]

---
-- @usage nmap -p 1599 --script impress-remote-discover <host>
--
-- @output
-- PORT     STATE SERVICE        Version
-- 1599/tcp open  impress-remote LibreOffice Impress remote 4.3.3.2
-- | impress-remote-discover:
-- |   Impress Version: 4.3.3.2
-- |   Remote PIN: 0000
-- |_  Client Name used: Firefox OS
--
-- @args impress-remote-discover.bruteforce No value needed (default is
--       <code>false</code>).
--
-- @args impress-remote-discover.client String value of the client name
--       (default is <code>Firefox OS</code>).
--
-- @args impress-remote-discover.pin PIN number for the remote (default is
--       <code>0000</code>).

author = "Jer Hiebert"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service(1599, "impress-remote", "tcp")

local function parse_args()
  local args = {}

  local client_name = stdnse.get_script_args(SCRIPT_NAME .. ".client")
  if client_name then
    stdnse.debug("Client name provided: %s", client_name)
    -- Sanity check the value from the user.
    if type(client_name) ~= "string" then
      return false, "Client argument must be a string."
    end
  end
  args.client_name = client_name or "Firefox OS"

  local bruteforce = stdnse.get_script_args(SCRIPT_NAME .. ".bruteforce")
  if bruteforce and bruteforce ~= "false" then
    -- accept any value but false.
    bruteforce = true
  else
    bruteforce = false
  end
  args.bruteforce = bruteforce or false

  local pin = stdnse.get_script_args(SCRIPT_NAME .. ".pin")
  if pin then
    -- Sanity check the value from the user.
    pin = tonumber(pin)
    if type(pin) ~= "number" then
      return false, "PIN argument must be a number."
    elseif pin < 0 or pin > 9999 then
      return false, "PIN argument must be in range between 0000 and 9999 inclusive."
    elseif bruteforce then
      return false, "When bruteforcing is enabled, a PIN cannot be set."
    end
  end
  args.pin = pin or 0

  return true, args
end

local remote_connect = function(host, port, client_name, pin)
  local socket = nmap.new_socket()
  local status, err = socket:connect(host, port)
  if not status then
    stdnse.debug("Can't connect: %s", err)
    return
  end
  socket:set_timeout(5000)

  local buffer, err = stdnse.make_buffer(socket, "\n")
  if err then
    socket:close()
    stdnse.debug1("Failed to create buffer from socket: %s", err)
    return
  end
  socket:send("LO_SERVER_CLIENT_PAIR\n" .. client_name .. "\n" .. pin .. "\n\n")

  return buffer, socket
end

-- Returns the Client Name, PIN, and Remote Server version if the PIN and Client Name are correct
local remote_version = function(buffer, socket, client_name, pin)
  local line, err
  -- The line we are looking for is 4 down in the response
  -- so we loop through lines until we get to that one
  for j=0,3 do
    line, err = buffer()
    if not line then
      socket:close()
      stdnse.debug1("Failed to receive line from socket: %s", err)
      return
    end

    if string.match(line, "^LO_SERVER_INFO$") then
      line, err = buffer()
      socket:close()
      local output = stdnse.output_table()
      output["Impress Version"] = line
      output["Remote PIN"] = pin
      output["Client Name used"] = client_name
      return output
    end
  end

  socket:close()
  stdnse.debug1("Failed to parse version from socket.")
  return
end

local check_pin = function(host, port, client_name, pin)
  local buffer, socket = remote_connect(host, port, client_name, pin)
  if not buffer then
    return
  end

  local line, err = buffer()
  if not line then
    socket:close()
    stdnse.debug1("Failed to receive line from socket: %s", err)
    return
  end

  if string.match(line, "^LO_SERVER_SERVER_PAIRED$") then
    return remote_version(buffer, socket, client_name, pin)
  end

  socket:close()
  stdnse.debug1("Remote Server present but PIN and/or Client Name was not accepted.")
  return
end

local bruteforce = function(host, port, client_name)
  -- There are 10000 possible PINs which we loop through
  for i=0,9999 do
    -- Pad the pin with leading zeros if required
    local pin = string.format("%04d", i)
    if i % 100 == 0 then
      stdnse.debug1("Bruteforce attempt %d with PIN %s...", i + 1, pin)
    end

    local buffer, socket = remote_connect(host, port, client_name, pin)
    if not buffer then
      return
    end

    local line, err = buffer()
    if not line then
      socket:close()
      stdnse.debug1("Failed to receive line from socket: %s", err)
      return
    end

    if string.match(line, "^LO_SERVER_SERVER_PAIRED$") then
      return remote_version(buffer, socket, client_name, pin)
    end

    socket:close()
  end

  stdnse.debug1("Failed to bruteforce PIN.")
  return
end

action = function(host, port)
  -- Parse and sanity check the command line arguments.
  local status, options = parse_args()
  if not status then
    stdnse.verbose1("ERROR: %s", options)
    return stdnse.format_output(false, options)
  end

  local result
  if options.bruteforce then
    result = bruteforce(host, port, options.client_name)
  else
    result = check_pin(host, port, options.client_name, options.pin)
  end

  if result and result["Impress Version"] then
    port.version.product = port.version.product or "LibreOffice Impress remote"
    port.version.version = result["Impress Version"]
    table.insert(port.version.cpe, ("cpe:/a:libreoffice:libreoffice:%s"):format(result["Impress Version"]))
    nmap.set_port_version(host, port, "hardmatched")
  end

  return result
end
