local bin = require "bin"
local datafiles = require "datafiles"
local math = require "math"
local nmap = require "nmap"
local os = require "os"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates TFTP (trivial file transfer protocol) filenames by testing
for a list of common ones.

TFTP doesn't provide directory listings. This script tries to retrieve
filenames from a list. The list is composed of static names from the
file <code>tftplist.txt</code>, plus configuration filenames for Cisco
devices that change based on the target address, of the form
<code>A.B.C.X-confg</code> for an IP address A.B.C.D and for X in 0 to
255.

Use the <code>tftp-enum.filelist</code> script argument to search for
other static filenames.

This script is a reimplementation of tftptheft from
http://code.google.com/p/tftptheft/.
]]

---
-- @usage nmap -sU -p 69 --script tftp-enum.nse --script-args="tftp-enum.filelist=customlist.txt" <host>
--
-- @args filelist - file name with list of filenames to enumerate at tftp server
--
-- @output
-- PORT   STATE SERVICE REASON
-- 69/udp open  tftp    script-set
-- | tftp-enum:
-- |_  bootrom.ld

author = "Alexander Rudakov"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = { "discovery", "intrusive" }


local REQUEST_ERROR = -1
local FILE_FOUND = 1
local FILE_NOT_FOUND = 2

portrule = shortport.portnumber(69, "udp")

-- return a new array containing the concatenation of all of its
-- parameters. Scaler parameters are included in place, and array
-- parameters have their values shallow-copied to the final array.
-- Note that userdata and function values are treated as scalar.
local function array_concat(...)
  local t = {}
  for n = 1, select("#", ...) do
    local arg = select(n, ...)
    if type(arg) == "table" then
      for _, v in ipairs(arg) do
        t[#t + 1] = v
      end
    else
      t[#t + 1] = arg
    end
  end
  return t
end

local generate_cisco_address_confg = function(base_address)
  local filenames = {}
  local octets = stdnse.strsplit("%.", base_address)

  for i = 0, 255 do
    local address_confg = octets[1] .. "." .. octets[2] .. "." .. octets[3] .. "." .. i .. "-confg"
    table.insert(filenames, address_confg)
  end

  return filenames
end

local generate_filenames = function(host)
  local customlist = stdnse.get_script_args('tftp-enum.filelist')
  local status, default_filenames = datafiles.parse_file(customlist or "nselib/data/tftplist.txt" , {})
  if not status then
    stdnse.print_debug(1, "Can not open file with tftp file names list")
    return {}
  end

  local cisco_address_confg_filenames = generate_cisco_address_confg(host.ip)

  return array_concat(default_filenames, cisco_address_confg_filenames)
end


local create_tftp_file_request = function(filename)
  return bin.pack('CC', 0x00, 0x01) .. filename .. bin.pack('C', 0x00) .. 'octet' .. bin.pack('C', 0x00)
end

local check_file_present = function(host, port, filename)
  stdnse.print_debug(1, ("checking file %s"):format(filename))

  local file_request = create_tftp_file_request(filename)


  local socket = nmap.new_socket()
  socket:connect(host.ip, port.number, "udp")
  local status, lhost, lport, rhost, rport = socket:get_info()


  if (not (status)) then
    stdnse.print_debug(1, ("error %s"):format(lhost))
    socket:close()
    return REQUEST_ERROR
  end


  local bind_socket = nmap.new_socket("udp")
  stdnse.print_debug(1, ("local port = %d"):format(lport))

  socket:send(file_request)
  socket:close()

  local bindOK, error = bind_socket:bind(nil, lport)


  stdnse.print_debug(1, "starting listener")

  if (not (bindOK)) then
    stdnse.print_debug(1, ("Error in bind %s"):format(error))
    bind_socket:close()
    return REQUEST_ERROR
  end


  local recvOK, data = bind_socket:receive()

  if (not (recvOK)) then
    stdnse.print_debug(1, ("Error in receive %s"):format(data))
    bind_socket:close()
    return REQUEST_ERROR
  end

  if (data:byte(1) == 0x00 and data:byte(2) == 0x03) then
    bind_socket:close()
    return FILE_FOUND
  elseif (data:byte(1) == 0x00 and data:byte(2) == 0x05) then
    bind_socket:close()
    return FILE_NOT_FOUND
  else
    bind_socket:close()
    return REQUEST_ERROR
  end

  return FILE_NOT_FOUND
end

--- Generates a random string of the requested length. This can be used to check how hosts react to
-- weird username/password combinations.
-- @param length (optional) The length of the string to return. Default: 8.
-- @param set (optional) The set of letters to choose from. Default: upper, lower, numbers, and underscore.
-- @return The random string.
local function get_random_string(length, set)
  if (length == nil) then
    length = 8
  end

  if (set == nil) then
    set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
  end

  local str = ""

  -- Seed the random number, if we haven't already
  if (not (nmap.registry.oracle_enum_users) or not (nmap.registry.oracle_enum_users.seeded)) then
    math.randomseed(os.time())
    nmap.registry.oracle_enum_users = {}
    nmap.registry.oracle_enum_users.seeded = true
  end

  for i = 1, length, 1 do
    local random = math.random(#set)
    str = str .. string.sub(set, random, random)
  end

  return str
end

local check_open_tftp = function(host, port)
  local random_name = get_random_string()
  local ret_value = check_file_present(host, port, random_name)
  if (ret_value == FILE_FOUND or ret_value == FILE_NOT_FOUND) then
    return true
  else
    return false
  end
end

action = function(host, port)

  if (not (check_open_tftp(host, port))) then
    stdnse.print_debug(1, "tftp seems not active")
    return
  end

  stdnse.print_debug(1, "tftp detected")

  nmap.set_port_state(host, port, "open")

  local results = {}
  local filenames = generate_filenames(host)

  for i, filename in ipairs(filenames) do
    local request_status = check_file_present(host, port, filename)
    if (request_status == FILE_FOUND) then
      table.insert(results, filename)
    end
  end

  return stdnse.format_output(true, results)
end
