local datafiles = require "datafiles"
local nmap = require "nmap"
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
-- @usage nmap -sU -p 69 --script tftp-enum.nse --script-args tftp-enum.filelist=customlist.txt <host>
--
-- @args filelist - file name with list of filenames to enumerate at tftp server
--
-- @output
-- PORT   STATE SERVICE REASON
-- 69/udp open  tftp    script-set
-- | tftp-enum:
-- |_  bootrom.ld

author = "Alexander Rudakov"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
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
  local cisco = false
  local status, default_filenames = datafiles.parse_file(customlist or "nselib/data/tftplist.txt" , {})
  if not status then
    stdnse.debug1("Can not open file with tftp file names list")
    return {}
  else

    for i, filename in ipairs(default_filenames) do
      if filename:match('{[Mm][Aa][Cc]}') then
        if not host.mac_addr then
          goto next_filename
        else
          filename = filename:gsub('{M[Aa][Cc]}', string.upper(stdnse.tohex(host.mac_addr)))
          filename = filename:gsub('{m[aA][cC]}', stdnse.tohex(host.mac_addr))
        end
      end

      if filename:match('{cisco}') then
        cisco = true
        table.remove(default_filenames,i)
      end
      ::next_filename::
    end

    if cisco == true then
      local cisco_address_confg_filenames = generate_cisco_address_confg(host.ip)
      return array_concat(default_filenames, cisco_address_confg_filenames)
    end
  end
  return default_filenames
end


local create_tftp_file_request = function(filename)
  return "\0\x01" .. filename .. "\0octet\0"
end

local check_file_present = function(host, port, filename)
  stdnse.debug1("checking file %s", filename)

  local file_request = create_tftp_file_request(filename)


  local socket = nmap.new_socket()
  socket:connect(host, port)
  local status, lhost, lport, rhost, rport = socket:get_info()
  stdnse.debug1("lhost: %s, lport: %s", lhost, lport);


  if (not (status)) then
    stdnse.debug1("error %s", lhost)
    socket:close()
    return REQUEST_ERROR
  end


  local bind_socket = nmap.new_socket("udp")
  stdnse.debug1("local port = %d", lport)

  socket:send(file_request)
  socket:close()

  local bindOK, error = bind_socket:bind(nil, lport)


  stdnse.debug1("starting listener")

  if (not (bindOK)) then
    stdnse.debug1("Error in bind %s", error)
    bind_socket:close()
    return REQUEST_ERROR
  end


  local recvOK, data = bind_socket:receive()

  if (not (recvOK)) then
    stdnse.debug1("Error in receive %s", data)
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

local check_open_tftp = function(host, port)
  local random_name = stdnse.generate_random_string(8, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
  local ret_value = check_file_present(host, port, random_name)
  if (ret_value == FILE_FOUND or ret_value == FILE_NOT_FOUND) then
    return true
  else
    return false
  end
end

action = function(host, port)

  if (not (check_open_tftp(host, port))) then
    stdnse.debug1("tftp seems not active")
    return
  end

  stdnse.debug1("tftp detected")

  port.service = "tftp"
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
