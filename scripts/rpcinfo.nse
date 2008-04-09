id = "rpcinfo"

description = "connects to portmapper and prints a list of all registered programs"
author = "Sven Klemm <sven@c3d2.de>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe","discovery"}

require "shortport"
require "packet"
require "datafiles"

portrule = shortport.port_or_service(111, "rpcbind")

action = function(host, port)
  local try, catch
  local transaction_id = "nmap"
  local socket = nmap.new_socket()
  local result = " \n"
  local rpc_numbers

  catch = function() socket:close() end
  try = nmap.new_try( catch )
  rpc_numbers = try(datafiles.parse_rpc())

  local request = string.char(0x80,0,0,40) -- fragment header
  request = request .. transaction_id -- transaction id
  request = request .. "\0\0\0\0\0\0\0\2" -- message type: call (0) and rpc version 2
  request = request .. string.char(0,1,134,160) -- programm portmap (100000)
  request = request .. "\0\0\0\2\0\0\0\4" -- programm version (2) procedure dump(4)
  request = request .. "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"-- Credentials and verifier

  socket:set_timeout(1000)
  try( socket:connect(host.ip, port.number) )
  try( socket:send( request ) )
  local status, answer, answer_part
  status, answer = socket:receive_bytes( 1 )
  while status do
    status, answer_part = socket:receive_bytes( 1 )
    if status then answer = answer .. answer_part end
  end
  socket:close()

  local fragment_length = answer:byte(4) + answer:byte(3) * 256 + answer:byte(2) * 65536
  if answer:sub(5,8) == transaction_id and answer:byte(12) == 1 and answer:byte(16) == 0 and answer:byte(28) == 0 then
    -- transaction_id matches, message type reply, reply state accepted and accept state executed successfully
    answer_part = answer
    answer = answer_part:sub( 28 + 1, fragment_length + 4 )
    answer_part = answer_part:sub( fragment_length + 4 + 1 )

    while answer_part:len() > 0 do -- defragment packet
      fragment_length = answer_part:byte(4) + answer_part:byte(3) * 256 + answer_part:byte(2) * 65536
      answer = answer .. answer_part:sub( 5, fragment_length + 4 )
      answer_part = answer_part:sub( fragment_length + 4 + 1 )
    end

    local dir = { udp = {}, tcp = {}}
    local rpc_prog, rpc_vers, rpc_proto, rpc_port
    while answer:byte(4) == 1 and answer:len() >= 20 do
      rpc_prog = packet.u32( answer, 4 )
      rpc_vers = packet.u32( answer, 8 )
      rpc_proto = packet.u32( answer, 12 )
      rpc_port = packet.u32( answer, 16 )
      answer = answer:sub(21)
      if rpc_proto == 6 then
        rpc_proto = "tcp"
      elseif rpc_proto == 17 then
        rpc_proto = "udp"
      end
      if not dir[rpc_proto][rpc_port] then dir[rpc_proto][rpc_port] = {} end
      if not dir[rpc_proto][rpc_port][rpc_prog] then dir[rpc_proto][rpc_port][rpc_prog] = {} end
      table.insert( dir[rpc_proto][rpc_port][rpc_prog], rpc_vers )
    end

    local format_version = function( version_table )
      if #version_table == 1 then return version_table[1] end
      table.sort( version_table )
      for i=2,#version_table do
        if version_table[i-1] ~= version_table[i] - 1 then
          return table.concat( version_table, ',' )
        end
      end
      return string.format('%d-%d',version_table[1],version_table[#version_table])
    end

    for rpc_proto, o in pairs(dir) do
      local ports = {}
      for rpc_port, i in pairs(o) do table.insert(ports, rpc_port) end
      table.sort(ports)
      for i, rpc_port in ipairs(ports) do
        i = o[rpc_port]
        for rpc_prog, versions in pairs(o[rpc_port]) do
          versions = format_version( versions )
          local name = rpc_numbers[rpc_prog] or ''
          result = result .. string.format('%d %-5s %5d/%s %s\n',rpc_prog,versions,rpc_port,rpc_proto,name)
        end
      end
    end

  end

  return result
end

