description = [[
Shows NFS exports, like the <code>showmount -e</code> command.
]]

---
-- @output
-- PORT    STATE SERVICE
-- 111/tcp open  rpcbind
--
-- Host script results:
-- |  nfs-showmount:
-- |  /home/storage/backup 10.46.200.0/255.255.255.0 10.46.200.66/255.255.255.255
-- |_ /home 10.46.200.0/255.255.255.0
--

-- Version 0.4

-- Created 11/23/2009 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 11/24/2009 - v0.2 - added RPC query to find mountd ports
-- Revised 11/24/2009 - v0.3 - added a hostrule instead of portrule
-- Revised 11/26/2009 - v0.4 - reduced packet sizes and documented them

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require 'comm'
require 'datafiles'

hostrule = function(host)

    local port_t111 = nmap.get_port_state(host, {number=111, protocol="udp"})
    local port_u111 = nmap.get_port_state(host, {number=111, protocol="tcp"})

    return ( port_t111 ~= nil and port_t111.state == "open") or
        (port_u111 ~= nil and (port_u111.state == "open" or
            port_u111.state == "open|filtered"))

end

--
-- Calculates the number of fill bytes needed
-- @param length contains the length of the string
-- @return the amount of pad needed to be divideable by 4
--
function calc_fill_bytes(length)

    -- calculate fill bytes
    if math.mod( length, 4 ) ~= 0 then
    return (4 - math.mod( length, 4))
    else
    return 0
    end

end

--
-- extracts the group from the export list entry
-- @param data string should be start with 32-bit lenght field
--
-- @return pos numeric new position within buffer, grp_val string the group contents
--
function extract_group(data)

    local pos, grp_val

    -- retrieve the group length
    pos, grp_len = bin.unpack( ">i", data )
    data = data:sub(pos)

    -- retrieve the group contents
    grp_val = data:sub(0, grp_len)
    pos = 4 + calc_fill_bytes(grp_len) + grp_len + 1

    return pos, grp_val

end

--
-- extracts the directory from the export list entry
-- @param data string should be start with 32-bit lenght field
--
-- @return pos numeric new position within buffer, dir_name string the name of the directory
--
function extract_directory(data)

    local pos, dir_len, dir_name

    -- retrieve the length of the directory name
    pos, dir_len = bin.unpack(">i", data)
    data = data:sub(pos)

    -- retrieve the directory name
    dir_name = data:sub(0, dir_len)
    pos = 4 + calc_fill_bytes(dir_len) + dir_len + 1

    return pos, dir_name

end

--
-- processes the response back from the mountd service
-- @param proto string should be either "udp" or "tcp"
-- @param data string contains the response recieved from the service
--
-- @return string with exports from NFS
--
function process_response(proto, data)

    local pos, val_follows
    local header = {}
    local response=" \n"

    -- if we're running over UDP skip first 4 bytes ( theres no 16-bit something + 16-bit length)
    if "udp" == proto then
        pos, header['xid'], header['type'], header['state'],
            header['verifier'], header['accept_state'] = bin.unpack(">iiili", data)
    else
        pos, _, header['length'], header['xid'], header['type'], header['state'],
            header['verifier'], header['accept_state'] = bin.unpack("S>Siiili", data)
    end

    data = data:sub(pos)

    -- We should probably be doing a lot more verification here, but let's stick to basics
    -- Was the response from the server = Reply(1) and
    -- Accept state = RPC Executed succefully (0)
    if header['type'] ~= 1 or header['accept_state'] ~= 0 then
        return
    end

    --
    --
    --  Each export list entry consists of:
    --
    --  One or more Directory entries:
    --  32-bit - length
    --  length - directory name
    --
    --      One or more Group entries:
    --      32-bit - length
    --      length - group contents
    --
    --      Every group entry is separated by
    --      32-bit - value follows - if set to 1 more groups exist
    --
    --  Every directory entry is separated by
    --  32-bit - value follows - if set to 1 more entries exist
    --
    --
    --  Note: The length specifies the amount of characters for
    --        both dir and group entries
    --
    --    However, directories and groups are padded by zeroes so that
    --    they are divideable by 4. Hence calc_fill_bytes
    --

    pos, val_follows = bin.unpack(">i", data)
        data = data:sub(pos)

    while 1 == val_follows do

        local dir_name, exp_group
        local grp_follows, grp_len, grp_val

        groups=""

        pos, dir_name = extract_directory( data )
        data = data:sub(pos)

        -- check if we have a group following
        pos, grp_follows = bin.unpack(">i", data )
        data = data:sub(pos)

        while grp_follows == 1 do

        pos, grp_val = extract_group( data )
        groups = groups .. " " .. grp_val

        data = data:sub(pos)

        -- check if there's antoher group following
            pos, grp_follows = bin.unpack(">i", data )
        data = data:sub(pos)

        end

        -- concatenate our dir_name and groups to the result
        response = response .. dir_name .. "" .. groups .. "\n"

        -- are there any more directory entries?
        pos, val_follows = bin.unpack(">i", data)
        data = data:sub(pos)

    end

    return response
end

--
-- Ruthlessly ripped, and modified, from Sven Klemm's rpcinfo.nse script
--
function get_rpc_port_for_service(host, svc_progname, svc_version)

  local socket = nmap.new_socket()
  socket:set_timeout(1000)
  local catch = function() socket:close() end
  local try = nmap.new_try(catch)
  local rpc_numbers = try(datafiles.parse_rpc())

  try(socket:connect(host.ip, 111))

  -- build rpc dump call packet
  local transaction_id = math.random(0x7FFFFFFF)
  local request = bin.pack('>IIIIIIILL',0x80000028,transaction_id,0,2,100000,2,4,0,0)
  try(socket:send(request))

  local answer = try(socket:receive_bytes(1))

  local _,offset,header,length,tx_id,msg_type,reply_state,accept_state,value,payload,last_fragment
  last_fragment = false; offset = 1; payload = ''

  -- extract payload from answer and try to receive more packets if
  -- RPC header with last_fragment set has not been received
  -- If we can't get further packets don't stop but process what we
  -- got so far.
  while not last_fragment do
    if offset > #answer then
      local status, data = socket:receive_bytes(1)
      if not status then break end
      answer = answer .. data
    end
    offset,header = bin.unpack('>I',answer,offset)
    last_fragment = bit.band( header, 0x80000000 ) ~= 0
    length = bit.band( header, 0x7FFFFFFF )
    payload = payload .. answer:sub( offset, offset + length - 1 )
    offset = offset + length
  end
  socket:close()

  offset,tx_id,msg_type,reply_state,_,_,accept_state = bin.unpack( '>IIIIII', payload )

  -- transaction_id matches, message type reply, reply state accepted and accept state executed successfully
  if tx_id == transaction_id and msg_type == 1 and reply_state == 0 and accept_state == 0 then
    local dir = { udp = {}, tcp = {}}
    local protocols = {[6]='tcp',[17]='udp'}
    local prog, version, proto, port
    local ports = {}
    offset, value = bin.unpack('>I',payload,offset)
    while value == 1 and #payload - offset >= 19 do
      offset,prog,version,proto,port,value = bin.unpack('>IIIII',payload,offset)
      proto = protocols[proto] or tostring( proto )

      if rpc_numbers[prog] == svc_progname and version == svc_version then
        ports[proto] = port
      end

    end

    return ports

  end

  return

end

action = function(host)

    local data = {}

    -- packet copy/pasted from wireshark, running showmount -e

    data["tcp"] = string.char(
        0x80, 0x00, 0x00, 0x28, -- Fragment Length: 44 bytes (31-bit?)
                                -- Last Fragment: Yes

        0x21, 0x00, 0x46, 0x4c, -- XID: 0x2100464c
        0x00, 0x00, 0x00, 0x00, -- Message type: Call(0)
        0x00, 0x00, 0x00, 0x02, -- RPC Version: 2
        0x00, 0x01, 0x86, 0xa5, -- Program: MOUNT(100005)
        0x00, 0x00, 0x00, 0x01, -- Program Version: 1
        0x00, 0x00, 0x00, 0x05, -- Procedure: EXPORT(5)

        -- Credentials
        0x00, 0x00, 0x00, 0x00, -- Flavor: AUTH_NULL (0)
        0x00, 0x00, 0x00, 0x00, -- Length: 0

        -- Verifier
        0x00, 0x00, 0x00, 0x00, -- Flavor: AUTH_NULL
        0x00, 0x00, 0x00, 0x00  -- Length: 0
    )

    data["udp"] = string.char(
        0x21, 0x00, 0x46, 0x4c, -- XID: 0x2100464c
        0x00, 0x00, 0x00, 0x00, -- Message type: Call(0)
        0x00, 0x00, 0x00, 0x02, -- RPC Version: 2
        0x00, 0x01, 0x86, 0xa5, -- Program: MOUNT(100005)
        0x00, 0x00, 0x00, 0x01, -- Program Version: 1
        0x00, 0x00, 0x00, 0x05, -- Procedure: EXPORT(5)

        -- Credentials
        0x00, 0x00, 0x00, 0x00, -- Flavor: AUTH_NULL (0)
        0x00, 0x00, 0x00, 0x00, -- Length: 0

        -- Verifier
        0x00, 0x00, 0x00, 0x00, -- Flavor: AUTH_NULL
        0x00, 0x00, 0x00, 0x00  -- Length: 0

    )


    local status, result
    local ports = get_rpc_port_for_service(host, "mountd", 1)

    for p in pairs(ports) do

        status, result = comm.exchange(host, ports[p], data[p], {proto=p})

        -- Fail gracefully
        if not status then
            if (nmap.verbosity() >= 2 or nmap.debugging() >= 1) then
                return "ERROR: TIMEOUT"
            else
                return
            end
        end

        result = process_response( p, result )

        if result then
            return result
        end

    end

    return

end
