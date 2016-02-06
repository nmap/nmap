--- Bittorrent and DHT protocol library which enables users to read
-- information from a torrent file, decode bencoded (bittorrent
-- encoded) buffers, find peers associated with a certain torrent and
-- retrieve nodes discovered during the search for peers.
--
-- For more information on the Bittorrent and DHT protocol go to:
-- http://www.bittorrent.org/beps/bep_0000.html
--
-- The library contains the class <code>Torrent</code> and the function (buf)
--
-- How this library is likely to be used:
-- <code>
--  local filename = "/home/user/name.torrent"
--  local torrent = bittorrent.Torrent:new()
--  torrent:load_from_file(filename)
--  torrent:trackers_peers() -- to load peers from the trackers
--  torrent:dht_peers() -- to further load peers using the DHT protocol from existing peers
-- </code>
-- After these operations the peers and nodes can be found in <code>torrent.peers</code> and
-- <code>torrent.nodes</code> tables respectively
--
-- @author "Gorjan Petrovski"
-- @license "Same as Nmap--See https://nmap.org/book/man-legal.html"
--

-- The usage of the library would be first to initialize a new Torrent
-- object. This initialization includes setting values for several
-- variables.
-- Next, a the torrent information needs to be loaded from a torrent file
-- or a magnet link. The information in question would be a list of
-- trackers, and the info_hash variable which is a 20 bytes length SHA1
-- hash of the info field in the torrent file. The torrent file includes
-- the field itself, but the magnet link only includes the info_hash
-- value.
-- After the basic info for the torrent is set, next the peers from the
-- trackers need to be downloaded (torrent:trackers_peers()). There are
-- http and udp trackers which use different protocols implemented in the
-- Torrent:http_tracker_peers() and Torrent:udp_tracker_peers(). The
-- communication is done serially and could be improved by using threads.
-- After a few peers have been discovered we can continue in using the
-- DHT protocol to discover more. We MUST have several peers in order to
-- use the DHT protocol, and what's more at least one of the peers must
-- have that protocol implemented. A peer which implements the DHT
-- protocol is called a node. What that protocol allows is actually to
-- find more peers for the torrent we are downloading/interested in, and
-- it also allows us to find more nodes (hosts which implement the DHT
-- protocol). Please notice that a DHT node does not necessarily have to
-- be a peer sharing the torrent we need. So, in fact we have two
-- networks, the network of peers (hosts sharing the torrent we need) and
-- the DHT network (network of nodes which allow us to find more peers
-- and nodes.
-- There are three kinds of commands we need to do DHT discovery:
-- - dht_ping, which is sent to a peer to test if the peer is a DHT node
-- - find_node, which is sent to a DHT node to discover more DHT nodes
-- - get_peers, which is sent to a DHT node to discover peers sharing a
-- specific torrent; If the node that we send the get_peers command
-- doesn't have a record of peers sharing that torrent, it returns more
-- nodes.
-- So in the bittorrent library I implemented every command in functions
-- which are run as separate threads. They synchronize their work using
-- the pnt condvar table. This is the map of pnt (peer node table):
-- pnt = { peers_dht_ping, peers, nodes_find_node, nodes_get_peers, nodes }
-- The dht_ping thread pings every peer in peers_dht_ping and then
-- inserts it into peers. It does this for batches of a 100 peers. If the
-- peer responds it adds it to the nodes_find_node list.
-- The find_node thread sends find_node queries to the nodes in
-- nodes_find_node, after which it puts them in nodes_get_peers. The
-- nodes included in the response are added to the nodes_find_node list
-- if they are not present in any of the nodes' lists.
-- The nodes_get_peers sends a get_peers query to every node in the list
-- after which they are added to the nodes list. If undiscovered peers
-- are returned they are inserted into peers_dht_ping. If undiscovered
-- nodes are found they are inserted into nodes_find_node.
-- All of these threads run for a specified timeout whose default value
-- is ~ 30 seconds.
-- As you can see all newly discovered nodes are added to the
-- nodes_find_node, and are processed first by the find_node thread, and
-- then by the get_peers thread. All newly discovered peers are added to
-- the peers_dht_ping to be processed by the dht_ping thread and so on.
-- That enables the three threads to cooperate and pass on peers and
-- nodes between each other.
--
-- There is also a bdecode function which decodes Bittorrent encoded
-- buffers and organizes them into a structure I deemed fit for use.
-- There are two known bittorrent structures: the list and the
-- dictionary. One problem I encountered was that the bittorrent
-- dictionary can have multiple entries with same-name keys. This kind of
-- structure is not supported by Lua, so I had to use lists to represent
-- the dictionaries as well which made accessing the keys a bit quirky

local bin = require "bin"
local bit = require "bit"
local coroutine = require "coroutine"
local http = require "http"
local io = require "io"
local nmap = require "nmap"
local openssl = require "openssl"
local os = require "os"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"
local nsedebug = require "nsedebug"

_ENV = stdnse.module("bittorrent", stdnse.seeall)

--------------------------------------------------------------------------------
--  utilities for logging memory data
--
local hex_dump = function( _title, buf )
    
  io.write( "\n-->> " .. _title .. "\n" )

  for byte=1, #buf, 16 do
     local chunk = buf:sub(byte, byte+15)

     io.write(string.format('%08X  ',byte-1))

     chunk:gsub('.', function (c) io.write(string.format('%02X ',string.byte(c))) end)
     io.write(string.rep(' ',3*(16-#chunk)))
     io.write(' ',chunk:gsub('%c','.'),"\n") 
  end

  io.write( "-->> end " .. _title .. "\n\n" )
end

  --
  --  print a table in memory
  --
  local print_r = function( t )
    local print_r_cache={}
    local function sub_print_r(t,indent)
        if (print_r_cache[tostring(t)]) then
            print(indent.."*"..tostring(t))
        else
            print_r_cache[tostring(t)]=true
            if (type(t)=="table") then
                for pos,val in pairs(t) do
                    if (type(val)=="table") then
                        print(indent.."["..pos.."] => "..tostring(t).." {")
                        sub_print_r(val,indent..string.rep(" ",string.len(pos)+8))
                        print(indent..string.rep(" ",string.len(pos)+6).."}")
                    elseif (type(val)=="string") then
                        print(indent.."["..pos..'] => "'..val..'"')
                    else
                        print(indent.."["..pos.."] => "..tostring(val))
                    end
                end
            else
                print(indent..tostring(t))
            end
        end
    end
    if (type(t)=="table") then
        print(tostring(t).." {")
        sub_print_r(t,"  ")
        print("}")
    else
        sub_print_r(t,"  ")
    end
    print()
  end

  ------------------------------------------------------------------------------

--[[ Retrieve the .torrent file, describing the torrent, hashes and tracker
function get_torrent(url)
  local r, code = http.request(url)
  if code == 404 or r == nil then return nil end

  -- We can't use benc.encode(torrent['info']) because the order can be
  -- different than on the real info string
  local a, b = string.find(r, "4:info")
  local t = string.sub(r, b + 1)
  t = string.sub(t, 1, string.len(t) - 1)

  return benc.decode(r), crypto.evp.new("sha1"):digest(t)
end
]]


--- Given a buffer and a starting position in the buffer, this function decodes
-- a bencoded string there and returns it as a normal lua string, as well as
-- the position after the string
local bdec_string = function(buf, pos)
  local text = string.match(buf, "^(%d+):", pos)
  local plen = tonumber(text or "nil", 10)
  if not plen then
    return nil, pos
  end
  
  local str
  
  if 0 < plen then
    local pstart = pos + #text + 1
    local pend   = pstart + plen 

    str = buf:sub( pstart, pend - 1 )
    pos = pend
  else
    str = ""
    pos = pos + 2
  end
  
  return str, pos
end

--- Given a buffer and a starting position in the buffer, this function decodes
-- a bencoded number there and returns it as a normal lua number, as well as
-- the position after the number
local bdec_number = function(buf, pos)
  local s, n = string.match(buf, "^i(%-*)(%d+)e", pos)
  if not n then return nil end

  local num = tonumber(n)
  -- 1 for the "i", 1 for the "e", 1 if there is a "-" plus the length of n
  pos = pos + 2 + #n

  if s == "-" then
    num = -num
    pos = pos + 1
  end

  return num, pos
end

--- Parses a bencoded buffer
-- @param buf, string with the bencoded buffer
-- @return bool indicating if parsing went ok
-- @return table containing the decoded structure, or error string
bdecode = function(buf)
  -- the main table
  local t = {}
  local stack = {}

  local pos = 1
  local cur = {}
  cur.type = "list"
  cur.ref = t
  table.insert(stack, cur)
  cur.ref.type="list"

  if not buf then
    return false, "ERROR: check bdecode parameter (a nil buffer)", nil
  end

  local len = #buf

  while true do
    if pos >= len or (len-pos)<=-1 then break end

    if cur.type == "list" then

      -- next element is a string
      if tonumber( string.char( buf:byte(pos) ) ) then
        local str
        str, pos = bdec_string(buf, pos)
        if not str then return nil, "Error parsing string #[" .. pos .. "]" end
        table.insert(cur.ref, str)

      -- next element is a number
      elseif "i" == string.char(buf:byte(pos)) then
        local num
        num, pos = bdec_number(buf, pos)
        if not num then return nil, "Error parsing number #[" .. pos .. "]" end
        table.insert(cur.ref, num)

      -- next element is a list
      elseif "l" == string.char(buf:byte(pos)) then
        local new_list = {}
        new_list.type="list"
        table.insert(cur.ref, new_list)

        cur = {}
        cur.type = "list"
        cur.ref = new_list
        table.insert(stack, cur)
        pos = pos+1

      --next element is a dict
      elseif "d" == string.char(buf:byte(pos)) then
        local new_dict = {}
        new_dict.type = "dict"
        table.insert(cur.ref, new_dict)

        cur = {}
        cur.type = "dict"
        cur.ref = new_dict
        table.insert(stack, cur)
        pos = pos+1

      --escape from the list
      elseif "e" == string.char(buf:byte(pos)) then
        table.remove(stack, #stack)
        cur = stack[#stack]
        if not cur then return nil, "Problem with list closure:", pos end
        pos = pos+1
      else
        stdnse.verbose1("* Error: can't handle data format")
        break
      end

    elseif cur.type == "dict" then

      local item = {} -- {key = <string>, value = <.*>}
      -- used to skip reading the value when escaping from a structure
      local escape_flag = false

      -- fill the key
      if tonumber( string.char( buf:byte(pos) ) ) then
        local str
        local tmp_pos = pos
        str, pos = bdec_string(buf, pos)
        if not str then return nil, "Error parsing string.", pos end
        item.key = str

      elseif "e" == string.char(buf:byte(pos)) then
        table.remove(stack, #stack)
        cur = stack[#stack]
        if not cur then return nil, "Problem with list closure:", pos end
        pos = pos+1

        escape_flag = true
      else
        return nil, "A dict key has to be a string or escape.", pos
      end

      -- value
      if not escape_flag then

        --  Antonio
        --  brutal
        --
        if "peers" == item.key then
          local len
          local a, b = string.find(buf, ":", pos)

          if a and b then
            local text = string.sub( buf, pos, a - 1 ) 

            -- stdnse.verbose1(">>Length sought for peers[" .. text .. "]")
            len = tonumber(text)
            item.value = string.sub( buf, a + 1, a + len)

            --  Antonio
            --  should fall back to an 'e'
            pos = len + a + 1

            table.insert(cur.ref, item)
          else
            return nil, "Panic"
          end
        end

        -- next element is a string
        if tonumber( string.char( buf:byte(pos) ) ) then

          local str
          str, pos = bdec_string(buf, pos)
          if not str then return nil, "Error parsing string.", pos end
          item.value = str
          table.insert(cur.ref, item)

        --next element is a number
        elseif "i" == string.char(buf:byte(pos)) then
          local num
          num, pos = bdec_number(buf, pos)
          if not num then return nil, "Error parsing number.", pos end
          item.value = num
          table.insert(cur.ref, item)

        -- next element is a list
        elseif "l" == string.char(buf:byte(pos)) then
          item.value = {}
          item.value.type = "list"
          table.insert(cur.ref, item)

          cur = {}
          cur.type = "list"
          cur.ref = item.value

          table.insert(stack, cur)
          pos = pos+1

        --next element is a dict
        elseif "d" == string.char(buf:byte(pos)) then
          item.value = {}
          item.value.type = "dict"
          table.insert(cur.ref, item)

          cur = {}
          cur.type = "dict"
          cur.ref = item.value

          table.insert(stack, cur)
          pos = pos+1

        --escape from the dict
        elseif "e" == string.char(buf:byte(pos)) then
          table.remove(stack, #stack)
          cur = stack[#stack]
          if not cur then return false, "Problem with dict closure", pos end
          pos = pos+1
        else
          stdnse.verbose1("* ERROR[" .. string.char(buf:byte(pos)) .. "] at pos[" .. pos .. "]")

          return false, "Error parsing file, unknown type found", pos
        end
      end -- if not escape_flag
    else -- elseif type == "dict"

      stdnse.verbose1("* Unknown type found: cur.type[" .. cur.type .. "] @[" .. pos .. "]")
      return nil, "Unknown type found.", pos
    end
  end -- while(true)

  -- The code below is commented out because some responses from trackers are
  -- not according to standards

  -- next(stack) is never gonna be nil because we're always in the main list
  -- next(stack, next(stack)) should be nil if we're in the main list
  --
  if next(stack, next(stack)) then
    return false, "Probably file incorrect format"
  end

  return true, t
end

--- This is the thread function which sends a DHT ping probe to every peer in
-- pnt.peers_dht_ping after which the peer is moved to the pnt.peers and
-- removed from pnt.peers_dht_ping. Every peer which responds to the DHT ping
-- is actually a DHT node and is added to the pnt.nodes_find_node table in
-- order to be processed byt the find_node_thread(). This operation is done
-- during the specified timeout which has a default value of about 30 seconds.

local dht_ping_thread = function(pnt, timeout)
  local condvar = nmap.condvar(pnt)
  local socket = nmap.new_socket("udp")
  socket:set_timeout(3000)
  local status, data

  stdnse.verbose2("! dht_ping_thread launched")

  local transaction_id = 0
  local start = os.time()

  while os.time() - start < timeout do
    local num_peers = 0
    --ping a 100 peers if there are as many

    while next(pnt.peers_dht_ping) ~= nil and num_peers <= 100 and os.time() - start < timeout do
      num_peers = num_peers +1
      local peer_ip, peer_info = next(pnt.peers_dht_ping)

      --transaction ids are 2 bytes long
      local t_ID_hex = stdnse.tohex(transaction_id % 0xffff)
      t_ID_hex = string.rep("0",4-#t_ID_hex)..t_ID_hex
      peer_info.transaction_id = bin.pack("H",t_ID_hex)

      -- mark it as received so we can distinguish from the others and
      -- successfully iterate while receiving
      peer_info.received = false

      pnt.peers[peer_ip] = peer_info
      pnt.peers_dht_ping[peer_ip] = nil

      -- bencoded ping query describing a dictionary with y = q (query), q = ping
      -- {"t":<transaction_id>, "y":"q", "q":"ping", "a":{"id":<node_id>}}
      local ping_query =  "d1:ad2:id20:" .. pnt.node_id .. "e1:q4:ping1:t2:" ..
        peer_info.transaction_id .. "1:y1:qe"

      status, data = socket:sendto(peer_ip, peer_info.port, ping_query)

      transaction_id = transaction_id +1
      if transaction_id % 0xffff == 0 then
        transaction_id = 0
      end
    end

    -- receive responses up to a 100
    for c = 1, 100 do
      if os.time() - start >= timeout then break end
      status, data = socket:receive()
      if not status then break end

      local s, r = bdecode(data)
      -- if the response is decoded process it
      if s then
        local error_flag = true
        local good_response = false
        local node_id = nil
        local trans_id = nil

        for _, i in ipairs(r[1]) do
          if i.key == "y" and i.value == "r" then
            error_flag = false
          elseif i.key == "r" and i.value and i.value[1] and i.value[1].value then
            node_id = i.value[1].value
            good_response = true
          elseif i.key == "t" then
            trans_id = i.value
          end
        end

        if (not error_flag) and good_response and node_id and trans_id then
          local peer_ip
          for ip, info in pairs(pnt.peers) do
            if info.transaction_id == trans_id then
              info.received = nil
              peer_ip = ip
              break
            end
          end
          if peer_ip then
            pnt.peers[peer_ip].node_id = node_id
            if not (pnt.nodes_find_node[peer_ip] or pnt.nodes_get_peers[peer_ip] or
              pnt.nodes[peer_ip]) then
              pnt.nodes_find_node[peer_ip] = pnt.peers[peer_ip]
            end
          end
        end
      end -- if s then
    end -- /for c = 1, 100
  end -- /while true
  socket:close()
  condvar("signal")
end


--- This thread sends a DHT find_node query to every node in
-- pnt.nodes_find_node, after which every node is moved to pnt.nodes_get_peers
-- to be processed by the get_peers_thread() function. The responses to these
-- queries contain addresses of other DHT nodes (usually 8) which are added to
-- the pnt.nodes_find_node list. This action is done for a timeout with a
-- default value of 30 seconds.
local find_node_thread = function(pnt, timeout)
  local condvar = nmap.condvar(pnt)
  local socket = nmap.new_socket("udp")
  socket:set_timeout(3000)
  local status, data

  stdnse.verbose2("! find_node_thread launched")

  local start = os.time()
  while true do
    if os.time() - start >= timeout then break end
    local num_peers = 0

    while next(pnt.nodes_find_node) ~= nil and num_peers <= 100 do
      num_peers = num_peers +1
      local node_ip, node_info = next(pnt.nodes_find_node)

      -- standard bittorrent protocol specified find_node query with y = q (query),
      -- q = "find_node" (type of query),
      -- find_node Query = {"t":<transaction_id>, "y":"q", "q":"find_node", "a": {"id":<node_id>, "target":<info_hash>}}
      local find_node_query = "d1:ad2:id20:" .. pnt.node_id .. "6:target20:" ..
        pnt.info_hash .. "e1:q9:find_node1:t2:" .. openssl.rand_bytes(2) .. "1:y1:qe"

      -- add the traversed nodes to pnt.nodes_get_peers so they can be traversed by get_peers_thread
      pnt.nodes_get_peers[node_ip] = node_info
      pnt.nodes_find_node[node_ip] = nil

      status, data = socket:sendto(node_ip, node_info.port, find_node_query)
    end

    for c = 1, 100 do
      if os.time() - start >= timeout then break end
      status, data = socket:receive()
      if not status then break end
      local s, r = bdecode(data)

      if s then
        local nodes = nil
        if r[1] and r[1][1] and r[1][1].key == "r" and r[1][1].value then
          for _, el in ipairs(r[1][1].value) do
            if el.key == "nodes" then
              nodes = el.value
            end
          end
        end

        --parse the nodes an add them to pnt.nodes_find_node
        if nodes then
          for node_id, bin_node_ip, bin_node_port in nodes:gmatch("(....................)(....)(..)") do
            local node_ip = string.format("%d.%d.%d.%d", bin_node_ip:byte(1), bin_node_ip:byte(2),
              bin_node_ip:byte(3), bin_node_ip:byte(4))
            local node_port = bit.lshift(bin_node_port:byte(1),8) + bin_node_port:byte(2)
            local node_info = {}
            node_info.port = node_port
            node_info.node_id = node_id

            if not (pnt.nodes[node_ip] or pnt.nodes_get_peers[node_ip]
              or pnt.nodes_find_node[node_ip]) then
              pnt.nodes_find_node[node_ip] = node_info
            end
          end
        end -- if nodes
      end -- if s
    end -- for c = 1, 100
  end -- while true
  socket:close()
  condvar("signal")
end


--- This thread sends get_peers DHT queries to all the nodes in
-- pnt.nodes_get_peers, after which they are moved to pnt.nodes. There are two
-- kinds of responses to these kinds of queries. One response contains peers,
-- which would be added to the pnt.peers_dht_ping list, and the other kind of
-- response is sent when the queried node has no peers, and contains more nodes
-- which are added to the pnt.nodes_find_node list.
local get_peers_thread = function(pnt, timeout)
  local condvar = nmap.condvar(pnt)
  local socket = nmap.new_socket("udp")
  socket:set_timeout(3000)
  local status, data

  stdnse.verbose2("! get_peers_thread launched")

  local start = os.time()
  while true do
    if os.time() - start >= timeout then break end
    local num_peers = 0

    while next(pnt.nodes_get_peers) ~= nil and num_peers <= 100 do
      num_peers = num_peers +1
      local node_ip, node_info = next(pnt.nodes_get_peers)

      -- standard bittorrent protocol specified get_peers query with y ="q" (query)
      -- and q = "get_peers" (type of query)
      -- {"t":<transaction_id>, "y":"q", "q":"get_peers", "a": {"id":<node_id>, "info_hash":<info_hash>}}
      local get_peers_query = "d1:ad2:id20:" .. pnt.node_id .. "9:info_hash20:" ..
        pnt.info_hash .. "e1:q9:get_peers1:t2:" .. openssl.rand_bytes(2) .. "1:y1:qe"

      pnt.nodes[node_ip] = node_info
      pnt.nodes_get_peers[node_ip] = nil

      status, data = socket:sendto(node_ip, node_info.port, get_peers_query)
    end

    for c = 1, 100 do
      if os.time() - start >= timeout then break end
      status, data = socket:receive()
      if not status then break end
      local s, r = bdecode(data)

      if s then
        local good_response = false
        local nodes = nil
        local peers = nil
        for _,el in ipairs(r[1]) do
          if el.key == "y" and el.value == "r" then
            good_response = true
          elseif el.key == "r" then
            for _,i in ipairs(el.value) do
              -- the key will either be for nodes or peers
              if i.key == "nodes" then -- nodes
                nodes = i.value
                break
              elseif i.key == "values" then -- peers
                peers = i.value
                break
              end
            end
          end
        end

        if not good_response then
          break
        end

        if nodes then

          for node_id, bin_node_ip, bin_node_port in
            nodes:gmatch("(....................)(....)(..)") do

            local node_ip = string.format("%d.%d.%d.%d", bin_node_ip:byte(1), bin_node_ip:byte(2),
              bin_node_ip:byte(3), bin_node_ip:byte(4))
            local node_port = bit.lshift(bin_node_port:byte(1),8) + bin_node_port:byte(2)
            local node_info = {}
            node_info.port = node_port
            node_info.node_id = node_id

            if not (pnt.nodes[node_ip] or pnt.nodes_get_peers[node_ip] or
              pnt.nodes_find_node[node_ip]) then
              pnt.nodes_find_node[node_ip] = node_info
            end
          end

        elseif peers then

          for _, peer in ipairs(peers) do
            local bin_ip, bin_port = peer:match("(....)(..)")
            local ip = string.format("%d.%d.%d.%d", bin_ip:byte(1),
              bin_ip:byte(2), bin_ip:byte(3), bin_ip:byte(4))
            local port = bit.lshift(bin_port:byte(1),8)+bin_port:byte(2)

            if not (pnt.peers[ip] or pnt.peers_dht_ping[ip]) then
              pnt.peers_dht_ping[ip] = {}
              pnt.peers_dht_ping[ip].port = port
            end
          end

        end -- if nodes / elseif peers
      end -- if s then
    end -- for c = 1,100
  end -- while true
  socket:close()
  condvar("signal")
end



Torrent =
{
  new = function(self)
    local obj ={}
    setmetatable(obj, self)
    self.__index = self

    self.buffer = nil -- buffer to keep the torrent
    self.tor_struct = nil -- the decoded structure from the bencoded buffer

    self.trackers = {} -- list of trackers  {"tr1", "tr2", "tr3"...}
    self.port = 6881 -- port on which our peer "listens" / it doesn't actually listen
    self.size = nil -- size of the files in the torrent

    --  self.info_buf = nil --buffer for info_hash        --  Antonio: this field is not necessary
    self.info_hash = nil --info_hash binary string
    self.info_hash_url = nil --info_hash escaped

    self.peers = {} -- peers = { [ip1] = {port1, id1}, [ip2] = {port2, id2}, ...}
    self.nodes = {} -- nodes = { [ip1] = {port1, id1}, [ip2] = {port2, id2}, ...}

    -- starting and ending position of the info dict
    self.info_pos_start = nil
    self.info_pos_end   = nil
--    self.info_buf_count = 0

    --  Antonio
    --
    self.num_seeders = 0      --  global counters of seeders and leechers
    self.num_leeches = 0  
    self.blacklist = nil      --  a black list of trackers

    return obj
  end,

  --  load a text file and put it on a table
  --  uses the self.blacklist variable
  --
  load_blacklist = function(self, filename)

    stdnse.verbose2("  load_blacklist[" .. filename .. "]")

    if not filename then 
      stdnse.verbose1("* No filename specified for blacklist.")
      return nil
    end

    local file = io.open(filename, "r")
    if not file then 
      stdnse.verbose1("* Unable to open blacklist[" .. filename .. "]")
      return nil
    end
    file:close()

    self.blacklist = {}
    for line in io.lines(filename) do
      if not self.blacklist[line] then
        self.blacklist[line] = 0
      end
    end

    return self.blacklist
  end,

    --  Antonio
  --  associate a new black list to the torrent
  --
  assoc_blist = function(self, blist_table)
    self.blacklist = blist_table
  end,

  --- Loads trackers and similar information for a torrent from a magnet link.
  load_from_magnet = function(self, magnet)
    local info_hash_hex = magnet:match("^magnet:%?xt=urn:btih:(%w+)&")
    if not info_hash_hex then
      return false, "Erroneous magnet link"
    end
    self.info_hash = bin.pack("H",info_hash_hex)

    local pos = #info_hash_hex + 21
    local name = magnet:sub(pos,#magnet):match("^&dn=(.-)&")
    if name then
      pos = pos + 4 + #name
    end
    magnet = magnet:sub(pos,#magnet)
    for tracker in magnet:gmatch("&tr=([^&]+)") do
      local trac = url.unescape(tracker)
      table.insert(self.trackers, trac)
    end
    self.size = 50
  end,

  --- Reads a torrent file, loads self.buffer and parses it using
  -- self:parse_buffer(), then self:calc_info_hash()
  --
  -- @param filename, string containing filename of the torrent file
  -- @return boolean indicating whether loading went alright
  -- @return err string with error message if loadin went wrong
  load_from_file = function(self, filename)

    stdnse.verbose2(">>Loading [" .. filename .. "]")

    if not filename then return false, "No filename specified." end
    local file = io.open(filename, "rb")
    if not file then return false, "Cannot open file: "..filename end

    self.buffer = file:read("*a")
    file:close()

    local status, err = self:parse_buffer()      
    if not status then
      return false, "Could not parse file: ".. err
    end

    status, err = self:calc_info_hash()
    if not status then
      return false, "Could not calculate info_hash: " .. err
    end    
    
    self.buffer = nil
    status, err = self:load_trackers()
    if not status then
      return false, "Could not load trackers: " .. err
    end

    status, err = self:calc_torrent_size()
    if not status then
      if not err then err = "" end
      return false, "Could not calculate torrent size: " .. err
    end

    return true
  end,

  --  Antonio
  --  Gets peers available from the loaded trackers
  --  Modified to check current tracker against a table of black listed trackers
  --
  trackers_peers = function(self)

    for _, tracker in ipairs(self.trackers) do
      local status, err, exec

      --  Antonio
      --  do a check if the current tracker is loaded
      --
      exec = true
      if self.blacklist and self.blacklist[tracker] then exec = false end

      if true == exec then
        stdnse.verbose2("  Query[" .. tracker .. "]")  

        if tracker:match("^http://") then -- http tracker
          status, err = self:http_tracker_peers(tracker)
        elseif tracker:match("^udp://") then -- udp tracker
          status, err = self:udp_tracker_peers(tracker)
        else -- unknown tracker
          err = "Unknown tracker protocol for: " .. tracker
          status = false
        end

        --if not status then return false, err end
        if not status then
            stdnse.verbose1("* [%s] error[%s]", tracker, err)
        end
      else
        stdnse.verbose2("  Black listed[" .. tracker .. "]") 
      end
    end

    return true
  end,

  --- Runs the three threads which do a DHT discovery of nodes and peers.
  --
  -- The default timeout for this discovery is 30 seconds but it can be
  -- set through the timeout argument.
  dht_peers = function(self, timeout)
    stdnse.debug1("bittorrent: Starting DHT peers discovery")

    if next(self.peers) == nil then
      stdnse.debug1("bittorrent: No peers detected")
      return
    end

    if not timeout or type(timeout)~="number" then timeout = 30 end

    -- peer node table aka the condvar!
    local pnt = {}
    pnt.peers = {}
    pnt.peers_dht_ping = self.peers

    pnt.nodes = {}
    pnt.nodes_get_peers = {}
    pnt.nodes_find_node = self.nodes

    pnt.node_id = openssl.rand_bytes(20)
    pnt.info_hash = self.info_hash

    local condvar = nmap.condvar(pnt)

    local dht_ping_co = stdnse.new_thread(dht_ping_thread, pnt, timeout)
    local find_node_co = stdnse.new_thread(find_node_thread, pnt, timeout)
    local get_peers_co = stdnse.new_thread(get_peers_thread, pnt, timeout)

    while true do
      stdnse.sleep(0.5)
      if coroutine.status(dht_ping_co) == "dead" and
        coroutine.status(find_node_co) == "dead" and
        coroutine.status(get_peers_co) == "dead" then
        break
      end
    end

    self.peers = pnt.peers
    self.nodes = pnt.nodes

    -- Add some residue nodes and peers
    for peer_ip, peer_info in pairs(pnt.peers_dht_ping) do
      if not self.peers[peer_ip] then
        self.peers[peer_ip] = peer_info
      end
    end
    for node_ip, node_info in pairs(pnt.nodes_find_node) do
      if not self.nodes[node_ip] then
        self.nodes[node_ip] = node_info
      end
    end
    for node_ip, node_info in pairs(pnt.nodes_get_peers) do
      if not self.nodes[node_ip] then
        self.nodes[node_ip] = node_info
      end
    end
  end,

  --- Parses self.buffer, fills self.tor_struct (, self.info_buf no more)
  --
  -- This function is similar to the bdecode function but it has a few
  -- additions for calculating torrent file specific fields
  parse_buffer = function(self)
    local buf = self.buffer
    local info_pos_start = 0 -- self.info_pos_start
    local info_pos_end   = 0 -- self.info_pos_end
    local len = #buf

    -- the main table
    local t = {}
    self.tor_struct = t
    local stack = {}

    local pos = 1
    local cur = {}
    cur.type = "list"
    cur.ref = t
    table.insert(stack, cur)
    cur.ref.type="list"
       
    local bypass = false
    local stack_lvl = nil

    while true do
      if pos >= len or (len-pos)<=-1 then break end
      
      local val_read = string.char( buf:byte(pos) ) 
      local skipiter = false

      if cur.type == "list" then

        -- next element is a string
        if tonumber( val_read ) then
          local str
          str, pos = bdec_string(buf, pos)
          if not str then return nil, "Error parsing string", pos end
          table.insert(cur.ref, str)

        -- next element is a number
        elseif "i" == val_read then
          local num
          num, pos = bdec_number(buf, pos)
          if not num then return nil, "Error parsing number", pos end
          table.insert(cur.ref, num)

        -- next element is a list
        elseif "l" == val_read then
          local new_list = {}
          new_list.type="list"
          table.insert(cur.ref, new_list)

          cur = {}
          cur.type = "list"
          cur.ref = new_list
          table.insert(stack, cur)
          pos = pos+1

        --next element is a dict
        elseif "d" == val_read then
          local new_dict = {}
          new_dict.type = "dict"
          table.insert(cur.ref, new_dict)

          cur = {}
          cur.type = "dict"
          cur.ref = new_dict
          table.insert(stack, cur)
          pos = pos+1

        --escape from the list
        elseif "e" == val_read then

          table.remove(stack, #stack)
          cur = stack[#stack]
          if not cur then return nil, "Error at list closure pos[" .. pos .. "]" end
          pos = pos+1          
        else
          return nil, "Unknown type pos[" .. pos .. "]"
        end

      elseif cur.type == "dict" then
        local item = {} -- {key = <string>, value = <.*>}

        -- key
        if tonumber( val_read ) then
          local str
          str, pos = bdec_string(buf, pos)
          if not str then return nil, "Error parsing string pos[" .. pos .. "]" end
          item.key = str

          -- fill the info_pos_start
          -- set the stack index
          -- 
          if item.key == "info" then
            info_pos_start = pos 
            stack_lvl = #stack            
            stdnse.verbose2("  parse_buffer [ + 4:info ] @[" .. info_pos_start .. "]")
          end

        -- escape
        elseif "e" == val_read then
          
          -- fill the info_pos_end until #stack higher than index
          -- this bit of code is crucial for correct hashkey calculation!
          --
          if stack_lvl and #stack >= stack_lvl then
            if 1 < (pos - info_pos_end) then info_pos_end = pos end
            if #stack == stack_lvl then stack_lvl = nil end

            stdnse.verbose2("  parse_buffer [ - 4:info ] @[" .. info_pos_end .. "]")
          end   

          table.remove(stack, #stack)
          cur = stack[#stack]
          if not cur then return nil, "Error dict closure pos[" .. pos .. "]" end
          pos = pos+1
          
          -- Antonio
          -- exit here
          skipiter = true 
        else
          return nil, "Dictionary key invalid pos[" .. pos .. "] value[" .. val_read .. "]"
        end
        
        if false == skipiter then
          val_read = string.char( buf:byte(pos) ) 

          -- value
          -- next element is a string
          if tonumber( val_read ) then
            local str
            str, pos = bdec_string(buf, pos)
            if not str then return nil, "Error parsing string pos[" .. pos .. "]" end
            item.value = str
            table.insert(cur.ref, item)

            --next element is a number
          elseif "i" == val_read then
            local num
            num, pos = bdec_number(buf, pos)
            if not num then return nil, "Error parsing number pos[" .. pos .. "]" end
            item.value = num
            table.insert(cur.ref, item)

          -- next element is a list
          elseif "l" == val_read then
            item.value = {}
            item.value.type = "list"
            table.insert(cur.ref, item)

            cur = {}
            cur.type = "list"
            cur.ref = item.value

            table.insert(stack, cur)
            pos = pos+1

          --next element is a dict
          elseif "d" == val_read then
            item.value = {}
            item.value.type = "dict"
            table.insert(cur.ref, item)

            cur = {}
            cur.type = "dict"
            cur.ref = item.value

            table.insert(stack, cur)
            pos = pos+1     

          --escape from the dict
          elseif "e" == val_read then
            table.remove(stack, #stack)
            cur = stack[#stack]
            if not cur then return false, "Error at dict closure pos[" .. pos .. "]" end
            pos = pos+1
          else
            return false, "Error parsing file, unknown type pos[" .. pos .. "]"
          end
        end
      else
        return false, "Invalid type of structure. Fix the code."
      end
    end -- while(true)

    -- here we have to check if the stack level is up running
    -- note that code is slightly different from the
    -- other stack index check
    --
    if stack_lvl and #stack > stack_lvl then            
      stdnse.verbose1("  parse_buffer [ ! 4:info ] info_pos_end[" .. info_pos_end .. "] pos[" .. pos .. "]")

      info_pos_end = pos - 1
    end   

    -- update torrent's indexes
    --
    self.info_pos_start = info_pos_start
    self.info_pos_end   = info_pos_end

    return true
  end,

  --- Loads the list of trackers in self.trackers from self.tor_struct
  load_trackers = function(self)
    local tor = self.tor_struct
    local trackers = {}
    self.trackers = trackers

    -- load the announce tracker
    --
    if tor and tor[1] and tor[1][1] and tor[1][1].key and
      tor[1][1].key == "announce" and tor[1][1].value then

      local _tracker = nil

      if tor[1][1].value.type and tor[1][1].value.type == "list" then

        for _, trac in ipairs(tor[1][1].value) do
          _tracker = trac
          break
        end
      else        
        _tracker = tor[1][1].value
      end

      if _tracker then
        table.insert(trackers, _tracker)
        stdnse.verbose3("  load_trackers announce tracker[" .. _tracker .. "]")
      end

    else
      local errstr = "Announce field not found"
      stdnse.verbose1("* load_trackers Error: " .. errstr)
      return false, errstr
    end

    -- load the announce-list trackers
    --
    if tor[1][2] and tor[1][2].key and tor[1][2].key == "announce-list" and tor[1][2].value then
      for _, trac_list in ipairs(tor[1][2].value) do
        if trac_list.type and trac_list.type == "list" then
          for _, trac in ipairs(trac_list) do
            table.insert(trackers, trac)
          end
        else
          table.insert(trackers, trac_list)
        end
      end
    end

    --  purge the list, remove duplicated entries
    --
    local _tkswap = {}
    local found = false

    for pos, element in ipairs( trackers ) do
      found = false
      for _, value in pairs( _tkswap ) do
        if value == element then
          found = true
          break
        end
      end

      if not found then
        table.insert(_tkswap, element)
      end
    end
    table.sort(_tkswap)

    --  finish up
    --
    self.trackers = _tkswap
    trackers      = nil

    if 1 < nmap.verbosity() then
      io.write("\nSorted trackers list:\n")
      for pos, val in ipairs( self.trackers ) do
        io.write("\t" .. val .. "\n")
      end    
    end

    return true
  end,

  --- Calculates the size of the torrent in bytes
  -- @param tor, decoded bencoded torrent file structure
  -- @ 
  calc_torrent_size = function(self)
    local tor = self.tor_struct
    local size = 0

    if tor[1].type ~= "dict" then
      local errstring = "Cannot find dictionary in file"

      stdnse.verbose1("* " .. errstring)
      return false, errstring
    end

    for _, m in ipairs(tor[1]) do
      if m.key == "info" then

        for _, n in ipairs(m.value) do
          if n.key == "files" then      --  type is a list

            for field, f in ipairs(n.value) do
              for field2, k in ipairs(f) do
                if k.key == "length" then
                  size = size + k.value

                  stdnse.verbose3("  Length sum[" .. size .. "] read[" .. k.value .. "]")
                  break
                end

              end
            end
            break

          elseif n.key == "length" then
            size = n.value

            stdnse.verbose3("  Fixed length[" .. size .. "]")
            break
          end
        end
      end
    end

    self.size=size
    if size == 0 then
      return false, "File size: 0"
    end

    stdnse.verbose1(string.format("  Torrent size [%.0fb] [%.2f Gb]", size, (size /(1024*1024*1024))))
    return true, ""

  end,

  --- Calculates the info hash using self.info_buf.
  --
  -- The info_hash value is used in many communication transactions for
  -- identifying the file shared among the bittorrent peers
  calc_info_hash = function(self)

    if not self.info_pos_start or not self.info_pos_end then
      return false, "No [info field] found"
    end

    local info_field   = string.sub(self.buffer, self.info_pos_start, self.info_pos_end)
    local info_hash    = openssl.sha1(info_field)
    self.info_hash_url = url.escape(info_hash)
    self.info_hash     = info_hash

    --  output debugging data
    --
    if 4 < nmap.verbosity() then hex_dump("self.buffer", self.buffer) end
    if 3 < nmap.verbosity() then 
      local triminfo = string.sub(info_field, #info_field - 512, #info_field)
      hex_dump("info_field [last 512]", triminfo) 
    end
    if 2 < nmap.verbosity() then hex_dump("info_hash", info_hash) end 

    return true
  end,

  --- Generates a peer_id similar to the ones generated by Ktorrent version 4.1.1
  generate_peer_id = function(self)
    -- let's fool trackers that we use ktorrent just in case they control
    -- which client they give peers to
    local fingerprint = "-KT4110-"
    local chars = {}

    -- the full length of a peer_id is 20 bytes but we already have 8 from the fingerprint
    return fingerprint .. stdnse.generate_random_string(12,
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
  end,

  --- Gets the peers from a http tracker when supplied the URL of the tracker
  http_tracker_peers = function(self, tracker)  
    local url, trac_port, url_ext = tracker:match("^http://(.-):(%d-)(/.*)")

    if (not url) or (not trac_port) then
      --probably no port specification
      url, url_ext = tracker:match("^http://(.-)(/.*)")
      trac_port = "80"
    end

    if (not url) or (not trac_port) or (not tonumber(trac_port)) then
      return false, "Cannot parse tracker address"
    end    

    trac_port = tonumber(trac_port)
    -- a http torrent tracker request specifying the info_hash of the torrent, our random
    -- generated peer_id (with some mods), notifying the tracker that we are just starting
    -- to download the torrent, with 0 downloaded and 0 uploaded bytes, an as many bytes
    -- left to download as the size of the torrent, requesting 200 peers in a compact format
    -- because some trackers refuse connection if they are not explicitly requested that way
    local request = url_ext .. 
      "?info_hash=" .. self.info_hash_url ..
      "&peer_id=" .. self:generate_peer_id() ..
      "&port=" .. self.port .. 
      "&uploaded=0&downloaded=0&left=" .. self.size ..
      "&event=started&numwant=200&compact=1"

    local response = http.get(url, trac_port, request, { timeout = 2000 })

    if not response or not response.body then
      return false, "No response from tracker."
    end

    if 0 == #response.body then
      return false, "Empty response from tracker."
    end

    --  minor check against a request to a bad company
    --
    local a, b, test = false
    local may_respond = {"<html>", "<!DOCTYPE html>", "<title>"}

    for _, txt_err in ipairs(may_respond) do
      a, b = string.find(response.body, txt_err) 
      if a or b then
        test = true
        break
      end
    end

    if true == test then
      hex_dump( "response body", response.body )
      return false, "Invalid bittorrent protocol message"
    end

    --[[
      Antonio

    -->> VALID RESPONSE
    00000000  64 31 34 3A 66 61 69 6C 75 72 65 20 72 65 61 73  d14:failure reas
    00000010  6F 6E 32 30 3A 75 6E 72 65 67 69 73 74 65 72 65  on20:unregistere
    00000020  64 20 74 6F 72 72 65 6E 74 65                    d torrente
    -->> end VALID RESPONSE
    ]]

    if 2 < nmap.verbosity() then
      hex_dump( "VALID RESPONSE", response.body )
    end

    local status, t = bdecode(response.body)

    if not status then
      return false, "Could not parse response:" .. t
    end

    if not t[1] then
      return false, "Server reply is empty, aborting request."
    end

    local peers_add = 0
    local peers_dup = 0

    for _, k in ipairs(t[1]) do
      if k.key == "peers" and type(k.value) == "string" then

        -- binary peers
        for bin_ip, bin_port in string.gmatch(k.value, "(....)(..)") do
          local ip = string.format("%d.%d.%d.%d",
            bin_ip:byte(1), bin_ip:byte(2), bin_ip:byte(3), bin_ip:byte(4))
          local port = bit.lshift(bin_port:byte(1), 8) + bin_port:byte(2)
          local peer = {}
          peer.ip = ip
          peer.port = port

          if not self.peers[peer.ip] then
            self.peers[peer.ip] = {}
            self.peers[peer.ip].port = peer.port
            if peer.id then self.peers[peer.ip].id = peer.id end
            peers_add = peers_add + 1
          else
            peers_dup = peers_dup + 1
          end
        end
        break

      elseif k.key == "peers" and type(k.value) == "table" then
        -- table peers
        for _, peer_table in ipairs(k.value) do
          local peer = {}
          for _, f in ipairs(peer_table) do
            if f.key == "peer_id" then
              peer.id = f.value
            elseif f.key == "ip" then
              peer.ip = f.value
            elseif f.key == "port" then
              peer.port = f.value
            end
          end
          if not peer.id then peer.id = "" end
          if not self.peers[peer.ip] then
            self.peers[peer.ip] = {}
            self.peers[peer.ip].port = peer.port
            self.peers[peer.ip].id = peer.id
            peers_add = peers_add + 1
          else
            self.peers[peer.ip].port = peer.port
            peers_dup = peers_dup + 1
          end
        end
        break
      end
    end

    --  Antonio
    --  don't have a clue, use fuzzy logic
    local p_seeders  = math.floor(peers_add / 6)
    local p_leechers = peers_add - p_seeders
    self.num_seeders = self.num_seeders + p_seeders
    self.num_leeches = self.num_leeches + p_leechers

    stdnse.verbose1("  [" .. tracker .. "] seeders[" .. p_seeders .. "] leechers[" .. p_leechers .. "]")

    if 1 < nmap.verbosity() then
      if (0 < peers_add) or (0 < peers_dup) then
        io.write(string.format("\nPeers list (%d new, %d dup):\n", peers_add, peers_dup))
        for peer_ip in pairs(self.peers) do
          io.write("\t" .. peer_ip .. ":" .. self.peers[peer_ip].port .. "\n")
        end
      end
    end    

    return true
  end,

  --- Gets the peers from udp trackers when supplied the URL of the tracker.
  --
  -- First we establish a connection to the udp server and then we can request
  -- peers. For a good specification refer to:
  -- http://www.rasterbar.com/products/libtorrent/udp_tracker_protocol.html
  udp_tracker_peers = function(self, tracker)

    local host, port, host_ext = tracker:match("^udp://(.-):(%d-)(/.*)")

    if (not host) or (not port) then
      --probably no ext specification
      host, port = tracker:match("^udp://(.-):(.+)")
      host_ext = ""
    end

    if (not host) or (not port) or(not tonumber(port))  then
      return false, "Cannot parse tracker address"
    end

    local socket = nmap.new_socket("udp")

    -- The initial connection parameters' variables have hello_ prefixed names
    local hello_transaction_id = openssl.rand_bytes(4)
    local hello_action = "00 00 00 00" -- 0 for a connection request
    local hello_connection_id = "00 00 04 17 27 10 19 80" -- identification of the protocol
    local hello_packet = bin.pack("HHA", hello_connection_id, hello_action, hello_transaction_id)
    local status, msg = socket:sendto(host, port, hello_packet)
    if not status then return false, msg end

    status, msg = socket:receive()
    if not status then 
      return false, "A socket receive failed: " .. msg
    end

    local _, r_action, r_transaction_id, r_connection_id  = bin.unpack("H4A4A8", msg)

    r_action = tonumber( r_action )

    if (not r_action) or (not r_transaction_id) or (not r_connection_id) then
      return false, "Tracker handshake bogus"
    end

    if 0 < r_action then
      return false, "Tracker handshake out of order"
    end

    if not (r_transaction_id == hello_transaction_id) then
      return false, "Tracker reply not for us"
    end

    -- established a connection, and now for an announce message, to which a
    -- response holds the peers

    -- the announce connection parameters' variables are prefixed with a_
    local a_action = "00 00 00 01" -- 1 for announce
    local a_transaction_id = openssl.rand_bytes(4)
    local a_info_hash = self.info_hash -- info_hash of the torrent
    local a_peer_id = self:generate_peer_id()
    local a_downloaded = "00 00 00 00 00 00 00 00" -- 0 bytes downloaded

    --  Antonio
    --  a note on: stdnse.tohex(self.size)
    --  here we go from 64bits to 32bits and big numbers will
    --  get a negative value, making the format( "%x", a negative value)
    --  to fail at run time.
    local temp_size = self.size
    if 0xefffffff < temp_size then
      temp_size = 0xefffffff
      stdnse.verbose1("* Size casted to [0xefffffff]")
    end

    local a_left = stdnse.tohex(temp_size)  -- bytes left to download is the size of torrent
    a_left = string.rep("0", 16-#a_left) .. a_left

    local a_uploaded = "00 00 00 00 00 00 00 00" -- 0 bytes uploaded
    local a_event = "00 00 00 02" -- value of 2 for started torrent
    local a_ip = "00 00 00 00" -- not necessary to specify our ip since it's resolved
      -- by tracker automatically
    local a_key = openssl.rand_bytes(4)
    local a_num_want = "FF FF FF FF" -- request for many many peers
    local a_port = "1A E1" -- 6881 the port "we are listening on"
    local a_extensions = "00 00" -- client recognizes no extensions of the bittorrent proto
    local announce_packet = bin.pack("AHAAAHHHHHAHHH", r_connection_id, a_action, a_transaction_id,
      a_info_hash, a_peer_id, a_downloaded, a_left, a_uploaded, a_event, a_ip, a_key,
      a_num_want, a_port, a_extensions)


    status, msg = socket:sendto(host, port, announce_packet)
    if not status then
      return false, "Couldn't send announce, reason: "..msg
    end

    status, msg = socket:receive()
    if not status then
      return false, "No response to announce, reason: "..msg
    end

    --[[
    actions
    The action fields has the following encoding:

    connect = 0
    announce = 1
    scrape = 2
    error = 3 (only in server replies)
    ]]

    local p_pos, p_action, p_transaction_id = bin.unpack("H4A4", msg)

    p_action = tonumber(p_action)

    --  got an error from the server
    --
    if 3 == p_action then
        local m_pos, text = bin.unpack("z", msg, p_pos)

        --  Antonio TBD
        --  raise a flag here if we get a bad hash key check
        --  <unregistered torrent>
        --
        return false, "Server replied an error string: " .. text
    end

    -- the action field in the response has to be 1 (like the sent response)
    --
    if not (p_action == 1) then
      return false, "Action in response to announce erroneous"
    end

    if not (p_transaction_id == a_transaction_id) then
      return false, "Transaction ID not equal to original"
    end

    if 12 > (#msg - p_pos) then
      return false, "Data truncated"
    end

    local p_interval, p_leechers, p_seeders
    p_pos, p_interval, p_leechers, p_seeders = bin.unpack("H4H4H4", msg, p_pos)

    if (p_interval) and (p_leechers) and (p_seeders) then
      p_interval  = tonumber(p_interval, 16)
      p_leechers  = tonumber(p_leechers, 16)
      p_seeders   = tonumber(p_seeders,  16)

      if (not p_interval) or (not p_leechers) or (not p_seeders) then
        return false, "Data conversion error"
      end 
    else
      hex_dump("H4H4H4", msg)
      return false, "Data corrupted"
    end

    stdnse.verbose1("  [" .. tracker .. "] seeders[" .. p_seeders .. "] leechers[" .. p_leechers .. "]")

    -- parse peers from msg:sub(p_pos, #msg)

    local peers_add = 0
    local peers_dup = 0

    for bin_ip, bin_port in msg:sub(p_pos,#msg):gmatch("(....)(..)") do
      local _ip = string.format("%d.%d.%d.%d",
        bin_ip:byte(1), bin_ip:byte(2), bin_ip:byte(3), bin_ip:byte(4))
      local _port = bit.lshift(bin_port:byte(1), 8) + bin_port:byte(2)

      if not self.peers[_ip] then
        local peer = {}
        peer.ip    = _ip
        peer.port  = _port

        self.peers[_ip] = peer 

        peers_add = peers_add + 1
      else
        peers_dup = peers_dup + 1
      end
    end

    --  update stats
    --
    if p_seeders > self.num_seeders then self.num_seeders = p_seeders end
    if p_leechers > self.num_leeches then self.num_leeches = p_leechers end

    --  Antonio
    --  output shall be controlled by the verbosity level
    --
    if 1 < nmap.verbosity() then
      if (0 < peers_add) or (0 < peers_dup) then
        io.write(string.format("\nPeers list (%d new, %d dup):\n", peers_add, peers_dup))
        for peer_ip in pairs(self.peers) do
          io.write("\t" .. peer_ip .. ":" .. self.peers[peer_ip].port .. "\n")
        end
      end
    end

    return true
  end

}

return _ENV;
