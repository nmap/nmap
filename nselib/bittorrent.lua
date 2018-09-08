--- Bittorrent and DHT protocol library which enables users to read
-- information from a torrent file, decode bencoded (bittorrent
-- encoded) buffers, find peers associated with a certain torrent and
-- retrieve nodes discovered during the search for peers.
--
-- For more information on the Bittorrent and DHT protocol go to:
-- http://www.bittorrent.org/beps/bep_0000.html
--
-- The library contains the class <code>Torrent</code> and the function bdecode(buf)
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
-- @author Gorjan Petrovski
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

local ipOps = require "ipOps"
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
local rand = require "rand"
_ENV = stdnse.module("bittorrent", stdnse.seeall)

--- Given a buffer and a starting position in the buffer, this function decodes
-- a bencoded string there and returns it as a normal lua string, as well as
-- the position after the string
local bdec_string = function(buf, pos)
  local len = tonumber(string.match(buf, "^(%d+):", pos) or "nil", 10)
  if not len then
    return nil, pos
  end
  pos = string.find(buf, ":", pos, true) + 1

  local str = buf:sub(pos,pos+len-1)
  pos = pos+len
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
  local len = #buf

  -- the main table
  local t = {}
  local stack = {}

  local pos = 1
  local cur = {}
  cur.type = "list"
  cur.ref = t
  table.insert(stack, cur)
  cur.ref.type="list"
  cur.ref.start = pos

  while pos <= len do

    if cur.type == "list" then
      -- next element is a string
      if tonumber( string.char( buf:byte(pos) ) ) then
        local str
        str, pos = bdec_string(buf, pos)
        if not str then return nil, "Error parsing string", pos end
        table.insert(cur.ref, str)

      -- next element is a number
      elseif "i" == string.char(buf:byte(pos)) then
        local num
        num, pos = bdec_number(buf, pos)
        if not num then return nil, "Error parsing number", pos end
        table.insert(cur.ref, num)

      -- next element is a list
      elseif "l" == string.char(buf:byte(pos)) then
        local new_list = {}
        new_list.type="list"
        table.insert(cur.ref, new_list)

        cur = {}
        cur.type = "list"
        cur.ref = new_list
        cur.ref.start = pos
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
        cur.ref.start = pos
        table.insert(stack, cur)
        pos = pos+1

      --escape from the list
      elseif "e" == string.char(buf:byte(pos)) then
        stack[#stack].ref.endpos = pos
        table.remove(stack, #stack)
        cur = stack[#stack]
        if not cur then return nil, "Problem with list closure:", pos end
        pos = pos+1

      -- trailing whitespace
      elseif string.match(buf, "^%s*$", pos) then
        pos = len+1
      else
        return nil, "Unknown type found.", pos
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
        stack[#stack].ref.endpos = pos
        table.remove(stack, #stack)
        cur = stack[#stack]
        if not cur then return nil, "Problem with list closure:", pos end
        pos = pos+1

        escape_flag = true

      else
        return nil, "A dict key has to be a string or escape.", pos
      end

      if not escape_flag then
        -- value
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
          cur.ref.start = pos

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
          cur.ref.start = pos

          table.insert(stack, cur)
          pos = pos+1

        --escape from the dict
        elseif "e" == string.char(buf:byte(pos)) then
          stack[#stack].ref.endpos = pos
          table.remove(stack, #stack)
          cur = stack[#stack]
          if not cur then return false, "Problem with dict closure", pos end
          pos = pos+1
        else
          return false, "Error parsing file, unknown type found", pos
        end
      end -- if not escape_flag
    else -- elseif type == "dict"
      return false, "Invalid type of structure. Fix the code."
    end
  end -- while(true)

  -- The code below is commented out because some responses from trackers are
  -- not according to standards

  -- next(stack) is never gonna be nil because we're always in the main list
  -- next(stack, next(stack)) should be nil if we're in the main list
  --    if next(stack, next(stack)) then
  --      return false, "Probably file incorrect format"
  --    end

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

  local transaction_id = 0
  local start = os.time()

  while os.time() - start < timeout do
    local num_peers = 0
    --ping a 100 peers if there are as many

    while next(pnt.peers_dht_ping) ~= nil and num_peers <= 100 and os.time() - start < timeout do
      num_peers = num_peers +1
      local peer_ip, peer_info = next(pnt.peers_dht_ping)

      --transaction ids are 2 bytes long
      peer_info.transaction_id = string.pack(">I2",transaction_id % 0xffff)

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
        pnt.info_hash .. "e1:q9:find_node1:t2:" .. rand.random_string(2) .. "1:y1:qe"

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
          local pos = 1
          while pos < #nodes do
            local node_id, node_ip, node_port
            node_id, node_ip, node_port, pos = string.unpack(">c20 I4 I2", nodes, pos)
            node_ip = ipOps.fromdword(node_ip)

            local node_info = {
              port = node_port,
              node_id = node_id,
            }

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
        pnt.info_hash .. "e1:q9:get_peers1:t2:" .. rand.random_string(2) .. "1:y1:qe"

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

          local pos = 1
          while pos < #nodes do
            local node_id, node_ip, node_port
            node_id, node_ip, node_port, pos = string.unpack(">c20 I4 I2", nodes, pos)
            node_ip = ipOps.fromdword(node_ip)

            local node_info = {
              port = node_port,
              node_id = node_id,
            }

            if not (pnt.nodes[node_ip] or pnt.nodes_get_peers[node_ip] or
              pnt.nodes_find_node[node_ip]) then
              pnt.nodes_find_node[node_ip] = node_info
            end
          end

        elseif peers then

          for _, peer in ipairs(peers) do
            local ip, port = string.unpack(">I4 I2", peer)
            ip = ipOps.fromdword(ip)

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
    local o ={}
    setmetatable(o, self)
    self.__index = self

    self.buffer = nil -- buffer to keep the torrent
    self.tor_struct = nil -- the decoded structure from the bencoded buffer

    self.trackers = {} -- list of trackers  {"tr1", "tr2", "tr3"...}
    self.port = 6881 -- port on which our peer "listens" / it doesn't actually listen
    self.size = nil -- size of the files in the torrent

    self.info_buf = nil --buffer for info_hash
    self.info_hash = nil --info_hash binary string
    self.info_hash_url = nil --info_hash escaped

    self.peers = {} -- peers = { [ip1] = {port1, id1}, [ip2] = {port2, id2}, ...}
    self.nodes = {} -- nodes = { [ip1] = {port1, id1}, [ip2] = {port2, id2}, ...}
    return o
  end,

  --- Loads trackers and similar information for a torrent from a magnet link.
  load_from_magnet = function(self, magnet)
    local info_hash_hex = magnet:match("^magnet:%?xt=urn:btih:(%w+)&")
    if not info_hash_hex then
      return false, "Erroneous magnet link"
    end
    self.info_hash = stdnse.fromhex(info_hash_hex)

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
    if not filename then return false, "No filename specified." end

    local file = io.open(filename, "r")
    if not file then return false, "Cannot open file: "..filename end

    self.buffer = file:read("a")
    file:close()

    local status, err = self:parse_buffer()
    if not status then
      return false, "Could not parse file: ".. err
    end

    status, err = self:calc_info_hash()
    if not status then
      return false, "Could not calculate info_hash: " .. err
    end

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

  --- Gets peers available from the loaded trackers
  trackers_peers = function(self)
    for _, tracker in ipairs(self.trackers) do
      local status, err

      if tracker:match("^http://") then -- http tracker
        status, err = self:http_tracker_peers(tracker)
        if not status then
          stdnse.debug1("Could not get peers from tracker %s, reason: %s",tracker, err)
        end
      elseif tracker:match("^udp://") then -- udp tracker
        status, err = self:udp_tracker_peers(tracker)
        if not status then
          stdnse.debug1("Could not get peers from tracker %s, reason: %s",tracker, err)
        end
      else -- unknown tracker
        stdnse.debug1("Unknown tracker protocol for: "..tracker)
      end
      --if not status then return false, err end
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

    -- peer node table a.k.a. the condvar!
    local pnt = {}
    pnt.peers = {}
    pnt.peers_dht_ping = self.peers

    pnt.nodes = {}
    pnt.nodes_get_peers = {}
    pnt.nodes_find_node = self.nodes

    pnt.node_id = rand.random_string(20)
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

  --- Parses self.buffer, fills self.tor_struct, self.info_buf
  --
  -- This function is similar to the bdecode function but it has a few
  -- additions for calculating torrent file specific fields
  parse_buffer = function(self)
    local status, t = bdecode(self.buffer)
    if not status then
      return status, t
    end
    self.tor_struct = t

    for _, i in ipairs(t[1]) do
      if i.key == "info" then
        self.info_buf = self.buffer:sub(i.value.start, i.value.endpos)
        break
      end
    end

    return true
  end,

  --- Loads the list of trackers in self.trackers from self.tor_struct
  load_trackers = function(self)
    local tor = self.tor_struct
    local trackers = {}
    self.trackers = trackers

    -- load the announce tracker
    if tor and tor[1] and tor[1][1] and tor[1][1].key and
      tor[1][1].key == "announce" and tor[1][1].value then

      if tor[1][1].value.type and tor[1][1].value.type == "list" then
        for _, trac in ipairs(tor[1][1].value) do
          table.insert(trackers, trac)
        end
      else
        table.insert(trackers, tor[1][1].value)
      end
    else
      return nil, "Announce field not found"
    end

    -- load the announce-list trackers
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

    return true
  end,

  --- Calculates the size of the torrent in bytes
  -- @param tor, decoded bencoded torrent file structure
  calc_torrent_size = function(self)
    local tor = self.tor_struct
    local size = nil
    if tor[1].type ~= "dict" then return nil, "first element not a dict" end
    for _, m in ipairs(tor[1]) do
      if m.key == "info" then
        if m.value.type ~= "dict" then return nil, "info is not a dict" end
        for _, n in ipairs(m.value) do
          if n.key == "files" then
            size = 0
            for _, f in ipairs(n.value) do
              for _, k in ipairs(f) do
                if k.key == "length" then
                  size = size + k.value
                  break
                end
              end
            end
            break
          elseif n.key == "length" then
            size = n.value
            break
          end
        end
      end
    end
    self.size=size
    if size == 0 then return false, "size is zero" end
    return true
  end,

  --- Calculates the info hash using self.info_buf.
  --
  -- The info_hash value is used in many communication transactions for
  -- identifying the file shared among the bittorrent peers
  calc_info_hash = function(self)
    local info_hash = openssl.sha1(self.info_buf)
    self.info_hash_url = url.escape(info_hash)
    self.info_hash = info_hash
    self.info_buf = nil
    return true
  end,

  --- Generates a peer_id similar to the ones generated by Ktorrent version 4.1.1
  generate_peer_id = function(self)
    -- let's fool trackers that we use ktorrent just in case they control
    -- which client they give peers to
    local fingerprint = "-KT4110-"
    local chars = {}
    -- the full length of a peer_id is 20 bytes but we already have 8 from the fingerprint
    return fingerprint .. rand.random_string(12,
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
  end,

  --- Gets the peers from a http tracker when supplied the URL of the tracker
  http_tracker_peers = function(self, tracker)
    local url, trac_port, url_ext = tracker:match("^http://(.-):(%d-)(/.*)")
    if not url then
      --probably no port specification
      url, url_ext = tracker:match("^http://(.-)(/.*)")
      trac_port = "80"
    end

    trac_port = tonumber(trac_port)
    -- a http torrent tracker request specifying the info_hash of the torrent, our random
    -- generated peer_id (with some mods), notifying the tracker that we are just starting
    -- to download the torrent, with 0 downloaded and 0 uploaded bytes, an as many bytes
    -- left to download as the size of the torrent, requesting 200 peers in a compact format
    -- because some trackers refuse connection if they are not explicitly requested that way
    local request = "?info_hash=" .. self.info_hash_url .. "&peer_id=" .. self:generate_peer_id() ..
      "&port=" .. self.port .. "&uploaded=0&downloaded=0&left=" .. self.size ..
      "&event=started&numwant=200&compact=1"

    local response = http.get(url, trac_port, url_ext .. request, nil)

    if not response or not response.body then
      return false, "No response from tracker: " .. tracker
    end

    local status, t = bdecode(response.body)

    if not status then
      return false, "Could not parse response:"..t
    end

    if not t[1] then
      return nil, "No response from server."
    end

    for _, k in ipairs(t[1]) do
      if k.key == "peers" and type(k.value) == "string" then
        -- binary peers
        local pos=1
        while pos < #k.value do
          local ip, port
          ip, port, pos = string.unpack(">I4 I2", k.value, pos)
          ip = ipOps.fromdword(ip)

          if not self.peers[ip] then
            self.peers[ip] = {}
            self.peers[ip].port = port
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
          else
            self.peers[peer.ip].port = peer.port
          end
        end
        break
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
    local host, port = tracker:match("^udp://(.-):(%d+)")
    port = tonumber(port)
    if (not host) or (not port) then
      return false, "Could not parse tracker url"
    end

    local socket = nmap.new_socket("udp")

    -- The initial connection parameters' variables have hello_ prefixed names
    local hello_transaction_id = rand.random_string(4)
    local hello_packet = "\0\0\x04\x17\x27\x10\x19\x80" -- identification of the protocol
    .. "\0\0\0\0" -- 0 for a connection request
    .. hello_transaction_id
    local status, msg = socket:sendto(host, port, hello_packet)
    if not status then return false, msg end

    status, msg = socket:receive()
    if not status then return false, "Could not connect to tracker:"..tracker.." reason:"..msg end

    local r_action, r_transaction_id, r_connection_id  =string.unpack(">I4c4c8",msg)

    if not (r_transaction_id == hello_transaction_id) then
      return false, "Received transaction ID not equivalent to sent transaction ID"
    end

    -- the action in the response has to be 0 too
    if r_action ~= 0 then
      return false, "Wrong action field, usually caused by an erroneous request"
    end

    -- established a connection, and now for an announce message, to which a
    -- response holds the peers

    -- the announce connection parameters' variables are prefixed with a_
    local a_action = 1 -- 1 for announce
    local a_transaction_id = rand.random_string(4)
    local a_info_hash = self.info_hash -- info_hash of the torrent
    local a_peer_id = self:generate_peer_id()
    local a_downloaded = 0 -- 0 bytes downloaded

    local a_left = self.size  -- bytes left to download is the size of torrent

    local a_uploaded = 0 -- 0 bytes uploaded
    local a_event = 2 -- value of 2 for started torrent
    local a_ip = 0 -- not necessary to specify our ip since it's resolved
      -- by tracker automatically
    local a_key = rand.random_string(4)
    local a_num_want = 0xFFFFFFFF -- request for many many peers
    local a_port = 6881 -- the port "we are listening on"
    local a_extensions = 0 -- client recognizes no extensions of the bittorrent proto
    local announce_packet = string.pack(">c8 I4 c4 c40 c20 I8 I8 I8 I4 I4 c4 I4 I2 I2",
      r_connection_id, a_action, a_transaction_id,
      a_info_hash, a_peer_id, a_downloaded, a_left, a_uploaded, a_event, a_ip, a_key,
      a_num_want, a_port, a_extensions)

    status, msg = socket:sendto(host, port, announce_packet)
    if not status then
      return false, "Couldn't send announce message, reason: "..msg
    end

    status, msg = socket:receive()
    if not status then
      return false, "Didn't receive response to announce message, reason: "..msg
    end
    local p_action, p_transaction_id, p_interval, p_leechers, p_seeders, pos = string.unpack(">I4 c4 I4 I4 I4",msg)

    -- the action field in the response has to be 1 (like the sent response)
    if not (p_action == 1) then
      return false, "Action in response to announce erroneous"
    end
    if not (p_transaction_id == a_transaction_id) then
      return false, "Transaction ID in response to announce message not equal to original"
    end

    -- parse peers from msg:sub(pos, #msg)

    while pos < #msg do
      local ip, port
      ip, port, pos = string.unpack(">I4 I2", msg, pos)
      ip = ipOps.fromdword(ip)
      if not self.peers[ip] then
        self.peers[ip] = {}
      end
      self.peers[ip].port = port
    end

    return true
  end
}



return _ENV;
