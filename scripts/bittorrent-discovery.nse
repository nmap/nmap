local stdnse = require "stdnse"
local table = require "table"
local target = require "target"


local bittorrent = stdnse.silent_require "bittorrent"

description = [[
Discovers bittorrent peers sharing a file based on a user-supplied
torrent file or magnet link.  Peers implement the Bittorrent protocol
and share the torrent, whereas the nodes (only shown if the
include-nodes NSE argument is given) implement the DHT protocol and
are used to track the peers. The sets of peers and nodes are not the
same, but they usually intersect.

If the <code>newtargets</code> script-arg is supplied it adds the discovered
peers as targets.
]]

---
-- @usage
-- nmap --script bittorrent-discovery --script-args newtargets,bittorrent-discovery.torrent=<torrent_file>
--
-- @args bittorrent-discovery.torrent a string containing the filename of the torrent file
-- @args bittorrent-discovery.magnet a string containing the magnet link of the torrent
-- @args bittorrent-discovery.timeout desired (not actual) timeout for the DHT discovery (default = 30s)
-- @args bittorrent-discovery.include-nodes boolean selecting whether to show only nodes
--
-- @output
-- | bittorrent-discovery:
-- |   Peers:
-- |     97.88.178.168
-- |     89.100.184.36
-- |     86.185.55.212
-- |     Total of 3 peers discovered
-- |   Nodes:
-- |     68.103.0.189
-- |     67.164.32.71
-- |     24.121.13.69
-- |     207.112.100.224
-- |     Total of 4 nodes discovered
-- |_  Use the newtargets script-arg to add the results as targets
--

author = "Gorjan Petrovski"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","safe"}


prerule = function()
  if not stdnse.get_script_args(SCRIPT_NAME..".torrent") and
      not stdnse.get_script_args(SCRIPT_NAME..".magnet") then
    stdnse.debug3("Skipping '%s' %s, No magnet link or torrent file arguments.", SCRIPT_NAME, SCRIPT_TYPE)
    return false
  end
  return true
end

action = function()
  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME..".timeout"))
  local filename = stdnse.get_script_args(SCRIPT_NAME..".torrent")
  local magnet = stdnse.get_script_args(SCRIPT_NAME..".magnet")
  local include_nodes = stdnse.get_script_args(SCRIPT_NAME..".include-nodes")

  local t = bittorrent.Torrent:new()
  if filename then
    t:load_from_file(filename)
  elseif magnet then
    t:load_from_magnet(magnet)
  end
  t:trackers_peers()
  t:dht_peers(timeout)

  local output = {}
  local peers = {}
  peers.name = "Peers:"
  local nodes = {}
  nodes.name = "Nodes:"

  -- add peers
  if target.ALLOW_NEW_TARGETS then
    for peer_ip in pairs(t.peers) do
      target.add(peer_ip)
      table.insert(peers, peer_ip)
    end
    if #peers>0 then
      table.insert(peers, "Total of "..#peers.." peers discovered")
    end
  else
    for peer_ip in pairs(t.peers) do
      table.insert(peers, peer_ip)
    end
    if #peers>0 then
      table.insert(peers, "Total of "..#peers.." peers discovered")
    end
  end

  -- add nodes
  if target.ALLOW_NEW_TARGETS and include_nodes then
    for node_ip in pairs(t.nodes) do
      target.add(node_ip)
      table.insert(nodes, node_ip)
    end
    if #nodes >0 then
      table.insert(nodes, "Total of "..#nodes.." nodes discovered")
    end
  elseif include_nodes then
    for node_ip in pairs(t.nodes) do
      table.insert(nodes, node_ip)
    end
    if #nodes >0 then
      table.insert(nodes, "Total of "..#nodes.." nodes discovered")
    end
  end

  local print_out = false

  if #peers > 0 then
    table.insert(output, peers)
    print_out = true
  end

  if include_nodes and #nodes > 0 then
    table.insert(output, nodes)
    print_out = true
  end

  if print_out and not target.ALLOW_NEW_TARGETS then
    table.insert(output,"Use the newtargets script-arg to add the results as targets")
  end

  return stdnse.format_output( print_out , output)
end
