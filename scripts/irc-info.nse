local comm = require "comm"
local nmap = require "nmap"
local math = require "math"
local irc = require "irc"
local stdnse = require "stdnse"
local rand = require "rand"

description = [[
Gathers information from an IRC server.

It uses STATS, LUSERS, and other queries to obtain this information.
]]

---
-- @output
-- 6665/tcp open     irc
-- | irc-info:
-- |   server: asimov.freenode.net
-- |   version: ircd-seven-1.1.3(20111112-b71671d1e846,charybdis-3.4-dev). asimov.freenode.net
-- |   servers: 31
-- |   ops: 36
-- |   chans: 48636
-- |   users: 84883
-- |   lservers: 1
-- |   lusers: 4350
-- |   uptime: 511 days, 23:02:29
-- |   source host: source.example.com
-- |_  source ident: NONE or BLOCKED
--@xmloutput
-- <elem key="server">asimov.freenode.net</elem>
-- <elem key="version">ircd-seven-1.1.3(20111112-b71671d1e846,charybdis-3.4-dev). asimov.freenode.net </elem>
-- <elem key="servers">31</elem>
-- <elem key="ops">36</elem>
-- <elem key="chans">48636</elem>
-- <elem key="users">84883</elem>
-- <elem key="lservers">1</elem>
-- <elem key="lusers">4350</elem>
-- <elem key="uptime">511 days, 23:02:29</elem>
-- <elem key="source host">source.example.com</elem>
-- <elem key="source ident">NONE or BLOCKED</elem>

author = {"Doug Hoyte", "Patrick Donnelly"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

portrule = irc.portrule

local banner_timeout = 60

function action (host, port)
  local nick = rand.random_alpha(9)

  local output = stdnse.output_table()

  local sd, line = comm.tryssl(host, port,
    ("USER nmap +iw nmap :Nmap Wuz Here\nNICK %s\n"):format(nick),
    {request_timeout=6000})
  if not sd then return "Unable to open connection" end

  local buf = stdnse.make_buffer(sd, "\r?\n")

  while line do
    stdnse.debug2("%s", line)

    -- This one lets us know we've connected, pre-PONGed, and got a NICK
    -- Start of MOTD, we'll take the server name from here
    local info = line:match "^:([%w-_.]+) 375"
    if info then
      output.server = info
      sd:send("LUSERS\nVERSION\nSTATS u\nWHO " .. nick .. "\nQUIT\n")
    end

    -- MOTD could be missing, we want to handle that scenario as well
    info = line:match "^:([%w-_.]+) 422"
    if info then
      output.server = info
      sd:send("LUSERS\nVERSION\nSTATS u\nWHO " .. nick .. "\nQUIT\n")
    end

    -- NICK already in use
    info = line:match "^:([%w-_.]+) 433"
    if info then
      nick = rand.random_alpha(9)
      sd:send("NICK " .. nick .. "\n")
    end

    -- PING/PONG
    local dummy = line:match "^PING :(.*)"
    if dummy then
      sd:send("PONG :" .. dummy .. "\n")
    end

    -- Server version info
    info = line:match "^:[%w-_.]+ 351 %w+ ([^:]+)"
    if info then
      output.version = info
    end

    -- Various bits of info
    local users, invisible, servers = line:match "^:[%w-_.]+ 251 %w+ :There are (%d+) users and (%d+) invisible on (%d+) servers"
    if users then
      output.users = math.tointeger(users + invisible)
      output.servers = servers
    end

    local users, servers = line:match "^:[%w-_.]+ 251 %w+ :There are (%d+) users and %d+ services on (%d+) servers"
    if users then
      output.users = users
      output.servers = servers
    end

    info = line:match "^:[%w-_.]+ 252 %w+ (%d+) :"
    if info then
      output.ops = info
    end

    info = line:match "^:[%w-_.]+ 254 %w+ (%d+) :"
    if info then
      output.chans = info
    end

    -- efnet
    local clients, servers = line:match "^:[%w-_.]+ 255 %w+ :I have (%d+) clients and (%d+) server"
    if clients then
      output.lusers = clients
      output.lservers = servers
    end

    -- ircnet
    local clients, servers = line:match "^:[%w-_.]+ 255 %w+ :I have (%d+) users, %d+ services and (%d+) server"
    if clients then
      output.lusers = clients
      output.lservers = servers
    end

    local uptime = line:match "^:[%w-_.]+ 242 %w+ :Server Up (%d+ days, [%d:]+)"
    if uptime then
      output.uptime = uptime
    end

    local ident, host = line:match "^:[%w-_.]+ 352 %w+ %S+ (%S+) ([%w-_.]+)"
    if ident then
      if ident:find "^~" then
        output["source ident"] = "NONE or BLOCKED"
      else
        output["source ident"] = ident
      end
      output["source host"] = host
    end

    local err = line:match "^ERROR :(.*)"
    if err then
      output.error = err
    end

    line = buf()
  end

  if output.server then
    return output
  else
    return nil
  end
end
