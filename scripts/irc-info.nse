local comm = require "comm"
local math = require "math"
local nmap = require "nmap"
local pcre = require "pcre"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

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


author = "Doug Hoyte"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}


portrule = shortport.port_or_service({6666,6667,6697,6679},{"irc","ircs"})

local init = function()
  -- Start of MOTD, we'll take the server name from here
  nmap.registry.ircserverinfo_375 = nmap.registry.ircserverinfo_375
    or pcre.new("^:([\\w-_.]+) 375", 0, "C")

  -- MOTD could be missing, we want to handle that scenario as well
  nmap.registry.ircserverinfo_422 = nmap.registry.ircserverinfo_422
    or pcre.new("^:([\\w-_.]+) 422", 0, "C")

  -- NICK already in use
  nmap.registry.ircserverinfo_433 = nmap.registry.ircserverinfo_433
    or pcre.new("^:[\\w-_.]+ 433", 0, "C")

  -- PING/PONG
  nmap.registry.ircserverinfo_ping = nmap.registry.ircserverinfo_ping
    or pcre.new("^PING :(.+)", 0, "C")

  -- Server version info
  nmap.registry.ircserverinfo_351 = nmap.registry.ircserverinfo_351
    or pcre.new("^:[\\w-_.]+ 351 \\w+ ([^:]+)", 0, "C")

  -- Various bits of info
  nmap.registry.ircserverinfo_251_efnet = nmap.registry.ircserverinfo_251_efnet
    or pcre.new("^:[\\w-_.]+ 251 \\w+ :There are (\\d+) users and (\\d+) invisible on (\\d+) servers", 0, "C")

  nmap.registry.ircserverinfo_251_ircnet = nmap.registry.ircserverinfo_251_ircnet
    or pcre.new("^:[\\w-_.]+ 251 \\w+ :There are (\\d+) users and \\d+ services on (\\d+) servers", 0, "C")

  nmap.registry.ircserverinfo_252 = nmap.registry.ircserverinfo_252
    or pcre.new("^:[\\w-_.]+ 252 \\w+ (\\d+) :", 0, "C")

  nmap.registry.ircserverinfo_254 = nmap.registry.ircserverinfo_254
    or pcre.new("^:[\\w-_.]+ 254 \\w+ (\\d+) :", 0, "C")

  nmap.registry.ircserverinfo_255_efnet = nmap.registry.ircserverinfo_255_efnet
    or pcre.new("^:[\\w-_.]+ 255 \\w+ :I have (\\d+) clients and (\\d+) server", 0, "C")

  nmap.registry.ircserverinfo_255_ircnet = nmap.registry.ircserverinfo_255_ircnet
    or pcre.new("^:[\\w-_.]+ 255 \\w+ :I have (\\d+) users, \\d+ services and (\\d+) server", 0, "C")

  nmap.registry.ircserverinfo_242 = nmap.registry.ircserverinfo_242
    or pcre.new("^:[\\w-_.]+ 242 \\w+ :Server Up (\\d+ days, [\\d:]+)", 0, "C")

  nmap.registry.ircserverinfo_352 = nmap.registry.ircserverinfo_352
    or pcre.new("^:[\\w-_.]+ 352 \\w+ \\S+ (\\S+) ([\\w-_.]+)", 0, "C")

  nmap.registry.ircserverinfo_error = nmap.registry.ircserverinfo_error
    or pcre.new("^ERROR :(.*)", 0, "C")
end

action = function(host, port)
  local sd = nmap.new_socket()
  local curr_nick = random_nick()
  local sver, shost, susers, sservers, schans, sircops, slusers, slservers, sup, serr
  local myhost, myident
  local s, e, t
  local buf
  local banner_timeout = 60
  local make_output = function()
    local o = stdnse.output_table()
    if (not shost) then
      if serr then
        return "ERROR: " .. serr .. "\n"
      else
        return nil
      end
    end

    o["server"] = shost
    o["version"] = sver
    o["servers"] = sservers
    o["ops"] = sircops
    o["chans"] = schans
    o["users"] = susers
    o["lservers"] = slservers
    o["lusers"] = slusers
    o["uptime"] = sup
    o["source host"] = myhost
    if myident and string.find(myident, "^~") then
      o["source ident"] = "NONE or BLOCKED"
    else
      o["source ident"] = myident
    end

    return o
  end

  init()

  local sd, line = comm.tryssl(host, port, "USER nmap +iw nmap :Nmap Wuz Here\nNICK " .. curr_nick .. "\n")
  if not sd then return "Unable to open connection" end

  -- set a healthy banner timeout
  sd:set_timeout(banner_timeout * 1000)

  buf = stdnse.make_buffer(sd, "\r?\n")

  while true do
    if (not line) then break end

    -- This one lets us know we've connected, pre-PONGed, and got a NICK
    s, e, t = nmap.registry.ircserverinfo_375:exec(line, 0, 0)
    if (s) then
      shost = string.sub(line, t[1], t[2])
      sd:send("LUSERS\nVERSION\nSTATS u\nWHO " .. curr_nick .. "\nQUIT\n")
    end

    s, e, t = nmap.registry.ircserverinfo_422:exec(line, 0, 0)
    if (s) then
      shost = string.sub(line, t[1], t[2])
      sd:send("LUSERS\nVERSION\nSTATS u\nWHO " .. curr_nick .. "\nQUIT\n")
    end

    s, e, t = nmap.registry.ircserverinfo_433:exec(line, 0, 0)
    if (s) then
      curr_nick = random_nick()
      sd:send("NICK " .. curr_nick .. "\n")
    end

    s, e, t = nmap.registry.ircserverinfo_ping:exec(line, 0, 0)
    if (s) then
      sd:send("PONG :" .. string.sub(line, t[1], t[2]) .. "\n")
    end

    s, e, t = nmap.registry.ircserverinfo_351:exec(line, 0, 0)
    if (s) then
      sver = string.sub(line, t[1], t[2])
    end

    s, e, t = nmap.registry.ircserverinfo_251_efnet:exec(line, 0, 0)
    if (s) then
      susers = (string.sub(line, t[1], t[2]) + string.sub(line, t[3], t[4]))
      sservers = string.sub(line, t[5], t[6])
    end

    s, e, t = nmap.registry.ircserverinfo_251_ircnet:exec(line, 0, 0)
    if (s) then
      susers = string.sub(line, t[1], t[2])
      sservers = string.sub(line, t[3], t[4])
    end

    s, e, t = nmap.registry.ircserverinfo_252:exec(line, 0, 0)
    if (s) then
      sircops = string.sub(line, t[1], t[2])
    end

    s, e, t = nmap.registry.ircserverinfo_254:exec(line, 0, 0)
    if (s) then
      schans = string.sub(line, t[1], t[2])
    end

    s, e, t = nmap.registry.ircserverinfo_255_efnet:exec(line, 0, 0)
    if (s) then
      slusers = string.sub(line, t[1], t[2])
      slservers = string.sub(line, t[3], t[4])
    end

    s, e, t = nmap.registry.ircserverinfo_255_ircnet:exec(line, 0, 0)
    if (s) then
      slusers = string.sub(line, t[1], t[2])
      slservers = string.sub(line, t[3], t[4])
    end

    s, e, t = nmap.registry.ircserverinfo_242:exec(line, 0, 0)
    if (s) then
      sup = string.sub(line, t[1], t[2])
    end

    s, e, t = nmap.registry.ircserverinfo_352:exec(line, 0, 0)
    if (s) then
      myident = string.sub(line, t[1], t[2])
      myhost = string.sub(line, t[3], t[4])
    end

    s, e, t = nmap.registry.ircserverinfo_error:exec(line, 0, 0)
    if (s) then
      serr = string.sub(line, t[1], t[2])
      return make_output()
    end

    line = buf()
  end

  return make_output()

end




random_nick = function()
  local nick = ""

  -- NICKLEN is at least 9
  for i = 0, 8, 1 do
    nick = nick .. string.char(math.random(97, 122)) -- lowercase ascii
  end

  return nick
end
