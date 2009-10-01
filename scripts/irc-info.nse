description = [[
Gathers information from an IRC server.

It uses STATS, LUSERS, and other queries to obtain this information.
]]

---
-- @output
-- 6665/tcp open     irc
-- |  irc-info: Server: target.example.org
-- |  Version: hyperion-1.0.2b(381). target.example.org
-- |  Lservers/Lusers: 0/4204
-- |  Uptime: 106 days, 2:46:30
-- |  Source host: source.example.org
-- |_ Source ident: OK n=nmap

author = "Doug Hoyte"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

require("stdnse")
require "shortport"
require("nsedebug")
require("comm")

portrule = shortport.port_or_service({6666,6667,6697,6679},{"irc","ircs"})

local init = function()
  -- Start of MOTD, we'll take the server name from here
  nmap.registry.ircserverinfo_375 = nmap.registry.ircserverinfo_375
    or pcre.new("^:([\\w-_.]+) 375", 0, "C")

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
  local make_output = function()
    local o = ""
    if (not shost) then
      if serr then
        return "ERROR: " .. serr .. "\n"
      else
        return nil
      end
    end

    o = o .. "Server: " .. shost .. "\n"
    if sver then
      o = o .. "Version: " .. sver .. "\n"
    end
    if sircops and susers and sservers and schans then
      o = o .. "Servers/Ops/Chans/Users: " .. sservers .. "/" .. sircops .. "/" .. schans .. "/" .. susers .. "\n"
    end
    if slusers and slservers then
      o = o .. "Lservers/Lusers: " .. slservers .. "/" .. slusers .. "\n"
    end
    if sup then
      o = o .. "Uptime: " .. sup .. "\n"
    end
    if myhost and myident then
      o = o .. "Source host: " .. myhost .. "\n"
      if string.find(myident, "^~") then
        o = o .. "Source ident: NONE or BLOCKED\n"
      else
        o = o .. "Source ident: OK " .. myident .. "\n"
      end
    end

    return o
  end

  init()

  local sd, line = comm.tryssl(host, port, "USER nmap +iw nmap :Nmap Wuz Here\nNICK " .. curr_nick .. "\n")
  if not sd then return "Unable to open connection" end

  buf = stdnse.make_buffer(sd, "\r?\n")

  while true do
    if (not line) then break end

    -- This one lets us know we've connected, pre-PONGed, and got a NICK
    s, e, t = nmap.registry.ircserverinfo_375:exec(line, 0, 0)
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
