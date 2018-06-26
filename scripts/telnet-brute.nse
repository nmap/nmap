local comm = require "comm"
local coroutine = require "coroutine"
local creds = require "creds"
local match = require "match"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local strbuf = require "strbuf"
local string = require "string"
local brute = require "brute"

description = [[
Performs brute-force password auditing against telnet servers.
]]

---
-- @usage
--   nmap -p 23 --script telnet-brute --script-args userdb=myusers.lst,passdb=mypwds.lst,telnet-brute.timeout=8s <target>
--
-- @output
-- 23/tcp open  telnet
-- | telnet-brute:
-- |   Accounts
-- |     wkurtz:colonel
-- |   Statistics
-- |_    Performed 15 guesses in 19 seconds, average tps: 0
--
-- @args telnet-brute.timeout   Connection time-out timespec (default: "5s")
-- @args telnet-brute.autosize  Whether to automatically reduce the thread
--                              count based on the behavior of the target
--                              (default: "true")

author = "nnposter"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {'brute', 'intrusive'}

portrule = shortport.port_or_service(23, 'telnet')


-- Miscellaneous script-wide parameters and constants
local arg_timeout = stdnse.get_script_args(SCRIPT_NAME .. ".timeout") or "5s"
local arg_autosize = stdnse.get_script_args(SCRIPT_NAME .. ".autosize") or "true"

local telnet_timeout      -- connection timeout (in ms), from arg_timeout
local telnet_autosize     -- whether to auto-size the execution, from arg_autosize
local telnet_eol = "\r\n" -- termination string for sent lines
local conn_retries = 2    -- # of retries when attempting to connect
local critical_debug = 1  -- debug level for printing critical messages
local login_debug = 2     -- debug level for printing attempted credentials
local detail_debug = 3    -- debug level for printing individual login steps
                          --                          and thread-level info

---
-- Print debug messages, prepending them with the script name
--
-- @param level Verbosity level
-- @param fmt Format string.
-- @param ... Arguments to format.
local debug = stdnse.debug

---
-- Decide whether a given string (presumably received from a telnet server)
-- represents a username prompt
--
-- @param str The string to analyze
-- @return Verdict (true or false)
local is_username_prompt = function (str)
  local lcstr = str:lower()
  return lcstr:find("%f[%w]username%s*:%s*$")
      or lcstr:find("%f[%w]login%s*:%s*$")
end


---
-- Decide whether a given string (presumably received from a telnet server)
-- represents a password prompt
--
-- @param str The string to analyze
-- @return Verdict (true or false)
local is_password_prompt = function (str)
  local lcstr = str:lower()
  return lcstr:find("%f[%w]password%s*:%s*$")
      or lcstr:find("%f[%w]passcode%s*:%s*$")
end


---
-- Decide whether a given string (presumably received from a telnet server)
-- indicates a successful login
--
-- @param str The string to analyze
-- @return Verdict (true or false)
local is_login_success = function (str)
  if str:find("^[A-Z]:\\") then                         -- Windows telnet
    return true
  end
  local lcstr = str:lower()
  return lcstr:find("[/>%%%$#]%s*$")                    -- general prompt
      or lcstr:find("^last login%s*:")                  -- linux telnetd
      or lcstr:find("%f[%w]main%smenu%f[%W]")           -- Netgear RM356
      or lcstr:find("^enter terminal emulation:%s*$")   -- Hummingbird telnetd
      or lcstr:find("%f[%w]select an option%f[%W]")     -- Zebra PrintServer
end


---
-- Decide whether a given string (presumably received from a telnet server)
-- indicates a failed login
--
-- @param str The string to analyze
-- @return Verdict (true or false)
local is_login_failure = function (str)
  local lcstr = str:lower()
  return lcstr:find("%f[%w]incorrect%f[%W]")
      or lcstr:find("%f[%w]failed%f[%W]")
      or lcstr:find("%f[%w]denied%f[%W]")
      or lcstr:find("%f[%w]invalid%f[%W]")
      or lcstr:find("%f[%w]bad%f[%W]")
end


---
-- Strip off ANSI escape sequences (terminal codes) that start with <esc>[
-- and replace them with white space, namely the VT character (0x0B).
-- This way their new representation can be naturally matched with pattern %s.
--
-- @param str The string that needs to be strained
-- @return The same string without the escape sequences
local remove_termcodes = function (str)
  local mark = '\x0B'
  return str:gsub('\x1B%[%??%d*%a', mark)
            :gsub('\x1B%[%??%d*;%d*%a', mark)
end


---
-- Simple class to encapsulate connection operations
local Connection = { methods = {} }


---
-- Initialize a connection object
--
-- @param host Telnet host
-- @param port Telnet port
-- @return Connection object or nil (if the operation failed)
Connection.new = function (host, port, proto)
  local soc = brute.new_socket(proto)
  if not soc then return nil end
  return setmetatable({
                        socket = soc,
                        isopen = false,
                        buffer = nil,
                        error = nil,
                        host = host,
                        port = port,
                        proto = proto
                      },
                      {
                        __index = Connection.methods,
                        __gc = Connection.methods.close
                      })
end


---
-- Open the connection
--
-- @param self Connection object
-- @return Status (true or false)
-- @return nil if the operation was successful; error code otherwise
Connection.methods.connect = function (self)
  local status
  local wait = 1

  self.buffer = ""

  for tries = 0, conn_retries do
    self.socket:set_timeout(telnet_timeout)
    status, self.error = self.socket:connect(self.host, self.port, self.proto)
    if status then break end
    stdnse.sleep(wait)
    wait = 2 * wait
  end

  self.isopen = status
  return status, self.error
end


---
-- Close the connection
--
-- @param self Connection object
-- @return Status (true or false)
-- @return nil if the operation was successful; error code otherwise
Connection.methods.close = function (self)
  if not self.isopen then return true, nil end
  local status
  self.isopen = false
  self.buffer = nil
  status, self.error = self.socket:close()
  return status, self.error
end


---
-- Send one line through the connection to the server
--
-- @param self Connection object
-- @param line Characters to send, will be automatically terminated
-- @return Status (true or false)
-- @return nil if the operation was successful; error code otherwise
Connection.methods.send_line = function (self, line)
  local status
  status, self.error = self.socket:send(line .. telnet_eol)
  return status, self.error
end


---
-- Add received data to the connection buffer while taking care
-- of telnet option signalling
--
-- @param self Connection object
-- @param data Data string to add to the buffer
-- @return Number of characters in the connection buffer
Connection.methods.fill_buffer = function (self, data)
  local outbuf = strbuf.new(self.buffer)
  local optbuf = strbuf.new()
  local oldpos = 0

  while true do
    -- look for IAC (Interpret As Command)
    local newpos = data:find('\255', oldpos)
    if not newpos then break end

    outbuf = outbuf .. data:sub(oldpos, newpos - 1)
    local opttype = data:byte(newpos + 1)
    local opt = data:byte(newpos + 2)

    if opttype == 251 or opttype == 252 then
      -- Telnet Will / Will Not
      -- regarding ECHO or GO-AHEAD, agree with whatever the
      -- server wants (or not) to do; otherwise respond with
      -- "don't"
      opttype = (opt == 1 or opt == 3) and opttype + 2 or 254
    elseif opttype == 253 or opttype == 254 then
      -- Telnet Do / Do not
      -- I will not do whatever the server wants me to
      opttype = 252
    end

    optbuf = optbuf .. string.char(255)
                    .. string.char(opttype)
                    .. string.char(opt)
    oldpos = newpos + 3
  end

  self.buffer = strbuf.dump(outbuf) .. data:sub(oldpos)
  self.socket:send(strbuf.dump(optbuf))
  return self.buffer:len()
end


---
-- Return leading part of the connection buffer, up to a line termination,
-- and refill the buffer as needed
--
-- @param self Connection object
-- @param normalize whether the returned line is normalized (default: false)
-- @return String representing the first line in the buffer
Connection.methods.get_line = function (self)
  if self.buffer:len() == 0 then
    -- refill the buffer
    local status, data = self.socket:receive_buf(match.pattern_limit("[\r\n:>%%%$#\255].*", 2048), true)
    if not status then
      -- connection error
      self.error = data
      return nil
    end

    self:fill_buffer(data)
  end
  return remove_termcodes(self.buffer:match('^[^\r\n]*'))
end


---
-- Discard leading part of the connection buffer, up to and including
-- one or more line terminations
--
-- @param self Connection object
-- @return Number of characters remaining in the connection buffer
Connection.methods.discard_line = function (self)
  self.buffer = self.buffer:gsub('^[^\r\n]*[\r\n]*', '', 1)
  return self.buffer:len()
end


---
-- Ghost connection object
Connection.GHOST = {}


---
-- Simple class to encapsulate target properties, including thread-specific data
-- persisted across Driver instances
local Target = { methods = {} }


---
-- Initialize a target object
--
-- @param host Telnet host
-- @param port Telnet port
-- @return Target object or nil (if the operation failed)
Target.new = function (host, port)
  local soc, _, proto = comm.tryssl(host, port, "\n", {timeout=telnet_timeout})
  if not soc then return nil end
  soc:close()
  return setmetatable({
                        host = host,
                        port = port,
                        proto = proto,
                        workers = setmetatable({}, { __mode = "k" })
                      },
                      { __index = Target.methods })
end


---
-- Set up the calling thread as one of the worker threads
--
-- @param self Target object
Target.methods.worker = function (self)
  local thread = coroutine.running()
  self.workers[thread] = self.workers[thread] or {}
end


---
-- Provide the calling worker thread with an open connection to the target.
-- The state of the connection is at the beginning of the login flow.
--
-- @param self Target object
-- @return Status (true or false)
-- @return Connection if the operation was successful; error code otherwise
Target.methods.attach = function (self)
  local worker = self.workers[coroutine.running()]
  local conn = worker.conn
               or Connection.new(self.host, self.port, self.proto)
  if not conn then return false, "Unable to allocate connection" end
  worker.conn = conn

  if conn.error then conn:close() end
  if not conn.isopen then
    local status, err = conn:connect()
    if not status then return false, err end
  end

  return true, conn
end


---
-- Recover a connection used by the calling worker thread
--
-- @param self Target object
-- @return Status (true or false)
-- @return nil if the operation was successful; error code otherwise
Target.methods.detach = function (self)
  local conn = self.workers[coroutine.running()].conn
  local status, response = true, nil
  if conn and conn.error then status, response = conn:close() end
  return status, response
end


---
-- Set the state of the calling worker thread
--
-- @param self Target object
-- @param inuse Whether the worker is in use (true or false)
-- @return inuse
Target.methods.inuse = function (self, inuse)
  self.workers[coroutine.running()].inuse = inuse
  return inuse
end


---
-- Decide whether the target is still being worked on
--
-- @param self Target object
-- @return Verdict (true or false)
Target.methods.idle = function (self)
  local idle = true
  for t, w in pairs(self.workers) do
    idle = idle and (not w.inuse or coroutine.status(t) == "dead")
  end
  return idle
end


---
-- Class that can be used as a "driver" by brute.lua
local Driver = { methods = {} }


---
-- Initialize a driver object
--
-- @param host Telnet host
-- @param port Telnet port
-- @param target instance of a Target class
-- @return Driver object or nil (if the operation failed)
Driver.new = function (self, host, port, target)
  assert(host == target.host and port == target.port, "Target mismatch")
  target:worker()
  return setmetatable({
                        target = target,
                        connect = telnet_autosize
                                  and Driver.methods.connect_autosize
                                  or Driver.methods.connect_simple,
                        thread_exit = nmap.condvar(target)
                      },
                      { __index = Driver.methods })
end


---
-- Connect the driver to the target (when auto-sizing is off)
--
-- @param self Driver object
-- @return Status (true or false)
-- @return nil if the operation was successful; error code otherwise
Driver.methods.connect_simple = function (self)
  assert(not self.conn, "Multiple connections attempted")
  local status, response = self.target:attach()
  if status then
    self.conn = response
    response = nil
  end
  return status, response
end


---
-- Connect the driver to the target (when auto-sizing is on)
--
-- @param self Driver object
-- @return Status (true or false)
-- @return nil if the operation was successful; error code otherwise
Driver.methods.connect_autosize = function (self)
  assert(not self.conn, "Multiple connections attempted")
  self.target:inuse(true)
  local status, response = self.target:attach()
  if status then
    -- connected to the target
    self.conn = response
    if self:prompt() then
      -- successfully reached login prompt
      return true, nil
    end
    -- connected but turned away
    self.target:detach()
  end
  -- let's park the thread here till all the functioning threads finish
  self.target:inuse(false)
  debug(detail_debug, "Retiring %s", tostring(coroutine.running()))
  while not self.target:idle() do self.thread_exit("wait") end
  -- pretend that it connected
  self.conn = Connection.GHOST
  return true, nil
end


---
-- Disconnect the driver from the target
--
-- @param self Driver object
-- @return Status (true or false)
-- @return nil if the operation was successful; error code otherwise
Driver.methods.disconnect = function (self)
  assert(self.conn, "Attempt to disconnect non-existing connection")
  if self.conn.isopen and not self.conn.error then
    -- try to reach new login prompt
    self:prompt()
  end
  self.conn = nil
  return self.target:detach()
end


---
-- Attempt to reach telnet login prompt on the target
--
-- @param self Driver object
-- @return line Reached prompt or nil
Driver.methods.prompt = function (self)
  assert(self.conn, "Attempt to use disconnected driver")
  local conn = self.conn
  local line
  repeat
    line = conn:get_line()
  until not line
        or is_username_prompt(line)
        or is_password_prompt(line)
        or not conn:discard_line()
  return line
end


---
-- Attempt to establish authenticated telnet session on the target
--
-- @param self Driver object
-- @return Status (true or false)
-- @return instance of creds.Account if the operation was successful;
--         instance of brute.Error otherwise
Driver.methods.login = function (self, username, password)
  assert(self.conn, "Attempt to use disconnected driver")
  local sent_username = self.target.passonly
  local sent_password = false
  local conn = self.conn

  local loc = " in " .. tostring(coroutine.running())

  local connection_error = function (msg)
    debug(detail_debug, msg .. loc)
    local err = brute.Error:new(msg)
    err:setRetry(true)
    return false, err
  end

  local passonly_error = function ()
    local msg = "Password prompt encountered"
    debug(critical_debug, msg .. loc)
    local err = brute.Error:new(msg)
    err:setAbort(true)
    return false, err
  end

  local username_error = function ()
    local msg = "Invalid username encountered"
    debug(detail_debug, msg .. loc)
    local err = brute.Error:new(msg)
    err:setInvalidAccount(username)
    return false, err
  end

  local login_error = function ()
    local msg = "Login failed"
    debug(detail_debug, msg .. loc)
    return false, brute.Error:new(msg)
  end

  local login_success = function ()
    local msg = "Login succeeded"
    debug(detail_debug, msg .. loc)
    return true, creds.Account:new(username, password, creds.State.VALID)
  end

  local login_no_password = function ()
    local msg = "Login succeeded without password"
    debug(detail_debug, msg .. loc)
    return true, creds.Account:new(username, "", creds.State.VALID)
  end

  debug(detail_debug, "Login attempt %s:%s%s", username, password, loc)

  if conn == Connection.GHOST then
    -- reached when auto-sizing is enabled and all worker threads
    -- failed
    return connection_error("Service unreachable")
  end

  -- username has not yet been sent
  while not sent_username do
    local line = conn:get_line()
    if not line then
      -- stopped receiving data
      return connection_error("Login prompt not reached")
    end

    if is_username_prompt(line) then
      -- being prompted for a username
      conn:discard_line()
      debug(detail_debug, "Sending username" .. loc)
      if not conn:send_line(username) then
        return connection_error(conn.error)
      end
      sent_username = true
      if conn:get_line() == username then
        -- ignore; remote echo of the username in effect
        conn:discard_line()
      end

    elseif is_password_prompt(line) then
      -- looks like 'password only' support
      return passonly_error()

    else
      -- ignore; insignificant response line
      conn:discard_line()
    end
  end

  -- username has been already sent
  while not sent_password do
    local line = conn:get_line()
    if not line then
      -- remote host disconnected
      return connection_error("Password prompt not reached")
    end

    if is_login_success(line) then
      -- successful login without a password
      conn:close()
      return login_no_password()

    elseif is_password_prompt(line) then
      -- being prompted for a password
      conn:discard_line()
      debug(detail_debug, "Sending password" .. loc)
      if not conn:send_line(password) then
        return connection_error(conn.error)
      end
      sent_password = true

    elseif is_login_failure(line) then
      -- failed login without a password; explicitly told so
      conn:discard_line()
      return username_error()

    elseif is_username_prompt(line) then
      -- failed login without a password; prompted again for a username
      return username_error()

    else
      -- ignore; insignificant response line
      conn:discard_line()
    end

  end

  -- password has been already sent
  while true do
    local line = conn:get_line()
    if not line then
      -- remote host disconnected
      return connection_error("Login not completed")
    end

    if is_login_success(line) then
      -- successful login
      conn:close()
      return login_success()

    elseif is_login_failure(line) then
      -- failed login; explicitly told so
      conn:discard_line()
      return login_error()

    elseif is_password_prompt(line) or is_username_prompt(line) then
      -- failed login; prompted again for credentials
      return login_error()

    else
      -- ignore; insignificant response line
      conn:discard_line()
    end

  end

  -- unreachable code
  assert(false, "Reached unreachable code")
end


action = function (host, port)
  local ts, tserror = stdnse.parse_timespec(arg_timeout)
  if not ts then
    return stdnse.format_output(false, "Invalid timeout value: " .. tserror)
  end
  telnet_timeout = 1000 * ts
  telnet_autosize = arg_autosize:lower() == "true"

  local target = Target.new(host, port)
  if not target then
    return stdnse.format_output(false, "Unable to connect to the target")
  end

  local engine = brute.Engine:new(Driver, host, port, target)
  engine.options.script_name = SCRIPT_NAME
  target.passonly = engine.options.passonly
  local _, result = engine:start()
  return result
end
