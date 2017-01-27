---
-- The brute library is an attempt to create a common framework for performing
-- password guessing against remote services.
--
-- The library currently attempts to parallelize the guessing by starting
-- a number of working threads and increasing that number gradually until
-- brute.threads limit is reached. The starting number of threads can be set
-- with brute.start argument, it defaults to 5. The brute.threads argument
-- defaults to 20. It is worth noticing that the number of working threads
-- will grow exponentially until any error occurs, after that the engine
-- will switch to linear growth.
--
-- The library contains the following classes:
-- * <code>Engine</code>
-- ** The actual engine doing the brute-forcing .
-- * <code>Error</code>
-- ** Class used to return errors back to the engine.
-- * <code>Options</code>
-- ** Stores any options that should be used during brute-forcing.
--
-- In order to make use of the framework a script needs to implement a Driver
-- class. The Driver class is then to be passed as a parameter to the Engine
-- constructor, which creates a new instance for each guess. The Driver class
-- SHOULD implement the following four methods:
--
-- <code>
-- Driver:login = function( self, username, password )
-- Driver:check = function( self )
-- Driver:connect = function( self )
-- Driver:disconnect = function( self )
-- </code>
--
-- The <code>login</code> method does not need a lot of explanation. The login
-- function should return two parameters. If the login was successful it should
-- return true and a <code>creds.Account</code>. If the login was a failure it
-- should return false and an <code>Error</code>. The driver can signal the
-- Engine to retry a set of credentials by calling the Error objects
-- <code>setRetry</code> method. It may also signal the Engine to abort all
-- password guessing by calling the Error objects <code>setAbort</code> method.
-- Finally, the driver can notify the Engine about protocol related exception
-- (like the ftp code 421 "Too many connections") by calling
-- <code>setReduce</code> method. The latter will signal the Engine to reduce
-- the number of running worker threads.
--
-- The following example code demonstrates how the Error object can be used.
--
-- <code>
-- -- After a number of incorrect attempts VNC blocks us, so we abort
-- if ( not(status) and x:match("Too many authentication failures") ) then
--   local err = brute.Error:new( data )
--   -- signal the engine to abort
--   err:setAbort( true )
--   return false, err
-- elseif ( not(status) ) then
--   local err = brute.Error:new( "VNC handshake failed" )
--   -- This might be temporary, signal the engine to retry
--   err:setRetry( true )
--   return false, err
-- end
-- .
-- .
-- .
-- -- Return a simple error, no retry needed
-- return false, brute.Error:new( "Incorrect password" )
-- </code>
--
-- The purpose of the <code>check</code> method is to be able to determine
-- whether the script has all the information it needs, before starting the
-- brute force. It's the method where you should check, e.g., if the correct
-- database or repository URL was specified or not. On success, the
-- <code>check</code> method returns true, on failure it returns false and the
-- brute force engine aborts.
--
-- NOTE: The <code>check</code> method is deprecated and will be removed from
-- all scripts in the future. Scripts should do this check in the action
-- function instead.
--
-- The <code>connect</code> method provides the framework with the ability to
-- ensure that the thread can run once it has been dispatched a set of
-- credentials. As the sockets in NSE are limited we want to limit the risk of
-- a thread blocking, due to insufficient free sockets, after it has acquired a
-- username and password pair.
--
-- The following sample code illustrates how to implement a sample
-- <code>Driver</code> that sends each username and password over a socket.
--
-- <code>
-- Driver = {
--   new = function(self, host, port, options)
--     local o = {}
--     setmetatable(o, self)
--     self.__index = self
--     o.host = host
--     o.port = port
--     o.options = options
--     return o
--   end,
--   connect = function( self )
--     self.socket = nmap.new_socket()
--     return self.socket:connect( self.host, self.port )
--   end,
--   disconnect = function( self )
--     return self.socket:close()
--   end,
--   check = function( self )
--     return true
--   end,
--   login = function( self, username, password )
--     local status, err, data
--     status, err = self.socket:send( username .. ":" .. password)
--     status, data = self.socket:receive_bytes(1)
--
--     if ( data:match("SUCCESS") ) then
--       return true, creds.Account:new(username, password, creds.State.VALID)
--     end
--     return false, brute.Error:new( "login failed" )
--   end,
-- }
-- </code>
--
-- The following sample code illustrates how to pass the <code>Driver</code>
-- off to the brute engine.
--
-- <code>
-- action = function(host, port)
--   local options = { key1 = val1, key2 = val2 }
--   local status, accounts = brute.Engine:new(Driver, host, port, options):start()
--   if( not(status) ) then
--     return accounts
--   end
--   return stdnse.format_output( true, accounts )
-- end
-- </code>
--
-- The Engine is written with performance and reasonable resource usage in mind
-- and requires minimum extra work from a script developer. A trivial approach
-- is to spawn as many working threads as possible regardless of network
-- conditions, other scripts' needs, and protocol response. This indeed works
-- well, but only in ideal conditions. In reality there might be several
-- scripts running or only limited number of threads are allowed to use sockets
-- at any given moment (as it is in Nmap). A more intelligent approach is to
-- automate the management of Engine's running threads, so that performance
-- of other scripts does not suffer because of exhaustive brute force work.
-- This can be done on three levels: protocol, network, and resource level.
--
-- On the protocol level the developer should notify the Engine about connection
-- restrictions imposed by a server that can be learned during a protocol
-- communication. Like code 421 "To many connections" is used in FTP. Reasonably
-- in such cases we would like to reduce the number of connections to this
-- service, hence saving resources for other work and reducing the load on the
-- target server. This can be done by returning an Error object with called
-- <code>setReduce</code> method on it. The error will make the Engine reduce
-- the number of running threads.
--
-- Following is an example how it can be done for FTP brute.
--
-- <code>
-- local line = <responce from the server>
--
-- if(string.match(line, "^230")) then
--   stdnse.debug1("Successful login: %s/%s", user, pass)
--   return true, creds.Account:new( user, pass, creds.State.VALID)
-- elseif(string.match(line, "^530")) then
--   return false, brute.Error:new( "Incorrect password" )
-- elseif(string.match(line, "^421")) then
--   local err = brute.Error:new("Too many connections")
--   err:setReduce(true)
--   return false, err
-- elseif(string.match(line, "^220")) then
-- elseif(string.match(line, "^331")) then
-- else
--   stdnse.debug1("WARNING: Unhandled response: %s", line)
--   local err = brute.Error:new("Unhandled response")
--   err:setRetry(true)
--   return false, err
-- end
-- </code>
--
-- On the network level we want to catch errors that can occur because of
-- network congestion or target machine specifics, say firewalled. These
-- errors can be caught as return results of operations on sockets, like
-- <code>local status, err = socket.receive()</code>. Asking a developer to
-- relay such errors to the Engine is counterproductive, and it would lead to
-- bloated scripts with lots of repetitive code. The Engine takes care of that
-- with a little help from the developer. The only thing that needs to be
-- done is to use <code>brute.new_socket()</code> instead of
-- <code>nmap.new_socket()</code> when creating a socket in a script.
--
-- NOTE: A socket created with <code>brute.new_socket()</code> will behave as
-- a regular socket when used without the brute library. The returned object
-- is a BruteSocket instance, which can be treated as a regular socket object.
--
-- Example on creating "brute" socket.
--
-- <code>
-- connect = function( self )
--   self.socket = brute.new_socket()
--   local status, err = self.socket:connect(self.host, self.port)
--   self.socket:set_timeout(arg_timeout)
--   if(not(status)) then
--     return false, brute.Error:new( "Couldn't connect to host: " .. err )
--   end
--   return true
-- end
-- </code>
--
-- On the resource level the Engine can query the current status of the NSE.
-- As of the time of writing, the only parameter used is a number of threads
-- waiting for connection (as was said before the NSE has a constraint on the
-- number of concurrent connections due to performance reasons). With a
-- running brute script the limit can be hit pretty fast, which can affect
-- performance of other scripts. To mitigate this situation resource management
-- strategy is used, and the Engine will reduce the number of working threads
-- if there are any threads waiting for connection. As a result the preference
-- for connection will be given to non brute scripts and if there are many
-- brute scripts running simultaneously, then they will not exhaust resources
-- unnecessarily.
-- This feature is enabled by default and does not require any additional work
-- from the developer.
--
-- Stagnation avoidance mechanism is implemented to alert users about services
-- that might have failed during bruteforcing. A warning triggers if all working
-- threads have been experiencing connection errors during 100 consequentive
-- iterations of the main thread loop. If <code>brute.killstagnated</code>
-- is set to <code>true</code> the Engine will abort after the first stagnation
-- warning.
--
-- For a complete example of a brute implementation consult the
-- <code>svn-brute.nse</code> or <code>vnc-brute.nse</code> scripts
--
-- @args brute.useraspass guess the username as password for each user
--       (default: true)
-- @args brute.emptypass guess an empty password for each user
--       (default: false)
-- @args brute.unique make sure that each password is only guessed once
--       (default: true)
-- @args brute.firstonly stop guessing after first password is found
--       (default: false)
-- @args brute.passonly iterate over passwords only for services that provide
--       only a password for authentication. (default: false)
-- @args brute.retries the number of times to retry if recoverable failures
--       occur. (default: 3)
-- @args brute.delay the number of seconds to wait between guesses (default: 0)
-- @args brute.threads the number of initial worker threads, the number of
--       active threads will be automatically adjusted.
-- @args brute.mode can be user, pass or creds and determines what mode to run
--       the engine in.
--       * user - the unpwdb library is used to guess passwords, every password
--                password is tried for each user. (The user iterator is in the
--                outer loop)
--       * pass - the unpwdb library is used to guess passwords, each password
--                is tried for every user. (The password iterator is in the
--                outer loop)
--       * creds- a set of credentials (username and password pairs) are
--                guessed against the service. This allows for lists of known
--                or common username and password combinations to be tested.
--       If no mode is specified and the script has not added any custom
--       iterator the pass mode will be enabled.
-- @args brute.credfile a file containing username and password pairs delimited
--       by '/'
-- @args brute.guesses the number of guesses to perform against each account.
--       (default: 0 (unlimited)). The argument can be used to prevent account
--       lockouts.
-- @args brute.start the number of threads the engine will start with.
--       (default: 5).
--
-- @author Patrik Karlsson <patrik@cqure.net>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

--
-- Version 0.73
-- Created 06/12/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 07/13/2010 - v0.2 - added connect, disconnect methods to Driver
--                             <patrik@cqure.net>
-- Revised 07/21/2010 - v0.3 - documented missing argument brute.mode
-- Revised 07/23/2010 - v0.4 - fixed incorrect statistics and changed output to
--                             include statistics, and to display "no accounts
--                             found" message.
-- Revised 08/14/2010 - v0.5 - added some documentation and smaller changes per
--                             David's request.
-- Revised 08/30/2010 - v0.6 - added support for custom iterators and did some
--                             needed cleanup.
-- Revised 06/19/2011 - v0.7 - added support for creds library [Patrik]
-- Revised 07/07/2011 - v0.71- fixed some minor bugs, and changed credential
--                             iterator to use a file handle instead of table
-- Revised 07/21/2011 - v0.72- added code to allow script reporting invalid
--                             (non existing) accounts using setInvalidAccount
-- Revised 11/12/2011 - v0.73- added support for max guesses per account to
--                             prevent account lockouts.
--                             bugfix: added support for guessing the username
--                             as password per default, as suggested by the
--                             documentation.
-- Revised 07/11/2016 - v.8  - added smart resource management and error handling
--                             mechanisms. Sergey Khegay <g.sergeykhegay@gmail.com>

local coroutine = require "coroutine"
local creds = require "creds"
local io = require "io"
local nmap = require "nmap"
local os = require "os"
local stdnse = require "stdnse"
local table = require "table"
local unpwdb = require "unpwdb"
local math = require "math"
_ENV = stdnse.module("brute", stdnse.seeall)

-- Engine options that can be set by scripts
-- Supported options are:
--   * firstonly     - stop after finding the first correct password
--                     (can be set using script-arg brute.firstonly)
--   * passonly      - guess passwords only, don't supply a username
--                     (can be set using script-arg brute.passonly)
--   * max_retries   - the amount of retries to do before aborting
--                     (can be set using script-arg brute.retries)
--   * delay         - sets the delay between attempts
--                     (can be set using script-arg brute.delay)
--   * mode          - can be set to either cred, user or pass and controls
--                     whether the engine should iterate over users, passwords
--                     or fetch a list of credentials from a single file.
--                     (can be set using script-arg brute.mode)
--   * title         - changes the title of the result table where the
--                     passwords are returned.
--   * nostore       - don't store the results in the credential library
--   * max_guesses   - the maximum amount of guesses to perform for each
--                     account.
--   * useraspass    - guesses the username as password (default: true)
--   * emptypass     - guesses an empty string as password (default: false)
--   * killstagnated - abort the Engine if bruteforcing has stagnated
--                     getting too many connections errors. (default: false)
--
Options = {

  new = function (self)
    local o = {}
    setmetatable(o, self)
    self.__index = self

    o.emptypass = self.checkBoolArg("brute.emptypass", false)
    o.useraspass = self.checkBoolArg("brute.useraspass", true)
    o.firstonly = self.checkBoolArg("brute.firstonly", false)
    o.passonly = self.checkBoolArg("brute.passonly", false)
    o.killstagnated = self.checkBoolArg("brute.killstagnated", false)
    o.max_retries = tonumber(nmap.registry.args["brute.retries"]) or 3
    o.delay = tonumber(nmap.registry.args["brute.delay"]) or 0
    o.max_guesses = tonumber(nmap.registry.args["brute.guesses"]) or 0

    return o
  end,

  --- Checks if a script argument is boolean true or false
  --
  -- @param arg string containing the name of the argument to check
  -- @param default boolean containing the default value
  -- @return boolean, true if argument evaluates to 1 or true, else false
  checkBoolArg = function (arg, default)
    local val = stdnse.get_script_args(arg) or default
    return (val == "true" or val == true or tonumber(val) == 1)
  end,

  --- Sets the brute mode to either iterate over users or passwords
  -- @see description for more information.
  --
  -- @param mode string containing either "user" or "password"
  -- @return status true on success else false
  -- @return err string containing the error message on failure
  setMode = function (self, mode)
    local modes = {
      "password",
      "user",
      "creds",
    }
    local supported = false

    for _, m in ipairs(modes) do
      if mode == m then
        supported = true
      end
    end

    if not supported then
      stdnse.debug1("ERROR: brute.options.setMode: mode %s not supported", mode)
      return false, "Unsupported mode"
    else
      self.mode = mode
    end
    return true
  end,

  --- Sets an option parameter
  --
  -- @param param string containing the parameter name
  -- @param value string containing the parameter value
  setOption = function (self, param, value)
    self[param] = value
  end,

  --- Set an alternate title for the result output (default: Accounts)
  --
  -- @param title string containing the title value
  setTitle = function (self, title)
    self.title = title
  end,

}

-- The account object which is to be reported back from each driver
-- The Error class, is currently only used to flag for retries
-- It also contains the error message, if one was returned from the driver.
Error = {
  retry = false,

  new = function (self, msg)
    local o = {
      msg = msg,
      done = false,
      reduce = nil,
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Is the error recoverable?
  --
  -- @return status true if the error is recoverable, false if not
  isRetry = function (self)
    return self.retry
  end,

  --- Set the error as recoverable
  --
  -- @param r boolean true if the engine should attempt to retry the
  --        credentials, unset or false if not
  setRetry = function (self, r)
    self.retry = r
  end,

  --- Set the error as abort all threads
  --
  -- @param b boolean true if the engine should abort guessing on all threads
  setAbort = function (self, b)
    self.abort = b
  end,

  --- Was the error abortable
  --
  -- @return status true if the driver flagged the engine to abort
  isAbort = function (self)
    return self.abort
  end,

  --- Get the error message reported
  --
  -- @return msg string containing the error message
  getMessage = function (self)
    return self.msg
  end,

  --- Is the thread done?
  --
  -- @return status true if done, false if not
  isDone = function (self)
    return self.done
  end,

  --- Signals the engine that the thread is done and should be terminated
  --
  -- @param b boolean true if done, unset or false if not
  setDone = function (self, b)
    self.done = b
  end,

  -- Marks the username as invalid, aborting further guessing.
  -- @param username
  setInvalidAccount = function (self, username)
    self.invalid_account = username
  end,

  -- Checks if the error reported the account as invalid.
  -- @return username string containing the invalid account
  isInvalidAccount = function (self)
    return self.invalid_account
  end,

  --- Set the error as reduce the number of running threads
  --
  -- @param r boolean true if should reduce, unset or false if not
  setReduce = function (self, r)
    self.reduce = r
  end,

  --- Checks if the error signals to reduce the number of running threads
  --
  -- @return status true if reduce, false otherwise
  isReduce = function (self)
    if self.reduce then
      return true
    end
    return false
  end,
}

-- Auxillary data structure
Batch = {
  new = function (self, lim, stime)
    local o = {
      limit = lim or 3, -- maximum number of items
      full = false,
      data = {}, -- storage
      size = 0, -- current number of items
      start_time = stime or 0,
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Adds new item to the vault (if possible)
  --
  -- @param obj, new object
  -- @return true if insert is successful, false if the vault is full
  add = function (self, obj)
    if self.size < self.limit then
      self.data[self.size + 1] = obj
      self.size = self.size + 1
      return true
    end

    return false
  end,

  isFull = function (self)
    if self.size >= self.limit then
      return true
    end

    return false
  end,

  getData = function (self)
    return self.data
  end,

  getSize = function (self)
    return self.size
  end,

  getStartTime = function (self)
    return self.start_time
  end,

  getLimit = function (self)
    return self.limit
  end,

  setLimit = function (self, lim)
    self.limit = lim
  end,
}


-- The brute engine, doing all the nasty work
Engine = {
  STAT_INTERVAL = 20,
  THREAD_TO_ENGINE = {},

  --- Creates a new Engine instance
  --
  -- @param driver, the driver class that should be instantiated
  -- @param host table as passed to the action method of the script
  -- @param port table as passed to the action method of the script
  -- @param options table containing any script specific options
  -- @return o new Engine instance
  new = function (self, driver, host, port, options)

    -- we want Engine.THREAD_TO_ENGINE to contain weak keys
    -- for effective garbage collection
    if getmetatable(Engine.THREAD_TO_ENGINE) == nil then
      setmetatable(Engine.THREAD_TO_ENGINE, {
          __mode = "k",
        })
    end

    local o = {
      driver = driver,
      host = host,
      port = port,
      driver_options = options,
      terminate_all = false,
      error = nil,
      counter = 0,
      threads = {},
      tps = {},
      iterator = nil,
      usernames = usernames_iterator(),
      passwords = passwords_iterator(),
      found_accounts = {},
      account_guesses = {},
      options = Options:new(),

      retry_accounts = {},
      initial_accounts_exhausted = false,
      batch = nil,
      tick = 0,
    }
    setmetatable(o, self)
    self.__index = self

    o.max_threads = tonumber(stdnse.get_script_args "brute.threads") or 20
    o.start_threads = tonumber(stdnse.get_script_args "brute.start") or 5

    return o
  end,

  --- Sets the username iterator
  --
  -- @param usernameIterator function to set as a username iterator
  setUsernameIterator = function (self, usernameIterator)
    self.usernames = usernameIterator
  end,

  --- Sets the password iterator
  --
  -- @param passwordIterator function to set as a password iterator
  setPasswordIterator = function (self, passwordIterator)
    self.passwords = passwordIterator
  end,

  --- Limit the number of worker threads
  --
  -- @param max number containing the maximum number of allowed threads
  setMaxThreads = function (self, max)
    self.max_threads = max
  end,

  --- Returns the number of non-dead threads
  --
  -- @return count number of non-dead threads
  threadCount = function (self)
    local count = 0

    for thread in pairs(self.threads) do
      if coroutine.status(thread) == "dead" then
        self.threads[thread] = nil
      else
        count = count + 1
      end
    end
    return count
  end,

  --- Calculates the number of threads that are actually doing any work
  --
  -- @return count number of threads performing activity
  activeThreads = function (self)
    local count = 0
    for thread, v in pairs(self.threads) do
      if v.guesses ~= nil then
        count = count + 1
      end
    end
    return count
  end,

  --- Iterator wrapper used to iterate over all registered iterators
  --
  -- @return iterator function
  get_next_credential = function (self)
    local function next_credential ()
      for user, pass in self.iterator do
        -- makes sure the credentials have not been tested before
        self.used_creds = self.used_creds or {}
        pass = pass or "nil"
        if not self.used_creds[user .. pass] then
          self.used_creds[user .. pass] = true
          coroutine.yield(user, pass)
        end
      end
      while true do
        coroutine.yield(nil, nil)
      end
    end
    return coroutine.wrap(next_credential)
  end,

  --- Does the actual authentication request
  --
  -- @return true on success, false on failure
  -- @return response Account on success, Error on failure
  doAuthenticate = function (self)

    local status, response
    local next_credential = self:get_next_credential()
    local retries = self.options.max_retries
    local username, password
    local thread_data = Engine.getThreadData(coroutine.running())
    assert(thread_data, "Unknown coroutine is running")

    repeat
      local driver = self.driver:new(self.host, self.port, self.driver_options)
      status, response = driver:connect()

      -- Did we successfully connect?
      if status then
        if not username and not password then
          repeat
            if #self.retry_accounts > 0 then
              -- stdnse.debug1("Using retry credentials")
              username = self.retry_accounts[#self.retry_accounts].username
              password = self.retry_accounts[#self.retry_accounts].password
              table.remove(self.retry_accounts, #self.retry_accounts)
            else
              username, password = next_credential()
            end

            thread_data.username = username
            thread_data.password = password


            if not username and not password then
              driver:disconnect()
              self.initial_accounts_exhausted = true
              return false
            end
          until (not self.found_accounts or not self.found_accounts[username])
            and (self.options.max_guesses == 0 or not self.account_guesses[username]
                  or self.options.max_guesses > self.account_guesses[username])

          -- increases the number of guesses for an account
          self.account_guesses[username] = self.account_guesses[username]
                                           and self.account_guesses[username] + 1 or 1
        end

        -- make sure that all threads locked in connect stat terminate quickly
        if Engine.terminate_all then
          driver:disconnect()
          driver = nil
          return false
        end

        local c
        -- Do we have a username or not?
        if username and #username > 0 then
          c = ("%s/%s"):format(username, #password > 0 and password or "<empty>")
        else
          c = ("%s"):format(#password > 0 and password or "<empty>")
        end

        local msg = (retries ~= self.options.max_retries) and "Re-trying" or "Trying"
        stdnse.debug2("%s %s against %s:%d", msg, c, self.host.ip, self.port.number)
        status, response = driver:login(username, password)

        driver:disconnect()
        driver = nil

        if not status and response:isReduce() then
          local ret_creds = {}
          ret_creds.username = username
          ret_creds.password = password
          return false, response, ret_creds
        end

      end

      retries = retries - 1

      -- End if:
      -- * The guess was successful
      -- * The response was not set to retry
      -- * We've reached the maximum retry attempts
    until status or (response and not (response:isRetry())) or retries == 0

    -- Increase the amount of total guesses
    self.counter = self.counter + 1

    return status, response
  end,


  login = function (self, cvar)
    local condvar = nmap.condvar(cvar)
    local thread_data = self.threads[coroutine.running()]
    local interval_start = os.time()


    while true do
      -- Should we terminate all threads or this particular thread?
      if (self.terminate_all or thread_data.terminate)
        or (self.initial_accounts_exhausted and #self.retry_accounts == 0) then
        break
      end

      -- Updtae tick and add this thread to the batch
      self.tick = self.tick + 1

      if not (self.batch:isFull()) and not thread_data.in_batch then
        self.batch:add(coroutine.running())

        thread_data.in_batch = true
        thread_data.ready = false
      end

      -- We expect doAuthenticate to pass the report variable received from the script
      local status, response, ret_creds = self:doAuthenticate()

      if thread_data.in_batch then
        thread_data.ready = true
      end

      if status then
        -- Prevent locked accounts from appearing several times
        if not self.found_accounts or self.found_accounts[response.username] == nil then
          if not self.options.nostore then
            local c = creds.Credentials:new(self.options.script_name, self.host, self.port)
            c:add(response.username, response.password, response.state)
          else
            self.credstore = self.credstore or {}
            table.insert(self.credstore, tostring(response))
          end

          stdnse.debug1("Discovered account: %s", tostring(response))

          -- if we're running in passonly mode, and want to continue guessing
          -- we will have a problem as the username is always the same.
          -- in this case we don't log the account as found.
          if not self.options.passonly then
            self.found_accounts[response.username] = true
          end

          -- Check if firstonly option was set, if so abort all threads
          if self.options.firstonly then
            self.terminate_all = true
          end
        end
      elseif ret_creds then
        -- add credentials to a vault
        self.retry_accounts[#self.retry_accounts + 1] = {
          username = ret_creds.username,
          password = ret_creds.password,
        }
        -- notify the main thread that there were an error on this coroutine
        thread_data.protocol_error = true

        condvar "signal"
        condvar "wait"
      else
        if response and response:isAbort() then
          self.terminate_all = true
          self.error = response:getMessage()
          break
        elseif response and response:isDone() then
          break
        elseif response and response:isInvalidAccount() then
          self.found_accounts[response:isInvalidAccount()] = true
        end
      end

      local timediff = (os.time() - interval_start)

      -- This thread made another guess
      thread_data.guesses = (thread_data.guesses and thread_data.guesses + 1 or 1)

      -- Dump statistics at regular intervals
      if timediff > Engine.STAT_INTERVAL then
        interval_start = os.time()
        local tps = self.counter / (os.time() - self.starttime)
        table.insert(self.tps, tps)
        stdnse.debug2("threads=%d,tps=%.1f", self:activeThreads(), tps)
      end

      -- if delay was specified, do sleep
      if self.options.delay > 0 then
        stdnse.sleep(self.options.delay)
      end

      condvar "signal"
    end

    condvar "signal"
  end,

  --- Adds new worker thread using start function
  --
  -- @return new thread object
  addWorker = function (self, cvar)
    local co = stdnse.new_thread(self.login, self, cvar)

    Engine.THREAD_TO_ENGINE[co] = self

    self.threads[co] = {
      running = true,
      protocol_error = nil,
      attempt = 0,
      in_batch = false,
      ready = false,

      connection_error = nil,
      con_error_reason = nil,
      username = nil,
      password = nil,
    }

    return co
  end,

  addWorkerN = function (self, cvar, n)
    assert(n >= 0)
    for i = 1, n do
      self:addWorker(cvar)
    end
  end,

  renewBatch = function (self)
    if self.batch then
      local size = self.batch:getSize()
      local data = self.batch:getData()

      for i = 1, size do
        if self.threads[data[i]] then
          self.threads[data[i]].in_batch = false
          self.threads[data[i]].ready = false
        end
      end
    end

    self.batch = Batch:new(math.min(self:threadCount(), 3), self.tick)
  end,

  readyBatch = function (self)
    if not self.batch then
      return false
    end

    local n = self.batch:getSize()
    local data = self.batch:getData()

    if n == 0 then
      return false
    end

    for i = 1, n do
      if self.threads[data[i]] and coroutine.status(data[i]) ~= "dead" and self.threads[data[i]].in_batch then
        if not self.threads[data[i]].ready then
          return false
        end
      end
    end

    return true
  end,

  --- Starts the brute-force
  --
  -- @return status true on success, false on failure
  -- @return err string containing error message on failure
  start = function (self)

    local cvar = {}
    local condvar = nmap.condvar(cvar)

    assert(self.options.script_name, "SCRIPT_NAME was not set in options.script_name")
    assert(self.port.number and self.port.protocol, "Invalid port table detected")
    self.port.service = self.port.service or "unknown"

    -- Only run the check method if it exist. We should phase this out
    -- in favor of a check in the action function of the script
    if self.driver:new(self.host, self.port, self.driver_options).check then
      -- check if the driver is ready!
      local status, response = self.driver:new(self.host, self.port, self.driver_options):check()
      if not status then
        return false, response
      end
    end

    local usernames = self.usernames
    local passwords = self.passwords

    if "function" ~= type(usernames) then
      return false, "Invalid usernames iterator"
    end
    if "function" ~= type(passwords) then
      return false, "Invalid passwords iterator"
    end

    local mode = self.options.mode or stdnse.get_script_args "brute.mode"

    -- if no mode was given, but a credfile is present, assume creds mode
    if not mode and stdnse.get_script_args "brute.credfile" then
      if stdnse.get_script_args "userdb" or stdnse.get_script_args "passdb" then
        return false, "\n  ERROR: brute.credfile can't be used in combination with userdb/passdb"
      end
      mode = 'creds'
    end

    -- Are we guessing against a service that has no username (eg. VNC)
    if self.options.passonly then
      local function single_user_iter (next)
        local function next_user ()
          coroutine.yield ""
        end
        return coroutine.wrap(next_user)
      end
      -- only add this iterator if no other iterator was specified
      if self.iterator == nil then
        self.iterator = Iterators.user_pw_iterator(single_user_iter(), passwords)
      end
    elseif mode == 'creds' then
      local credfile = stdnse.get_script_args "brute.credfile"
      if not credfile then
        return false, "No credential file specified (see brute.credfile)"
      end

      local f = io.open(credfile, "r")
      if not f then
        return false, ("Failed to open credfile (%s)"):format(credfile)
      end

      self.iterator = Iterators.credential_iterator(f)
    elseif mode and mode == 'user' then
      self.iterator = self.iterator or Iterators.user_pw_iterator(usernames, passwords)
    elseif mode and mode == 'pass' then
      self.iterator = self.iterator or Iterators.pw_user_iterator(usernames, passwords)
    elseif mode then
      return false, ("Unsupported mode: %s"):format(mode)
      -- Default to the pw_user_iterator in case no iterator was specified
    elseif self.iterator == nil then
      self.iterator = Iterators.pw_user_iterator(usernames, passwords)
    end

    if (not mode or mode == 'user' or mode == 'pass') and self.options.useraspass then
      -- if we're only guessing passwords, this doesn't make sense
      if not self.options.passonly then
        self.iterator = unpwdb.concat_iterators(
          Iterators.pw_same_as_user_iterator(usernames, "lower"),
          self.iterator
        )
      end
    end

    if (not mode or mode == 'user' or mode == 'pass') and self.options.emptypass then
      local function empty_pass_iter ()
        local function next_pass ()
          coroutine.yield ""
        end
        return coroutine.wrap(next_pass)
      end
      self.iterator = Iterators.account_iterator(usernames, empty_pass_iter(), mode or "pass")
    end

    self.starttime = os.time()


    -- How many threads should start?
    local start_threads = self.start_threads
    -- If there are already too many threads waiting for connection,
    -- then start humbly with one thread
    if nmap.socket.get_stats().connect_waiting > 0 then
      start_threads = 1
    end

    -- Start `start_threads` number of threads
    self:addWorkerN(cvar, start_threads)
    self:renewBatch()

    local revive = false
    local killed_one = false
    local error_since_batch_start = false
    local stagnation_count = 0 -- number of times when all threads are stopped because of exceptions
    local quick_start = true
    local stagnated = true

    -- Main logic loop
    while true do
      local thread_count = self:threadCount()

      -- should we stop
      if thread_count <= 0 then
        if self.initial_accounts_exhausted and #self.retry_accounts == 0 or self.terminate_all then
          break
        else
          -- there are some accounts yet to be checked, so revive the engine
          revive = true
        end
      end

      -- Reset flags
      killed_one = false
      error_since_batch_start = false

      -- Are all the threads have any kind of mistake?
      -- if not, then this variable will change to false after next loop
      stagnated = true

      -- Run through all coroutines and check their statuses
      -- if any mistake has happened kill one coroutine.
      -- We do not actually kill a coroutine right-away, we just
      -- signal it to finish work until some point an then die.
      for co, v in pairs(self.threads) do
        if not v.connection_error then
          stagnated = false
        end

        if v.protocol_error or v.connection_error then
          if v.attempt >= self.batch:getStartTime() then
            error_since_batch_start = true
          end

          if not killed_one then
            v.terminate = true
            killed_one = true

            if v.protocol_error then
              stdnse.debug2("Killed one thread because of PROTOCOL exception")
            else
              stdnse.debug2("Killed one thread because of CONNECTION exception")
            end
          end

          -- Remove error flags of the thread to let it continue to run
          v.protocol_error = nil
          v.connection_error = nil
        else
          -- If we got here, then at least one thread is running fine
          -- and there is no connection stagnation
          --stagnated = false
        end
      end

      if stagnated == true then
        stagnation_count = stagnation_count + 1

        -- If we get inside `if` below, then we are not making any
        -- guesses for too long. In this case it is reasonable to stop
        -- bruteforce.
        if stagnation_count == 100 then
          stdnse.debug1("WARNING: The service seems to have failed or is heavily firewalled... Consider aborting.")
          if self.options.killstagnated then
            self.error = "The service seems to have failed or is heavily firewalled..."
            self.terminate_all = true
          end
          stagnation_count = 0
        end
      else
        stagnation_count = 0
      end

      -- `quick_start` changes to false only once since Engine starts
      -- `auick_start` remains false till the end of the bruteforce.
      if killed_one then
        quick_start = false
      end

      -- Check if we possibly exhaust resources.
      if not killed_one then
        local waiting = nmap.socket.get_stats().connect_waiting

        if waiting ~= 0 then
          local kill_count = 1
          if waiting > 5 then
            kill_count = math.max(math.floor(thread_count / 2), 1)
          end

          for co, v in pairs(self.threads) do
            if coroutine.status(co) ~= "dead" then
              stdnse.debug2("Killed one because of RESOURCE management")
              v.terminate = true
              killed_one = true

              kill_count = kill_count - 1
              if kill_count == 0 then
                break
              end
            end
          end
        end

      end

      -- Renew the batch if there was an error since we started to assemble the batch
      -- or the batch's limit is unreachable with current number of threads
      -- or when some thread does not change state to ready for too long
      if error_since_batch_start
        or not killed_one and thread_count < self.batch:getLimit()
        or (thread_count > 0 and self.tick - self.batch:getStartTime() > 10) then
        self:renewBatch()
      end

      if (not killed_one and self.batch:isFull() and thread_count < self.max_threads)
        or revive then

        local num_to_add = 1
        if quick_start then
          num_to_add = math.min(self.max_threads - thread_count, thread_count)
        end

        self:addWorkerN(cvar, num_to_add)
        self:renewBatch()
        revive = false
      end


      stdnse.debug2("Status: #threads = %d, #retry_accounts = %d, initial_accounts_exhausted = %s, waiting = %d",
        self:threadCount(), #self.retry_accounts, tostring(self.initial_accounts_exhausted),
        nmap.socket.get_stats().connect_waiting)

      -- wake up other threads
      -- wait for all threads to finish running
      condvar "broadcast"
      condvar "wait"
    end


    local valid_accounts

    if not self.options.nostore then
      valid_accounts = creds.Credentials:new(self.options.script_name, self.host, self.port):getTable()
    else
      valid_accounts = self.credstore
    end

    local result = stdnse.output_table()
    -- Did we find any accounts, if so, do formatting
    if valid_accounts and #valid_accounts > 0 then
      result[self.options.title or "Accounts"] = valid_accounts
    else
      result.Accounts = "No valid accounts found"
    end

    -- calculate the average tps
    local sum = 0
    for _, v in ipairs(self.tps) do
      sum = sum + v
    end
    local time_diff = (os.time() - self.starttime)
    time_diff = (time_diff == 0) and 1 or time_diff
    local tps = (sum == 0) and (self.counter / time_diff) or (sum / #self.tps)

    -- Add the statistics to the result
    result.Statistics = ("Performed %d guesses in %d seconds, average tps: %.1f"):format( self.counter, time_diff, tps )

    if self.options.max_guesses > 0 then
      -- we only display a warning if the guesses are equal to max_guesses
      for user, guesses in pairs(self.account_guesses) do
        if guesses == self.options.max_guesses then
          result.Information = ("Guesses restricted to %d tries per account to avoid lockout"):format(self.options.max_guesses)
          break
        end
      end
    end

    -- Did any error occur? If so add this to the result.
    if self.error then
      result.ERROR = self.error
      return false, result
    end
    return true, result
  end,

  getEngine = function (co)
    local engine = Engine.THREAD_TO_ENGINE[co]
    if not engine then
      stdnse.debug1("WARNING: No engine associated with %s", coroutine.running())
    end
    return engine
  end,

  getThreadData = function (co)
    local engine = Engine.getEngine(co)
    if not engine then
      return nil
    end
    return engine.threads[co]
  end,
}

--- Default username iterator that uses unpwdb
--
function usernames_iterator ()
  local status, usernames = unpwdb.usernames()
  if not status then
    return "Failed to load usernames"
  end
  return usernames
end

--- Default password iterator that uses unpwdb
--
function passwords_iterator ()
  local status, passwords = unpwdb.passwords()
  if not status then
    return "Failed to load passwords"
  end
  return passwords
end

Iterators = {

  --- Iterates over each user and password
  --
  -- @param users table/function containing list of users
  -- @param pass table/function containing list of passwords
  -- @param mode string, should be either 'user' or 'pass' and controls
  --        whether the users or passwords are in the 'outer' loop
  -- @return function iterator
  account_iterator = function (users, pass, mode)
    local function next_credential ()
      local outer, inner
      if "table" == type(users) then
        users = unpwdb.table_iterator(users)
      end
      if "table" == type(pass) then
        pass = unpwdb.table_iterator(pass)
      end

      if mode == 'pass' then
        outer, inner = pass, users
      elseif mode == 'user' then
        outer, inner = users, pass
      else
        return
      end

      for o in outer do
        for i in inner do
          if mode == 'pass' then
            coroutine.yield(i, o)
          else
            coroutine.yield(o, i)
          end
        end
        inner "reset"
      end
      while true do
        coroutine.yield(nil, nil)
      end
    end
    return coroutine.wrap(next_credential)
  end,


  --- Try each password for each user (user in outer loop)
  --
  -- @param users table/function containing list of users
  -- @param pass table/function containing list of passwords
  -- @return function iterator
  user_pw_iterator = function (users, pass)
    return Iterators.account_iterator(users, pass, "user")
  end,

  --- Try each user for each password (password in outer loop)
  --
  -- @param users table/function containing list of users
  -- @param pass table/function containing list of passwords
  -- @return function iterator
  pw_user_iterator = function (users, pass)
    return Iterators.account_iterator(users, pass, "pass")
  end,

  --- An iterator that returns the username as password
  --
  -- @param users function returning the next user
  -- @param case string [optional] 'upper' or 'lower', specifies if user
  --        and password pairs should be case converted.
  -- @return function iterator
  pw_same_as_user_iterator = function (users, case)
    local function next_credential ()
      for user in users do
        if case == 'upper' then
          coroutine.yield(user, user:upper())
        elseif case == 'lower' then
          coroutine.yield(user, user:lower())
        else
          coroutine.yield(user, user)
        end
      end
      users "reset"
      while true do
        coroutine.yield(nil, nil)
      end
    end
    return coroutine.wrap(next_credential)
  end,

  --- An iterator that returns the username and uppercase password
  --
  -- @param users table containing list of users
  -- @param pass table containing list of passwords
  -- @param mode string, should be either 'user' or 'pass' and controls
  --        whether the users or passwords are in the 'outer' loop
  -- @return function iterator
  pw_ucase_iterator = function (users, passwords, mode)
    local function next_credential ()
      for user, pass in Iterators.account_iterator(users, passwords, mode) do
        coroutine.yield(user, pass:upper())
      end
      while true do
        coroutine.yield(nil, nil)
      end
    end
    return coroutine.wrap(next_credential)
  end,

  --- Credential iterator (for default or known user/pass combinations)
  --
  -- @param f file handle to file containing credentials separated by '/'
  -- @return function iterator
  credential_iterator = function (f)
    local function next_credential ()
      local c = {}
      for line in f:lines() do
        if not (line:match "^#!comment:") then
          local trim = function (s)
            return s:match '^()%s*$' and '' or s:match '^%s*(.*%S)'
          end
          line = trim(line)
          local user, pass = line:match "^([^%/]*)%/(.*)$"
          coroutine.yield(user, pass)
        end
      end
      f:close()
      while true do
        coroutine.yield(nil, nil)
      end
    end
    return coroutine.wrap(next_credential)
  end,

  unpwdb_iterator = function (mode)
    local status, users, passwords

    status, users = unpwdb.usernames()
    if not status then
      return
    end

    status, passwords = unpwdb.passwords()
    if not status then
      return
    end

    return Iterators.account_iterator(users, passwords, mode)
  end,

}

-- A socket wrapper class.
-- Instances of this class can be treated as regular sockets.
-- This wrapper is used to relay connection errors to the corresponding Engine
-- instance.
BruteSocket = {
  new = function (self)
    local o = {
      socket = nil,
    }
    setmetatable(o, self)

    self.__index = function (table, key)
      if self[key] then
        return self[key]
      elseif o.socket[key] then
        if type(o.socket[key]) == "function" then
          return function (self, ...)
            return o.socket[key](o.socket, ...)
          end
        else
          return o.socket[key]
        end
      end

      return nil
    end

    o.socket = nmap.new_socket()

    return o
  end,

  getSocket = function (self)
    return self.socket
  end,

  checkStatus = function (self, status, err)
    if not status and (err == "ERROR" or err == "TIMEOUT") then
      local engine = Engine.getEngine(coroutine.running())

      if not engine then
        stdnse.debug2("WARNING: No associated engine detected for %s", coroutine.running())
        return -- behave like a usual socket
      end

      local thread_data = Engine.getThreadData(coroutine.running())

      engine.retry_accounts[#engine.retry_accounts + 1] = {
        username = thread_data.username,
        password = thread_data.password,
      }

      thread_data.connection_error = true
      thread_data.con_error_reason = err
    end
  end,

  connect = function (self, host, port)
    local status, err = self.socket:connect(host, port)
    self:checkStatus(status, err)

    return status, err
  end,

  send = function (self, data)
    local status, err = self.socket:send(data)
    self:checkStatus(status, err)

    return status, err
  end,

  receive = function (self)
    local status, data = self.socket:receive()
    self:checkStatus(status, data)

    return status, data
  end,

  close = function (self)
    self.socket:close()
  end,
}

function new_socket ()
  return BruteSocket:new()
end


return _ENV
