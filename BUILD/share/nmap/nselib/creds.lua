--- The credential class stores found credentials in the Nmap registry
--
-- The credentials library may be used by scripts to store credentials in
-- a common format in the nmap registry. The Credentials class serves as
-- a primary interface for scripts to the library.
--
-- The State table keeps track of possible account states and a corresponding
-- message to return for each state.
--
-- The following code illustrates how a script may add discovered credentials
-- to the database:
-- <code>
-- local c = creds.Credentials:new( {"myapp"}, host, port )
-- c:add("patrik", "secret", creds.State.VALID )
-- </code>
--
-- The following code illustrates how a script can return a table of discovered
-- credentials at the end of execution:
-- <code>
-- return tostring(creds.Credentials:new({"myapp"}, host, port))
-- </code>
--
-- Another script can iterate over credential already discovered by other
-- scripts just by referring to the same tag:
-- <code>
-- local c = creds.Credentials:new({"myapp", "yourapp"}, host, port)
-- for cred in c:getCredentials(creds.State.VALID) do
--   showContentForUser(cred.user, cred.pass)
-- end
-- </code>
--
-- The following code illustrates how a script may iterate over all discovered
-- credentials:
-- <code>
-- local c = creds.Credentials:new(creds.ALL_DATA, host, port)
-- for cred in c:getCredentials(creds.State.VALID) do
--   showContentForUser(cred.user, cred.pass)
-- end
-- </code>
--
-- The library also enables users to add credentials through script arguments
-- either globally or per service. These credentials may be retrieved by script
-- through the same functions as any other discovered credentials. Arguments
-- passed using script arguments will be added with the PARAM state. The
-- following code may be used by a scripts to retrieve these credentials:
-- <code>
-- local c = creds.Credentials:new(creds.ALL_DATA, host, port)
-- for cred in c:getCredentials(creds.State.PARAM) do
--   ... do something ...
-- end
-- </code>
--
-- Any globally added credentials will be made available to all scripts,
-- regardless of what service is being filtered through the host and port
-- arguments when instantiating the Credentials class. Service specific
-- arguments will only be made available to scripts with ports matching
-- the service name. The following two examples illustrate how credentials are
-- added globally and for the http service:
-- <code>
-- --script-args creds.global='admin:nimda'
-- --script-args creds.http='webadmin:password'
-- </code>
--
-- The service name at this point may be anything and the entry is created
-- dynamically without validating whether the service exists or not.
--
-- The credential argument is not documented in this library using the <at>args
-- function as the argument would incorrectly show up in all scripts making use
-- of this library. This would show that credentials could be added to scripts
-- that do not make use of this function. Therefore any scripts that make use
-- of the credentials passing arguments need to have appropriate documentation
-- added to them.
--
--
-- The following code illustrates how a script may save its discovered credentials
-- to a file:
-- <code>
-- local c = creds.Credentials:new( SCRIPT_NAME, host, port )
-- c:add("patrik", "secret", creds.State.VALID )
-- status, err = c:saveToFile("outputname","csv")
-- </code>
--
-- Supported output formats are CSV, verbose and plain.  In both verbose and plain
-- records are separated by colons.  The difference between the two is that verbose
-- includes the credential state.  The file extension is automatically added to
-- the filename based on the type requested.
--
-- @args creds.global Credentials to be returned by Credentials.getCredentials
--                    regardless of the service.
-- @args creds.[service] Credentials to be returned by
--                       Credentials.getCredentials for [service]. E.g.
--                       creds.http=admin:password
--
-- @author "Patrik Karlsson <patrik@cqure.net>"
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

-- Version 0.5
-- Created 2011/02/06 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 2011/27/06 - v0.2 - revised by Patrik Karlsson <patrik@cqure.net>
--                * added documentation
--                * added getCredentials function
--
-- Revised 2011/05/07 - v0.3 - revised by Patrik Karlsson <patrik@cqure.net>
--                * modified getCredentials to return an iterator
--                * added support for adding credentials as
--                  script arguments
--
-- Revised 2011/09/04 - v0.4 - revised by Tom Sellers
--                * added saveToFile function for saving credential
--                * table to file in CSV or text formats
--
-- Revised 2015/19/08 - v0.5 - Gioacchino Mazzurco <gmazzurco89@gmail.com>
--                * added multitag support to share credential easier accross
--                  scripts
--

local bit = require "bit"
local coroutine = require "coroutine"
local io = require "io"
local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
_ENV = stdnse.module("creds", stdnse.seeall)


--- Table mapping the different account states to their number
--
-- Also available is the <code>StateMsg</code> table, used to map these numbers
-- to a description.
-- @class table
-- @name State
-- @field LOCKED Account is locked
-- @field VALID Valid credentials
-- @field DISABLED Account is disabled
-- @field CHANGEPW Valid credentials, password must be changed at next logon
-- @field PARAM Credentials passed to script during Nmap execution
-- @field EXPIRED Valid credentials, account expired
-- @field TIME_RESTRICTED Valid credentials, account cannot log in at current time
-- @field HOST_RESTRICTED Valid credentials, account cannot log in from current host
-- @field LOCKED_VALID Valid credentials, account locked
-- @field DISABLED_VALID Valid credentials, account disabled
-- @field HASHED Hashed valid or invalid credentials
State = {
  LOCKED = 1,
  VALID = 2,
  DISABLED = 4,
  CHANGEPW = 8,
  PARAM = 16,
  EXPIRED = 32,
  TIME_RESTRICTED = 64,
  HOST_RESTRICTED = 128,
  LOCKED_VALID = 256,
  DISABLED_VALID = 512,
  HASHED = 1024,
}

StateMsg = {
  [State.LOCKED]    = 'Account is locked',
  [State.VALID]     = 'Valid credentials',
  [State.DISABLED]  = 'Account is disabled',
  [State.CHANGEPW]  = 'Valid credentials, password must be changed at next logon',
  [State.PARAM]  = 'Credentials passed to script during Nmap execution',
  [State.EXPIRED]   = 'Valid credentials, account expired',
  [State.TIME_RESTRICTED] = 'Valid credentials, account cannot log in at current time',
  [State.HOST_RESTRICTED] = 'Valid credentials, account cannot log in from current host',
  [State.LOCKED_VALID]    = 'Valid credentials, account locked',
  [State.DISABLED_VALID]  = 'Valid credentials, account disabled',
  [State.HASHED]  = 'Hashed valid or invalid credentials',
}


ALL_DATA = {}

-- The RegStorage class
RegStorage = {

  --- Creates a new RegStorage instance
  --
  -- @return a new instance
  -- @name RegStorage.new
  new = function(self)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.filter = {}
    return o
  end,

  --- Add credentials to storage
  --
  -- @param tags a table containing tags associated with the credentials
  -- @param host host table, name or ip
  -- @param port number containing the port of the service
  -- @param service the name of the service
  -- @param user the name of the user
  -- @param pass the password of the user
  -- @param state of the account
  -- @name RegStorage.add
  add = function( self, tags, host, port, service, user, pass, state )
    local cred = {
      tags = tags,
      host = host,
      port = port,
      service = service,
      user = user,
      pass = pass,
      state = state
    }
    nmap.registry.creds = nmap.registry.creds or {}
    table.insert( nmap.registry.creds, cred )
  end,

  --- Sets the storage filter
  --
  -- @param host table containing the host
  -- @param port table containing the port
  -- @param state table containing the account state
  -- @name RegStorage.setFilter
  setFilter = function( self, host, port, state )
    self.filter.host = host
    self.filter.port = port
    self.filter.state = state
  end,

  --- Returns a credential iterator matching the selected filters
  --
  -- @return a credential iterator
  -- @name RegStorage.getAll
  getAll = function( self )
    local function get_next()
      local host, port = self.filter.host, self.filter.port

      if ( not(nmap.registry.creds) ) then return end

      for _, v in pairs(nmap.registry.creds) do
        local h = ( v.host.ip or v.host )
        if ( not(host) and not(port) ) then
          if ( not(self.filter.state) or ( v.state == self.filter.state ) ) then
            coroutine.yield(v)
          end
        elseif ( not(host) and ( port == v.port ) ) then
          if ( not(self.filter.state) or ( v.state == self.filter.state ) ) then
            coroutine.yield(v)
          end
        elseif ( ( host and ( h == host or h == host.ip ) ) and not(port) ) then
          if ( not(self.filter.state) or ( v.state == self.filter.state ) ) then
            coroutine.yield(v)
          end
        elseif ( ( host and ( h == host or h == host.ip ) ) and port.number == v.port ) then
          if ( not(self.filter.state) or ( v.state == bit.band(self.filter.state, v.state) ) ) then
            coroutine.yield(v)
          end
        end
      end
    end
    return coroutine.wrap(get_next)
  end,

}

Account = {
  --- Creates a new instance of the Account class
  --
  -- @param username containing the user's name
  -- @param password containing the user's password
  -- @param state A <code>creds.State</code> account state
  -- @return A new <code>creds.Account</code> object
  -- @name Account.new
  new = function(self, username, password, state)
    local o = { username = username, password = password, state = StateMsg[state] or state }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Converts an account object to a printable script
  --
  -- @return string representation of object
  -- @name Account.__tostring
  __tostring = function( self )
    return (
      (self.username and self.username .. ":" or "") ..
      (self.password ~= "" and self.password or "<empty>") ..
      (self.state and " - " .. self.state or "")
      )
  end,

  --- Less-than operation for sorting
  --
  -- Lexicographic comparison by user, pass, and state
  -- @name Account.__lt
  __lt = function (a, b)
    if a.user and b.user and a.user >= b.user then
      return false
    elseif a.pass and b.pass and a.pass >= b.pass then
      return false
    elseif a.state and b.state and a.state >= b.state then
      return false
    end
    return true
  end,
}


-- Return a function suitable for use as a __pairs metamethod
-- which will cause the table to yield its values sorted by key.
local function sorted_pairs (sortby)
  return function (t)
    local order = stdnse.keys(t)
    table.sort(order, sortby)
    return coroutine.wrap(function()
        for i,k in ipairs(order) do
          coroutine.yield(k, t[k])
        end
      end)
  end
end

-- The credentials class
Credentials = {

  --- Creates a new instance of the Credentials class
  -- @param tags a table containing tags associated with the credentials
  -- @param host table as received by the scripts action method
  -- @param port table as received by the scripts action method
  -- @name Credentials.new
  new = function(self, tags, host, port)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.storage = RegStorage:new()
    o.storage:setFilter(host, port)
    o.host = host
    o.port = ( port and port.number ) and port.number
    o.service = ( port and port.service ) and port.service
    if ( type(tags) ~= "table" ) then tags = {tags} end
    o.tags = tags
    return o
  end,

  --- Add a discovered credential
  --
  -- @param user the name of the user
  -- @param pass the password of the user
  -- @param state of the account
  -- @name Credentials.add
  add = function( self, user, pass, state )
    local pass = ( pass and #pass > 0 ) and pass or "<empty>"
    assert( self.host, "No host supplied" )
    assert( self.port, "No port supplied" )
    assert( state, "No state supplied")
    assert( self.tags, "No tags supplied")

    -- there are cases where we will only get a user or password
    -- so as long we have one of them, we're good
    if ( user or pass ) then
      self.storage:add( self.tags, self.host, self.port, self.service, user, pass, state )
    end
  end,

  --- Returns a credential iterator
  --
  -- @see State
  -- @param state mask containing values from the <code>State</code> table
  -- @return credential iterator, returning a credential each time it's
  --         called. Unless filtered by the state mask all credentials
  --         for the host, port match are iterated over.
  --         The credential table has the following fields:
  --         <code>host</code> - table as received by the action function
  --         <code>port</code> - number containing the port number
  --         <code>user</code> - string containing the user name
  --         <code>pass</code> - string containing the user password
  --         <code>state</code> - a state number
  --         <code>service</code> - string containing the name of the service
  --         <code>tags</code> - table containing tags associated with
  --                             the credential
  -- @name Credentials.getCredentials
  getCredentials = function(self, state)
    local function next_credential()
      if ( state ) then
        self.storage:setFilter(self.host, { number=self.port, service = self.service }, state)
      end

      for cred in self.storage:getAll() do
        if ( self.tags == ALL_DATA ) then
          coroutine.yield(cred)
        end
        for _,stag in pairs(self.tags) do
          for _,ctag in pairs(cred.tags) do
            if(stag == ctag) then
              coroutine.yield(cred)
            end
          end
        end
      end

      if ( state and State.PARAM == bit.band(state, State.PARAM) ) then
        local creds_global = stdnse.get_script_args('creds.global')
        local creds_service
        local creds_params

        if ( self.service ) then
          creds_service = stdnse.get_script_args('creds.' .. self.service )
        end

        if ( creds_service ) then creds_params = creds_service end
        if ( creds_global and creds_service ) then
          creds_params = creds_params .. ',' .. creds_global
        elseif ( creds_global ) then
          creds_params = creds_global
        end

        if ( not(creds_params) ) then return end

        for _, cred in ipairs(stdnse.strsplit(",", creds_params)) do
          -- if the credential contains a ':' we have a user + pass pair
          -- if not, we only have a user with an empty password
          local user, pass
          if ( cred:match(":") ) then
            user, pass = cred:match("^(.-):(.-)$")
          else
            user = cred:match("^(.*)$")
          end
          coroutine.yield( { host = self.host,
          port = self.port,
          user = user,
          pass = pass,
          state = State.PARAM,
          service = self.service } )
        end
      end
    end
    return coroutine.wrap( next_credential )
  end,

  --- Returns a table of credentials
  --
  -- @return tbl table containing the discovered credentials
  -- @name Credentials.getTable
  getTable = function(self)
    local result = {}

    for v in self:getCredentials() do
      local h = ( v.host.ip or v.host )
      assert(type(h)=="string", "Could not determine a valid host")
      local svc = ("%s/%s"):format(v.port,v.service)

      result[h] = result[h] or {}
      result[h][svc] = result[h][svc] or {}
      table.insert( result[h][svc], Account:new(
          v.user ~= "" and v.user or nil,
          v.pass,
          v.state
          )
        )
    end

    for _, host_tbl in pairs(result) do
      for _, svc_tbl in pairs(host_tbl) do
        -- sort the accounts
        table.sort( svc_tbl )
      end
      -- sort the services
      setmetatable(host_tbl, {
          __pairs = sorted_pairs( function(a,b)
              return tonumber(a:match("^(%d+)")) < tonumber(b:match("^(%d+)"))
            end )
        })
    end

    -- sort the IP addresses
    setmetatable(result, {
        __pairs = sorted_pairs( function(a, b)
          return ipOps.compare_ip(a, "le", b)
        end )
      })

    local _
    if ( self.host and next(result) ) then
      _, result = next(result)
    end
    if ( self.host and self.port and next(result) ) then
      _, result = next(result)
    end
    return next(result) and result
  end,

  -- Saves credentials in the current object to file
  -- @param filename string name of the file
  -- @param fileformat string file format type, values = csv | verbose | plain (default)
  -- @return status true on success, false on failure
  -- @return err string containing the error if status is false
  saveToFile = function(self, filename, fileformat)

    if ( fileformat == 'csv' ) then
      filename = filename .. '.csv'
    else
      filename = filename .. '.txt'
    end

    local f = io.open( filename, "w")
    local output = nil

    if ( not(f) ) then
      return false, ("ERROR: Failed to open file (%s)"):format(filename)
    end

    for account in self:getCredentials() do
      if ( fileformat == 'csv' ) then
        output = "\"" .. account.user .. "\",\"" .. account.pass .. "\",\"" .. StateMsg[account.state] .. "\""
      elseif ( fileformat == 'verbose') then
        output = account.user .. ":" .. account.pass .. ":" .. StateMsg[account.state]
      else
        output = account.user .. ":" .. account.pass
      end
      if ( not(f:write( output .."\n" ) ) ) then
        return false, ("ERROR: Failed to write file (%s)"):format(filename)
      end
    end

    f:close()
    return true
  end,

  --- Get credentials with optional host and port filter
  -- If no filters are supplied all records are returned
  --
  -- @param host table or string containing the host to filter
  -- @param port number containing the port to filter
  -- @return table suitable from <code>stdnse.format_output</code>
  -- @name Credentials.__tostring
  __tostring = function(self)
    local all = self:getTable()
    if ( all ) then return tostring(all) end
  end,

}

return _ENV;
