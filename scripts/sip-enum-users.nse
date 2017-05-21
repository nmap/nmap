local io = require "io"
local nmap = require "nmap"
local string = require "string"
local shortport = require "shortport"
local sip = require "sip"
local stdnse = require "stdnse"
local table = require "table"
local math = require "math"
local brute = require "brute"
local creds = require "creds"
local unpwdb = require "unpwdb"

description = [[
Enumerates a SIP server's valid extensions (users).

The script works by sending REGISTER SIP requests to the server with the
specified extension and checking for the response status code in order
to know if an extension is valid. If a response status code is 401 or
407, it means that the extension is valid and requires authentication. If the
response status code is 200, it means that the extension exists and doesn't
require any authentication while a 403 response status code means that
extension exists but access is forbidden. To skip false positives, the script
begins by sending a REGISTER request for a random extension and checking for
response status code.
]]

---
--@args sip-enum-users.minext Extension value to start enumeration from.
--  Defaults to <code>0</code>.
--
--@args sip-enum-users.maxext Extension value to end enumeration at.
--  Defaults to <code>999</code>.
--
--@args sip-enum-users.padding Number of digits to pad zeroes up to.
--  Defaults to <code>0</code>. No padding if this is set to zero.
--
--@args sip-enum-users.users If set, will also enumerate users
--  from <code>userslist</code> file.
--
--@args sip-enum-users.userslist Path to list of users.
--  Defaults to <code>nselib/data/usernames.lst</code>.
--
--@usage
-- nmap --script=sip-enum-users -sU -p 5060 <targets>
--
-- nmap --script=sip-enum-users -sU -p 5060 <targets> --script-args
-- 'sip-enum-users.padding=4, sip-enum-users.minext=1000,
-- sip-enum-users.maxext=9999'
--
--@output
-- 5060/udp open sip
-- | sip-enum-users:
-- |   Accounts
-- |     101: Auth required
-- |     120: No auth
-- |   Statistics
-- |_    Performed 1000 guesses in 50 seconds, average tps: 20


author = "Hani Benhabiles"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"auth", "intrusive"}


portrule = shortport.port_or_service(5060, "sip", {"tcp", "udp"})

--- Function that sends register sip request with provided extension
-- using the specified session.
-- @arg sess session to use.
-- @arg ext Extension to send register request to.
-- @return status true on success, false on failure.
-- @return Response instance on success, error string on failure.
local registerext = function(sess, ext)
  -- set session values
  local request = sip.Request:new(sip.Method.REGISTER)

  request:setUri("sip:" ..  sess.sessdata:getServer())
  sess.sessdata:setUsername(ext)
  request:setSessionData(sess.sessdata)

  return sess:exch(request)
end

--- Function that returns a number as string with a number of zeroes padded to
-- the left.
-- @arg num Number to be padded.
-- @arg padding number of digits to pad up to.
-- @return string of padded number.
local padnum = function(num, padding)
  -- How many zeroes do we need to add
  local n = #tostring(num)
  if n >= padding then
    return tostring(num)
  end
  n = padding - n

  return string.rep(tostring(0), n) .. tostring(num)
end

--- Iterator function that returns values from a lower value up to a greater
-- value with zeroes padded up to padding argument.
-- @arg minval Start value.
-- @arg maxval End value.
-- @arg padding number of digits to pad up to.
-- @return string current value.
local numiterator = function(minval, maxval, padding)
  local i = minval - 1
  return function()
    i = i + 1
    if i <= maxval then return padnum(i, padding), '' end
  end
end

--- Iterator function that returns lines from a file
-- @arg userslist Path to file list in data location.
-- @return status false if error.
-- @return string current line.
local useriterator = function(list)
  local f = nmap.fetchfile(list) or list
  if not f then
    return false, ("Couldn't find %s"):format(list)
  end
  f = io.open(f)
  if ( not(f) ) then
    return false, ("Failed to open %s"):format(list)
  end
  return function()
    for line in f:lines() do
      return line
    end
  end
end

--- function that tests for 404 status code when sending a REGISTER request
-- with a random sip extension.
-- @arg host Target host table.
-- @arg port Target port table.
local test404 = function(host, port)
  local session, status, randext, response
  -- Random extension
  randext = math.random(1234567,987654321)

  session = sip.Session:new(host, port)
  status = session:connect()
  if not status then
    return false, "Failed to connect to the SIP server."
  end

  status, response = registerext(session, randext)
  if  not status then
    return false, "No response from the SIP server."
  end
  if response:getErrorCode() ~= 404 then
    return false, "Server not returning 404 for random extension."
  end
  return true

end

Driver = {

  new = function(self, host, port)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    return o
  end,

  connect = function( self )
    self.session = sip.Session:new(self.host, self.port)
    local status = self.session:connect()
    if ( not(status) ) then
      return false, brute.Error:new( "Couldn't connect to host" )
    end
    return true
  end,

  login = function( self, username, password)
    -- We are using the "password" values instead of the "username" so we
    -- could benefit from brute.lua passonly option and setPasswordIterator
    -- function, as we are doing usernames enumeration only and not
    -- credentials brute forcing.
    local status, response, responsecode
    -- Send REGISTER request for each extension
    status, response = registerext(self.session, password)
    if status then
      responsecode = response:getErrorCode()
      -- If response status code is 401 or 407, then extension exists but
      -- requires authentication
      if responsecode == sip.Error.UNAUTHORIZED or
        responsecode == sip.Error.PROXY_AUTH_REQUIRED then
        return true, creds.Account:new(password, " Auth required", '')

        -- If response status code is 200, then extension exists
        -- and requires no authentication
      elseif responsecode == sip.Error.OK then
        return true, creds.Account:new(password, " No auth", '')
        -- If response status code is 200, then extension exists
        -- but access is forbidden.

      elseif responsecode == sip.Error.FORBIDDEN then
        return true, creds.Account:new(password, " Forbidden", '')
      end
      return false,brute.Error:new( "Not found" )
    else
      return false,brute.Error:new( "No response" )
    end
  end,

  disconnect = function(self)
    self.session:close()
    return true
  end,
}

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
  local result, lthreads = {}, {}
  local status, err
  local minext = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".minext")) or 0
  local minext = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".minext")) or 0
  local maxext = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".maxext")) or 999
  local padding = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".padding")) or 0
  local users = stdnse.get_script_args(SCRIPT_NAME .. ".users")
  local usersfile = stdnse.get_script_args(SCRIPT_NAME .. ".userslist")
  or "nselib/data/usernames.lst"

  -- min extension should be less than max extension.
  if minext > maxext then
    return fail("maxext should be greater or equal than minext.")
  end
  -- If not set to zero, number of digits to pad up to should have less or
  -- equal the number of digits of max extension.
  if padding ~= 0 and #tostring(maxext) > padding then
    return fail("padding should be greater or equal to number of digits of maxext.")
  end

  -- We test for false positives by sending a request for a random extension
  -- and checking if it did return a 404.
  status, err = test404(host, port)
  if not status then
    return fail(err)
  end

  local engine = brute.Engine:new(Driver, host, port)
  engine.options.script_name = SCRIPT_NAME

  local iterator = numiterator(minext, maxext, padding)
  if users then
    local usernames, err = useriterator(usersfile)
    if not usernames then
      return fail(err)
    end
    -- Concat numbers and users iterators
    iterator = unpwdb.concat_iterators(iterator, usernames)
  end
  engine:setPasswordIterator(iterator)
  engine.options.passonly = true
  status, result = engine:start()

  return result
end
