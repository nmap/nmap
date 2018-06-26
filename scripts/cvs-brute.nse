local brute = require "brute"
local creds = require "creds"
local cvs = require "cvs"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs brute force password auditing against CVS pserver authentication.
]]

---
-- @usage
-- nmap -p 2401 --script cvs-brute <host>
--
-- @output
-- 2401/tcp open  cvspserver syn-ack
-- | cvs-brute:
-- |   Accounts
-- |     hotchner:francisco - Account is valid
-- |     reid:secret - Account is valid
-- |   Statistics
-- |_    Performed 544 guesses in 14 seconds, average tps: 38
--
-- @args cvs-brute.repo string containing the name of the repository to brute
--       if no repo was given the script checks the registry for any
--       repositories discovered by the cvs-brute-repository script. If the
--       registry contains any discovered repositories, the script attempts to
--       brute force the credentials for the first one.

-- Version 0.1
-- Created 07/13/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>


author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}
dependencies = {"cvs-brute-repository"}


portrule = shortport.port_or_service(2401, "cvspserver")

Driver =
{

  new = function(self, host, port, repo)
    local o = { repo = repo, helper = cvs.Helper:new(host, port) }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  connect = function( self )
    self.helper:connect(brute.new_socket())
    return true
  end,

  login = function( self, username, password )
    local status, err = self.helper:login( self.repo, username, password )
    if ( status ) then
      return true, creds.Account:new(username, password, creds.State.VALID)
    end

    -- This error seems to indicate that the user does not exist
    if ( err:match("E PAM start error%: Critical error %- immediate abort\0$") ) then
      stdnse.debug2("The user %s does not exist", username)
      local err = brute.Error:new("Account invalid")
      err:setInvalidAccount(username)
      return false, err
    end
    return false, brute.Error:new( "Incorrect password" )
  end,

  disconnect = function( self )
    self.helper:close()
  end,

}

local function getDiscoveredRepos(host)

  if ( not(host.registry.cvs_repos)) then
    return
  end

  return host.registry.cvs_repos
end

action = function(host, port)

  local repo = stdnse.get_script_args("cvs-brute.repo") and
    { stdnse.get_script_args("cvs-brute.repo") } or
    getDiscoveredRepos(host)
  if ( not(repo) ) then stdnse.verbose1("ERROR: No CVS repository specified (see cvs-brute.repo)") end

  local status, result

  -- If repositories were discovered and not overridden by argument
  -- only attempt to brute force the first one.
  local engine = brute.Engine:new(Driver, host, port, repo[1])

  engine.options.script_name = SCRIPT_NAME
  status, result = engine:start()

  return result
end

