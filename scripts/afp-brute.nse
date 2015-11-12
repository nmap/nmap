local afp = require "afp"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local unpwdb = require "unpwdb"

-- we don't really need openssl here, but let's attempt to load it as a way
-- to simply prevent the script from running, in case we don't have it
local openssl = stdnse.silent_require("openssl")

description = [[
Performs password guessing against Apple Filing Protocol (AFP).
]]

---
-- @usage
-- nmap -p 548 --script afp-brute <host>
--
-- @output
-- PORT    STATE SERVICE
-- 548/tcp open  afp
-- | afp-brute:
-- |_  admin:KenSentMe => Valid credentials

-- Information on AFP implementations
--
-- Snow Leopard
-- ------------
-- - Delay 10 seconds for accounts with more than 5 incorrect login attempts (good)
-- - Instant response if password is successful
--
-- Netatalk
-- --------
-- - Netatalk responds with a "Parameter error" when the username is invalid
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


-- Version 0.3
-- Created 01/15/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 03/09/2010 - v0.2 - changed so that passwords are iterated over users
--                           - this change makes better sense as guessing is slow
-- Revised 09/09/2011 - v0.3 - changed account status text to be more consistent with other *-brute scripts

portrule = shortport.port_or_service(548, "afp")

action = function( host, port )

  local result, response, status = {}, nil, nil
  local valid_accounts, found_users = {}, {}
  local helper
  local usernames, passwords

  status, usernames = unpwdb.usernames()
  if not status then return end

  status, passwords = unpwdb.passwords()
  if not status then return end

  for password in passwords do
    for username in usernames do
      if ( not(found_users[username]) ) then

        helper = afp.Helper:new()
        status, response = helper:OpenSession( host, port )

        if ( not(status) ) then
          stdnse.debug1("OpenSession failed")
          return
        end


        stdnse.debug1("Trying %s/%s ...", username, password)
        status, response = helper:Login( username, password )

        -- if the response is "Parameter error." we're dealing with Netatalk
        -- This basically means that the user account does not exist
        -- In this case, why bother continuing? Simply abort and thank Netatalk for the fish
        if response:match("Parameter error.") then
          stdnse.debug1("Netatalk told us the user does not exist! Thanks.")
          -- mark it as "found" to skip it
          found_users[username] = true
        end

        if status then
          -- Add credentials for other afp scripts to use
          if nmap.registry.afp == nil then
            nmap.registry.afp = {}
          end
          nmap.registry.afp[username]=password
          found_users[username] = true

          table.insert( valid_accounts, string.format("%s:%s => Valid credentials", username, password:len()>0 and password or "<empty>" ) )
          break
        end
        helper:CloseSession()
      end
    end
    usernames("reset")
  end

  local output = stdnse.format_output(true, valid_accounts)

  return output

end
