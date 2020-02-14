local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local base64 = require "base64"
local string = require "string"
local table = require "table"
local io = require "io"

local libssh2_util = require "libssh2-utility"

description = [[
This script takes a table of paths to private keys, passphrases, and usernames
and checks each pair to see if the target ssh server accepts them for publickey
authentication. If no keys are given or the known-bad option is given, the
script will check if a list of known static public keys are accepted for
authentication.
]]

---
-- @usage
--  nmap -p 22 --script ssh-publickey-acceptance --script-args "ssh.usernames={'root', 'user'}, ssh.privatekeys={'./id_rsa1', './id_rsa2'}"  <target>
--
-- @usage
--  nmap -p 22 --script ssh-publickey-acceptance --script-args 'ssh.usernames={"root", "user"}, publickeys={"./id_rsa1.pub", "./id_rsa2.pub"}'  <target>
--
-- @output
-- 22/tcp open  ssh     syn-ack
-- | ssh-publickey-acceptance:
-- |   Accepted Public Keys:
-- |_    Key ./id_rsa1 accepted for user root
--
-- @args ssh.privatekeys Table containing filenames of privatekeys to test
-- @args ssh.passphrases Table containing passphrases for each private key
-- @args ssh.publickeys Table containing filenames of publickkeys to test
-- @args ssh.usernames Table containing usernames to check
-- @args knownbad   If specified, check if keys from publickeydb are accepted
-- @args publickeydb  Specifies alternative publickeydb

author = "Devin Bjelland"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "intrusive"}

local privatekeys = stdnse.get_script_args "ssh.privatekeys"
local passphrases = stdnse.get_script_args "ssh.passphrases" or {}
local usernames = stdnse.get_script_args "ssh.usernames"
local knownbad = stdnse.get_script_args "knownbad"
local publickeys = stdnse.get_script_args "ssh.publickeys"
local publickeydb = stdnse.get_script_args "publickeydb" or nmap.fetchfile("nselib/data/publickeydb")
portrule = shortport.ssh

function action (host, port)
  local result = stdnse.output_table()
  local r = {}
  local helper = libssh2_util.SSHConnection:new()
  local failures = 0
  local successes = 0
  if publickeys and usernames then
    for j = 1, #usernames do
      for i = 1, #publickeys do
        stdnse.debug("Checking key: " .. publickeys[i] .. " for user " .. usernames[j])
        local status, result = helper:read_publickey(publickeys[i])
        if not status then
          stdnse.verbose("Error reading key: " .. result)
        elseif helper:connect(host, port) then
          successes = successes + 1
          local status, err = helper:publickey_canauth(usernames[j], result)
          if status then
            table.insert(r, "Key " .. publickeys[i] .. " accepted for user " .. usernames[j])
            stdnse.verbose("Found accepted key: " .. publickeys[i] .. " for user " .. usernames[j])
          elseif err then
            stdnse.debug("Error in publickey_canauth: %s", err)
          end
          helper:disconnect()
        else
          -- Allow 3 connection attempts, then bail
          failures = failures + 1
          stdnse.debug1("Connect failed.")
          if failures > 2 then
            if successes == 0 then
              -- If we haven't succeeded even once, don't report results.
              stdnse.debug1("Giving up.")
              return nil
            else
              goto ACTION_END
            end
          end
        end
      end
    end
  end

  if knownbad or not (privatekeys or publickeys) then
    for line in io.lines(publickeydb) do
      local sections = {}
      for section in string.gmatch(line, '([^,]+)') do
        table.insert(sections, section)
      end
      local key = sections[1]
      local user = sections[2]
      local msg = sections[3]
      stdnse.debug("Checking key: " .. key .. " for user " .. user)
      key = base64.dec(key)
      if helper:connect(host, port) then
        successes = successes + 1
        if helper:publickey_canauth(user, key) then
          table.insert(r, msg)
          stdnse.verbose("Found accepted key: " .. msg)
        end
        helper:disconnect()
      else
        -- Allow 3 connection attempts, then bail
        failures = failures + 1
        stdnse.debug1("Connect failed.")
        if failures > 2 then
          if successes == 0 then
            -- If we haven't succeeded even once, don't report results.
            stdnse.debug1("Giving up.")
            return nil
          else
            goto ACTION_END
          end
        end
      end
    end
  end

  if privatekeys and usernames then
    for j = 1, #usernames do
      for i = 1, #privatekeys do
        stdnse.debug("Checking key: " .. privatekeys[i] .. " for user " .. usernames[j])
        if helper:connect(host, port) then
          successes = successes + 1
          if not helper:publickey_auth(usernames[j], privatekeys[i], passphrases[i] or "") then
            stdnse.verbose "Failed to authenticate"
          else
            table.insert(r, "Key " .. privatekeys[i] .. " accepted for user " .. usernames[j])
            stdnse.verbose("Found accepted key: " .. privatekeys[i] .. " for user " .. usernames[j])

          end
          helper:disconnect()
        else
          -- Allow 3 connection attempts, then bail
          failures = failures + 1
          stdnse.debug1("Connect failed.")
          if failures > 2 then
            if successes == 0 then
              -- If we haven't succeeded even once, don't report results.
              stdnse.debug1("Giving up.")
              return nil
            else
              goto ACTION_END
            end
          end
        end
      end
    end
  end

  ::ACTION_END::
  if #r > 0 then
    result["Accepted Public Keys"] = r
  else
    result["Accepted Public Keys"] = "No public keys accepted"
  end

  return result
end
