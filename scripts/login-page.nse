local http = require "http"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Exposes the admin login page in any website.
Displays both the user login and admin login pages in all websites.
]]

---
-- @usage nmap --script login-page <target>
-- @usage nmap --script login-page --script-args type="php" <target>

-- @args login-page.type Checks for pages of particular extension,
--       default is type is all which checks for all the extensions.

-- @output
-- PORT   STATE SERVICE REASON
-- 22/tcp open  ssh     syn-ack ttl 64
-- 80/tcp open  http    syn-ack ttl 64
-- | login-page:
-- |   192.168.146.145/admin/
-- |   192.168.146.145/admin/index.php
-- |_  192.168.146.145/admin/login.php
---

author = "Rewanth Cool"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.portnumber(80, "tcp")

action = function(host, port)

  local path = "/"
  local type = stdnse.get_script_args(SCRIPT_NAME .. ".type") or "all"

  local existing_types = {
    "aspx",
    "asp",
    "brf",
    "cgi",
    "cfm",
    "js",
    "jsp",
    "php"
  }

  local flag = 0
  for _, v in ipairs(existing_types) do
    if type == v then
      flag = 1
    end
  end

  if flag == 0 then
    stdnse.debug("No database exists this type of websites yet.")
    stdnse.debug("Continuing with the existing database to check for general pages.")
    type = "all"
  end

  local file = "nselib/data/web-login/" .. type .. ".lst"

  local regex = {
    "Username",
    "Password",
    "username",
    "password",
    "USERNAME",
    "PASSWORD",
    "Admin Password"
  }

  local output = {}
  local uris = nmap.fetchfile(file)
  stdnse.debug(string.format(" Working on %s", uris))

  for uri in io.lines(uris) do
    local response = http.get(host, port, path .. uri)
    local hostname = host.targetname or host.ip

    if response.body ~= nil then
        stdnse.debug(string.format("Not nil : %s\n", hostname .. path .. uri))
    else
        stdnse.debug(string.format("Nil : %s\n", hostname .. path .. uri))
    end

    for _, v in ipairs(regex) do
      if response.body ~= nil and string.match(response.body, v) then

        local url = hostname .. path .. uri
        -- Removing the non-alpha numeric strings if there exist any
        local trimmed_url = url:gsub('%W','')
        table.insert(output, trimmed_url)
        break
      end
    end
  end

  local counter = 0
  for _, v in ipairs(output) do
    counter = counter + 1
  end

  if counter == 0 then
    return nil
  else
    return output
  end

end
