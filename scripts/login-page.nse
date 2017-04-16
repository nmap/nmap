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

  -- Checking whether the user provided type is existing in our db or not.
  local flag = 0
  for _, v in ipairs(existing_types) do
    if type == v then
      flag = 1
    end
  end

  -- If no such db exists then we combine all the db and check againsts them
  if flag == 0 then
    stdnse.debug("No database exists this type of websites yet.")
    stdnse.debug("Continuing with the existing database to check for general pages.")

    -- Extension type not found in the db, so assigning the type a special value
    -- which checks for all types of extensions
    type = "all"
  end

  local file = "nselib/data/web-login/" .. type .. ".lst"

  -- These regex are used while scraping the web pages for confirmation.
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

  -- Fetching all the uris from the db
  local uris = nmap.fetchfile(file)
  stdnse.debug(string.format("Working on %s", uris))

  -- Reading line by line and sending requests to those pages.
  for uri in io.lines(uris) do
    local response = http.get(host, port, path .. uri)
    local hostname = host.targetname or host.ip

    for _, v in ipairs(regex) do
      if response.body ~= nil and string.match(response.body, v) then
        local url = hostname .. path .. uri
        -- Removing the non-alpha numeric strings if there exist any like \x0D
        local trimmed_url = url:gsub('\x0D','')
        table.insert(output, trimmed_url)
        break
      end
    end

  end

  -- Counter, that checks if output table is empty or not.
  local counter = 0
  for _, v in ipairs(output) do
    counter = counter + 1
  end

  -- If the output table is empty return nil.
  if counter == 0 then
    return nil
  else
    return output
  end

end
