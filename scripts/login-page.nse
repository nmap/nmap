local http = require "http"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Exposes the admin login page in any website.
Displays both the user login and admin login pages in any website.

TODO:
- Automatically crawl the website and find the extension instead of taking
  it as a parameter from the user.
    - httpspider library can be used to accomplish this task.
- If there are frequent socket errors or http.request TIMEOUTS notify the user
  to check his internet connection and proxy instead of returning nil.
]]

---
--  @usage ./nmap --script login-page <target> -d
--  @usage ./nmap --script login-page --script-args extension="php" <target> -d
--
--  If timeout occurs frequently due to bad internet connection then
--  @usage ./nmap --script login-page --script-args extension="php" --host-timeout=<timeout> -d
--
--  Best way to run the script
--  If the user has prior knowledge on which port to check, he can save time by
--  specifying that particular port as a general command line argument using -p
--  @usage ./nmap --script login-page --script-args extension="jsp" -p 80 -d
--
--  @args login-page.extension Checks for pages of particular extension,
--        default is extension is all which checks for all the extensions.
--
--  @output
--  PORT   STATE SERVICE REASON
--  22/tcp open  ssh     syn-ack ttl 64
--  80/tcp open  http    syn-ack ttl 64
--  | login-page:
--  |   192.168.146.145/admin/
--  |   192.168.146.145/admin/index.php
--  |_  192.168.146.145/admin/login.php
---

author = "Rewanth Cool"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = function(host, port)
  -- Working :
  -- If -p argument is used, then the script will be executed only on the given ports.
  -- If -p argument is not used, then the script will be executed on all the open ports.
  stdnse.debug(string.format("Loading port %d", port.number))

  local selected_ports = shortport.port_or_service({port.number}, "http", "tcp", {"open", "open|filtered"})
  return selected_ports(host, port)
end

action = function(host, port)

  local path = "/"
  local extension = stdnse.get_script_args(SCRIPT_NAME .. ".extension") or "all"

  --  NOTE:
  --  If any new db file is created for non-existing extension
  --  make sure to update the name of the extension here also
  --  inorder to execute this script successfully.
  local existing_extensions = {
    "aspx",
    "asp",
    "brf",
    "cgi",
    "cfm",
    "js",
    "jsp",
    "php"
  }

  -- Checking whether the user provided extension is existing in our db or not.
  local flag = 0
  local string_of_existing_extensions = ''
  for _, v in ipairs(existing_extensions) do
    string_of_existing_extensions = string_of_existing_extensions .. v .. ', '
    if extension == v then
      flag = 1
    end
  end

  string_of_existing_extensions = string_of_existing_extensions .. 'all'

  -- If user provided extension is not in our db
  if flag == 0 then
    -- Extension type not found in the db, throwing a suggestion to end user.
    local err = "There is no extension like '" .. extension .. "' in the db."
    err = err .. " Send a mail to rewanth1997[at]gmail.com"
    err = err .. " and it will be updated soon to db."
    err = err .. " Available extensions are "
    err = err .. string_of_existing_extensions .. "\n"
    return err
  end

  local file = "nselib/data/web-login/" .. extension .. ".lst"

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
  local hostname = host.targetname or host.ip

  -- Fetching all the uris from the db
  local uris = nmap.fetchfile(file)
  stdnse.debug(string.format("Working on %s", uris))

  -- Reading line by line and sending requests to those pages.
  for uri in io.lines(uris) do
    stdnse.debug(string.format("Sending GET request to %s", hostname .. path .. uri))

    local response = http.get(host, port, path .. uri)

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
