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
- Current database are having only 150 entries for each extension, updating this
  is a never ending process and this can be done frequently to obtain better results.
]]

---
--  @usage ./nmap --script login-page <target> -d
--  @usage ./nmap --script login-page --script-args extension="php" <target> -d
--
--  If timeout occurs frequently due to bad internet connection then
--  @usage ./nmap --script login-page --script-args extension="php" <target> --host-timeout=<timeout> -d
--
--  Best way to run the script
--  If the user has prior knowledge on which port to check, he can save time by
--  specifying that particular port as a general command line argument using -p
--  @usage ./nmap --script login-page --script-args extension="jsp" <target> -p 80 -d
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

portrule = shortport.http

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
    "php",
    "all"
  }

  -- If extension is not provided, then select complete list as default.
  if extension == nil then
    extension = "all"
  end

  -- Raising an error if the extension provided by the user is not existing in our database.
  if not stdnse.contains(existing_extensions, extension) then
    -- Inserting error statements into the table to throw as an error.
    table.insert(existing_extensions, "The above list are the available extensions.")
    table.insert(existing_extensions, "Send a report to dev[at]nmap.org if you find a valid extension is missing in the above list.")
    return existing_extensions
  end

  local file = "nselib/data/web-login/" .. extension .. ".lst"

  -- Insensitive case regex for matching key words from the page
  local regex = {
    "[uU][sS][eE][rR][nN][aA][mM][eE]", -- English (Username)
    "[pP][aA][sS][sS][wW][oO][rR][dD]", -- English (Password)
    "[pP]/[wW]", -- English (P/W)
    "[aA][dD][mM][iI][nN] [pP][aA][sS][sS][wW][oO][rR][dD]", -- English (Admin Password)
    "[pP][eE][rR][sS][oO][nN][aA][lL]", -- English (Personal)
    "[wW][aA][cC][hH][tT][wW][oO][oO][rR][dD]", --Dutch (Password)
    "[sS][eE][nN][hH][aA]", --Portuguese (Password)
    "[cC][lL][aA][vV][eE]", --Spanish (Key)
    "[uU][sS][aA][gG][eE][rR]" --French (User)
  }


  local output = {}
  local hostname = host.targetname or host.ip

  -- Fetching all the uris from the db
  local uris = nmap.fetchfile(file)
  stdnse.debug(string.format("Working on %s", uris))

  -- Reading line by line and sending requests to those pages.
  for uri in io.lines(uris) do
    stdnse.debug(string.format("Sending GET request to %s", hostname .. ':' .. port.number .. path .. uri))

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

  -- If the output table is empty return nil.
  if #output > 0 then
    return output
  else
    return nil
  end

end
