local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Checks if the target http server has mod_negotiation enabled.  This
feature can be leveraged to find hidden resources and spider a web
site using fewer requests.

The script works by sending requests for resources like index and home
without specifying the extension. If mod_negotiate is enabled (default
Apache configuration), the target would reply with content-location header
containing target resource (such as index.html) and vary header containing
"negotiate" depending on the configuration.

For more information, see:
* http://www.wisec.it/sectou.php?id=4698ebdc59d15
* Metasploit auxiliary module
    /modules/auxiliary/scanner/http/mod_negotiation_scanner.rb
]]

---
-- @usage
-- nmap --script=http-apache-negotiation --script-args http-apache-negotiation.root=/root/ <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_http-apache-negotiation: mod_negotiation enabled.
--
-- @args http-apache-negotiation.root target web site root.
--  Defaults to <code>/</code>.

author = "Hani Benhabiles"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}


portrule = shortport.http

action = function(host, port)

  local root = stdnse.get_script_args("http-apache-negotiation.root") or "/"

  -- Common default file names. Could add a couple more.
  local files = {
    'robots',
    'index',
    'home',
    'blog'
  }

  for _, file in ipairs(files) do
    local header = http.get(host, port, root .. file).header

    -- Matching file. in content-location header
    --  or negotiate in vary header.
    if header["content-location"] and string.find(header["content-location"], file ..".")
      or header["vary"] and string.find(header["vary"], "negotiate")  then
      return "mod_negotiation enabled."
    end
  end
end
