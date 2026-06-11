local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Searches for leaked or forgotten backup copies of the WordPress configuration file (wp-config.php).
These files often contain highly sensitive information, such as database credentials.
]]

author = "1nf1n7y"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  -- Receive the path from the user or use the root path '/'.
  local base_path = stdnse.get_script_args("http-wordpress-config-backups.path") or "/"
  
  -- "Ensuring that the path ends with a forward slash.
  if not string.match(base_path, "/$") then
    base_path = base_path .. "/"
  end

  local backup_files = {
    "wp-config.php.bak",
    "wp-config.php.old",
    "wp-config.php.save",
    "wp-config.php.swp",
    "wp-config.php.txt",
    "wp-config.php.original",
    "wp-config.php~",
    ".wp-config.php.swp",
    "wp-config.bak",
    "wp-config.old",
    "config.php.bak",
    "_wp-config.php"
  }

  local results = {}

  for _, file in ipairs(backup_files) do
    local full_path = base_path .. file
    local response = http.get(host, port, full_path)

    if response.status == 200 and response.body then
      -- Verifying/Checking keywords inside the file
      if string.match(response.body, "DB_NAME") or 
         string.match(response.body, "DB_PASSWORD") or 
         string.match(response.body, "AUTH_KEY") then
        table.insert(results, "VULNERABLE: Found sensitive backup file: " .. full_path)
      end
    end
  end

  -- Display results using table.concat to avoid stdnse errors.
  if #results > 0 then
    return "\n" .. table.concat(results, "\n")
  end
end
