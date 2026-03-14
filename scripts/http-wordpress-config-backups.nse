local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Searches for leaked or forgotten backup copies of the WordPress configuration file (wp-config.php).
These files often contain highly sensitive information, such as database credentials.

---
usage:
  nmap --script http-wordpress-config-backups [--script-args http-wordpress-config-backups.path=/wp/] <target>

output:
  PORT   STATE SERVICE
  80/tcp open  http
  | http-wordpress-config-backups: 
  |   VULNERABLE: Found sensitive backup file: /wp-config.php.bak
  |_  VULNERABLE: Found sensitive backup file: /wp-config.php.old
]]

author = "1nf1n7y"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local base_path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  
  if not string.match(base_path, "/$") then
    base_path = base_path .. "/"
  end

  local backup_files = {
    "wp-config.php.bak", "wp-config.php.old", "wp-config.php.save",
    "wp-config.php.swp", "wp-config.php.txt", "wp-config.php.original",
    "wp-config.php~", ".wp-config.php.swp", "wp-config.bak",
    "wp-config.old", "config.php.bak", "_wp-config.php"
  }

  local results = stdnse.output_table()
  local requests = {}

  -- Build the pipeline requests
  for _, file in ipairs(backup_files) do
    table.insert(requests, base_path .. file)
  end

  -- Perform pipelined requests for efficiency
  local pipeline_responses = http.pipeline_get(host, port, requests)

  for i, response in ipairs(pipeline_responses) do
    if response.status == 200 and response.body then
      -- Verify content to avoid false positives
      if string.match(response.body, "DB_NAME") or 
         string.match(response.body, "DB_PASSWORD") or 
         string.match(response.body, "AUTH_KEY") then
        table.insert(results, "VULNERABLE: Found sensitive backup file: " .. requests[i])
      end
    end
  end

  if #results > 0 then
    return results
  end
end