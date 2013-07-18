local coroutine = require "coroutine"
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local datafiles = require "datafiles"

description = [[
Searches for web virtual hostnames by making a large number of HEAD requests against http servers using common hostnames.

Each HEAD request provides a different
<code>Host</code> header. The hostnames come from a built-in default
list. Shows the names that return a document. Also shows the location of
redirections.

The domain can be given as the <code>http-vhosts.domain</code> argument or
deduced from the target's name. For example when scanning www.example.com,
various names of the form <name>.example.com are tried.
]]

---
-- @usage 
-- nmap --script http-vhosts -p 80,8080,443 <target>
--
-- @arg http-vhosts.domain The domain that hostnames will be prepended to, for
-- example <code>example.com</code> yields www.example.com, www2.example.com,
-- etc. If not provided, a guess is made based on the hostname.
-- @arg http-vhosts.path The path to try to retrieve. Default <code>/</code>.
-- @arg http-vhosts.collapse The limit to start collapsing results by status code. Default <code>20</code>
-- @arg http-vhosts.filelist file with the vhosts to try. Default <code>nselib/data/vhosts-default.lst</code>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-vhosts:
-- | example.com: 301 -> http://www.example.com/
-- | www.example.com: 200
-- | docs.example.com: 302 -> https://www.example.com/docs/
-- |_images.example.com: 200
--
-- @todo feature: move hostnames to an external file and allow the user to use another one
-- @internal: see http://seclists.org/nmap-dev/2010/q4/401 and http://seclists.org/nmap-dev/2010/q4/445
-- 
-- 
-- @todo feature: add option report and implement it
-- @internal after stripping sensitive info like ip, domain names, hostnames 
--           and redirection targets from the result, append it to a file 
--           that can then be uploaded. If enough info is gathered, the names 
--           will be weighted. It can be shared with metasploit
--
-- @todo feature: fill nsedoc
--
-- @todo feature: register results for other scripts (external help needed)
--
-- @todo feature: grow names list (external help needed)
--

author = "Carlos Pantelides"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = { "discovery", "intrusive" }

local arg_domain = stdnse.get_script_args(SCRIPT_NAME..".domain")
local arg_path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"
local arg_filelist = stdnse.get_script_args(SCRIPT_NAME..'.filelist')
local arg_collapse = tonumber(stdnse.get_script_args(SCRIPT_NAME..".collapse")) or 10

-- Defines domain to use, first from user and then from host
local defineDomain = function(host)
  local name = stdnse.get_hostname(host)
  if name and name ~= host.ip then
    local pos = string.find (name, ".",1,true)
    if not pos then return name end
    return string.sub (name, pos + 1)
  end
end

---
-- Makes a target name with a name and a domain
-- @param name string 
-- @param domain string
-- @return string
local makeTargetName = function(name,domain)
  if name and name ~= "" then
    if domain and domain ~= "" then
      return name .. "." .. domain
    else
      return name
    end
  elseif domain and domain ~= "" then
    return domain
  end
end


---
-- Collapses a result
-- key -> table
-- @param result table
-- @return string
local collapse = function(result) 
  local collapsed = {""}
  for code, group in next, result do
    if  #group > arg_collapse then
      table.insert(collapsed, ("%d names had status %s"):format(#group, code))
    else 
      for _,name in ipairs(group) do
        table.insert(collapsed, name)
      end
    end
  end
  return table.concat(collapsed,"\n")
end

local testThread = function(result, host, port, name)
  local condvar = nmap.condvar(result)
  local targetname = makeTargetName(name , arg_domain)
  if targetname ~= nil then
		local http_response = http.generic_request(host, port, "HEAD", arg_path, {header={Host=targetname}})

    if not http_response.status  then
      result["ERROR"] = result["ERROR"] or {}
      table.insert(result["ERROR"], targetname)
    else
      local status = tostring(http_response.status)
      result[status] = result[status] or {}
      if ( 300 <= http_response.status and http_response.status < 400 ) then
        table.insert(result[status], ("%s : %s -> %s"):format(targetname, status, (http_response.header.location or "(no Location provided)")))
      else 
        table.insert(result[status], ("%s : %s"):format(targetname, status))
      end
    end
  end
  condvar "signal"
end

portrule = shortport.http

---
-- Script action
-- @param host table
-- @param port table
action = function(host, port)
  local result, threads = {}, {}
  local condvar = nmap.condvar(result)

  local status, hostnames = datafiles.parse_file(arg_filelist or "nselib/data/vhosts-default.lst" , {})
  if not status then
    stdnse.print_debug(1, "Can not open file with vhosts file names list")
    return
  end

  arg_domain = arg_domain or defineDomain(host)
  for _,name in ipairs(hostnames) do
    local co = stdnse.new_thread(testThread, result, host, port, name)
    threads[co] = true
  end

  while(next(threads)) do
    for t in pairs(threads) do
      threads[t] = ( coroutine.status(t) ~= "dead" ) and true or nil
    end
    if ( next(threads) ) then
      condvar "wait"
    end
  end

  return collapse(result)
end
