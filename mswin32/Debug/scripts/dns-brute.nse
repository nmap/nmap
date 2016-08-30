local coroutine = require "coroutine"
local dns = require "dns"
local io = require "io"
local math = require "math"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

description = [[
Attempts to enumerate DNS hostnames by brute force guessing of common
subdomains. With the <code>dns-brute.srv</code> argument, dns-brute will also
try to enumerate common DNS SRV records.
]]
-- 2011-01-26

---
-- @usage
-- nmap --script dns-brute --script-args dns-brute.domain=foo.com,dns-brute.threads=6,dns-brute.hostlist=./hostfile.txt,newtargets -sS -p 80
-- nmap --script dns-brute www.foo.com
-- @args dns-brute.hostlist The filename of a list of host strings to try.
--                          Defaults to "nselib/data/vhosts-default.lst"
-- @args dns-brute.threads  Thread to use (default 5).
-- @args dns-brute.srv      Perform lookup for SRV records
-- @args dns-brute.srvlist  The filename of a list of SRV records to try.
--                          Defaults to "nselib/data/dns-srv-names"
-- @args dns-brute.domain   Domain name to brute force if no host is specified
-- @output
-- Pre-scan script results:
-- | dns-brute:
-- |   DNS Brute-force hostnames
-- |     www.foo.com - 127.0.0.1
-- |     mail.foo.com - 127.0.0.2
-- |     blog.foo.com - 127.0.1.3
-- |     ns1.foo.com - 127.0.0.4
-- |_    admin.foo.com - 127.0.0.5
-- @xmloutput
-- <table key="DNS Brute-force hostnames">
--   <table>
--     <elem key="address">127.0.0.1</elem>
--     <elem key="hostname">www.foo.com</elem>
--   </table>
--   <table>
--     <elem key="address">127.0.0.2</elem>
--     <elem key="hostname">mail.foo.com</elem>
--   </table>
--   <table>
--     <elem key="address">127.0.1.3</elem>
--     <elem key="hostname">blog.foo.com</elem>
--   </table>
--   <table>
--     <elem key="address">127.0.0.4</elem>
--     <elem key="hostname">ns1.foo.com</elem>
--   </table>
--   <table>
--     <elem key="address">127.0.0.5</elem>
--     <elem key="hostname">admin.foo.com</elem>
--   </table>
-- </table>
-- <table key="SRV results"></table>

author = "Cirrus"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"intrusive", "discovery"}

prerule = function()
  if not stdnse.get_script_args("dns-brute.domain") then
    stdnse.debug1("Skipping '%s' %s, 'dns-brute.domain' argument is missing.", SCRIPT_NAME, SCRIPT_TYPE)
    return false
  end
  return true
end

hostrule = function(host)
  return true
end

local function guess_domain(host)
  local name

  name = stdnse.get_hostname(host)
  if name and name ~= host.ip then
    return string.match(name, "%.([^.]+%..+)%.?$") or string.match(name, "^([^.]+%.[^.]+)%.?$")
  else
    return nil
  end
end

-- Single DNS lookup, returning all results. dtype should be e.g. "A", "AAAA".
local function resolve(host, dtype)
  local status, result = dns.query(host, {dtype=dtype,retAll=true})
  return status and result or false
end

local function array_iter(array, i, j)
  return coroutine.wrap(function ()
    while i <= j do
      coroutine.yield(array[i])
      i = i + 1
    end
  end)
end

local function thread_main(domainname, results, name_iter)
  local condvar = nmap.condvar( results )
  for name in name_iter do
    for _, dtype in ipairs({"A", "AAAA"}) do
      local res = resolve(name..'.'..domainname, dtype)
      if(res) then
        for _,addr in ipairs(res) do
          local hostn = name..'.'..domainname
          if target.ALLOW_NEW_TARGETS then
            stdnse.debug1("Added target: "..hostn)
            local status,err = target.add(hostn)
          end
          stdnse.debug1("Hostname: "..hostn.." IP: "..addr)
          local record = { hostname=hostn, address=addr }
          setmetatable(record, {
            __tostring = function(t)
              return string.format("%s - %s", t.hostname, t.address)
            end
          })
          results[#results+1] = record
        end
      end
    end
  end
  condvar("signal")
end

local function srv_main(domainname, srvresults, srv_iter)
  local condvar = nmap.condvar( srvresults )
  for name in srv_iter do
    local res = resolve(name..'.'..domainname, "SRV")
    if(res) then
      for _,addr in ipairs(res) do
        local hostn = name..'.'..domainname
        addr = stdnse.strsplit(":",addr)
        for _, dtype in ipairs({"A", "AAAA"}) do
          local srvres = resolve(addr[4], dtype)
          if(srvres) then
            for srvhost,srvip in ipairs(srvres) do
              if target.ALLOW_NEW_TARGETS then
                stdnse.debug1("Added target: "..srvip)
                local status,err = target.add(srvip)
              end
              stdnse.debug1("Hostname: "..hostn.." IP: "..srvip)
              local record = { hostname=hostn, address=srvip }
              setmetatable(record, {
                __tostring = function(t)
                  return string.format("%s - %s", t.hostname, t.address)
                end
              })
              srvresults[#srvresults+1] = record
            end
          end
        end
      end
    end
  end
  condvar("signal")
end

action = function(host)
  local domainname = stdnse.get_script_args('dns-brute.domain')
  if not domainname then
    domainname = guess_domain(host)
  end
  if not domainname then
    return string.format("Can't guess domain of \"%s\"; use %s.domain script argument.", stdnse.get_hostname(host), SCRIPT_NAME)
  end

  if not nmap.registry.bruteddomains then
    nmap.registry.bruteddomains = {}
  end

  if nmap.registry.bruteddomains[domainname] then
    stdnse.debug1("Skipping already-bruted domain %s", domainname)
    return nil
  end

  nmap.registry.bruteddomains[domainname] = true
  stdnse.debug1("Starting dns-brute at: "..domainname)
  local max_threads = tonumber( stdnse.get_script_args('dns-brute.threads') ) or 5
  local dosrv = stdnse.get_script_args("dns-brute.srv") or false
  stdnse.debug1("THREADS: "..max_threads)
  -- First look for dns-brute.hostlist
  local fileName = stdnse.get_script_args('dns-brute.hostlist')
  -- Check fetchfile locations, then relative paths
  local commFile = (fileName and nmap.fetchfile(fileName)) or fileName
  -- Finally, fall back to vhosts-default.lst
  commFile = commFile or nmap.fetchfile("nselib/data/vhosts-default.lst")
  local hostlist = {}
  if commFile then
    for l in io.lines(commFile) do
      if not l:match("#!comment:") then
        table.insert(hostlist, l)
      end
    end
  else
    stdnse.debug1("Cannot find hostlist file, quitting")
    return
  end

  local threads, results, srvresults = {}, {}, {}
  local condvar = nmap.condvar( results )
  local i = 1
  local howmany = math.floor(#hostlist/max_threads)+1
  stdnse.debug1("Hosts per thread: "..howmany)
  repeat
    local j = math.min(i+howmany, #hostlist)
    local name_iter = array_iter(hostlist, i, j)
    threads[stdnse.new_thread(thread_main, domainname, results, name_iter)] = true
    i = j+1
  until i > #hostlist
  local done
  -- wait for all threads to finish
  while( not(done) ) do
    done = true
    for thread in pairs(threads) do
      if (coroutine.status(thread) ~= "dead") then done = false end
    end
    if ( not(done) ) then
      condvar("wait")
    end
  end

  if(dosrv) then
    -- First look for dns-brute.srvlist
    fileName = stdnse.get_script_args('dns-brute.srvlist')
    -- Check fetchfile locations, then relative paths
    commFile = (fileName and nmap.fetchfile(fileName)) or fileName
    -- Finally, fall back to dns-srv-names
    commFile = commFile or nmap.fetchfile("nselib/data/dns-srv-names")
    local srvlist = {}
    if commFile then
      for l in io.lines(commFile) do
        if not l:match("#!comment:") then
          table.insert(srvlist, l)
        end
      end

      i = 1
      threads = {}
      howmany = math.floor(#srvlist/max_threads)+1
      condvar = nmap.condvar( srvresults )
      stdnse.debug1("SRV's per thread: "..howmany)
      repeat
        local j = math.min(i+howmany, #srvlist)
        local name_iter = array_iter(srvlist, i, j)
        threads[stdnse.new_thread(srv_main, domainname, srvresults, name_iter)] = true
        i = j+1
      until i > #srvlist
      local done
      -- wait for all threads to finish
      while( not(done) ) do
        done = true
        for thread in pairs(threads) do
          if (coroutine.status(thread) ~= "dead") then done = false end
        end
        if ( not(done) ) then
          condvar("wait")
        end
      end
    else
      stdnse.debug1("Cannot find srvlist file, skipping")
    end
  end

  local response = stdnse.output_table()
  if(#results==0) then
    setmetatable(results, { __tostring = function(t) return "No results." end })
  end
  response["DNS Brute-force hostnames"] = results
  if(dosrv) then
    if(#srvresults==0) then
      setmetatable(srvresults, { __tostring = function(t) return "No results." end })
    end
    response["SRV results"] = srvresults
  end
  return response
end

