local stdnse = require "stdnse"
local shortport = require "shortport"
local dns = require "dns"
local base32 = require "base32"
local bin = require "bin"
local nmap = require "nmap"
local string = require "string"
local table = require "table"

local openssl = stdnse.silent_require "openssl"

description = [[
Tries to enumerate domain names from the DNS server that supports DNSSEC
NSEC3 records.

The script queries for nonexistant domains until it exhausts all domain
ranges keeping track of hashes. At the end, all hashes are printed along
with salt and number of iterations used. This technique is known as
"NSEC3 walking".

That info should then be fed into an offline cracker, like
<code>unhash</code> from http://dnscurve.org/nsec3walker.html, to
bruteforce the actual names from the hashes. Assuming that the script
output was written into a text file <code>hashes.txt</code> like:
<code>
domain example.com
salt 123456
iterations 10
nexthash d1427bj0ahqnpi4t0t0aaun18oqpgcda vhnelm23s1m3japt7gohc82hgr9un2at
nexthash k7i4ekvi22ebrim5b6celtaniknd6ilj prv54a3cr1tbcvqslrb7bftf5ji5l0p8
nexthash 9ool6bk7r2diaiu81ctiemmb6n961mph nm7v0ig7h9c0agaedc901kojfj9bgabj
nexthash 430456af8svfvl98l66shhrgucoip7mi mges520acstgaviekurg3oksh9u31bmb
</code>

Run this command to recover the domain names:
<code>
# ./unhash < hashes.txt > domains.txt
names: 8
d1427bj0ahqnpi4t0t0aaun18oqpgcda ns.example.com.
found 1 private NSEC3 names (12%) using 235451 hash computations
k7i4ekvi22ebrim5b6celtaniknd6ilj vulpix.example.com.
found 2 private NSEC3 names (25%) using 35017190 hash computations
</code>

Use the <code>dns-nsec-enum</code> script to handle servers that use NSEC
rather than NSEC3.

References:
* http://dnscurve.org/nsec3walker.html
]]
---
-- @usage
-- nmap  -sU -p 53 <target> --script=dns-nsec3-enum --script-args dns-nsec3-enum.domains=example.com
---
-- @args dns-nsec3-enum.domains The domain or list of domains to
-- enumerate. If not provided, the script will make a guess based on the
-- name of the target.
-- @args dns-nsec3-enum.timelimit Sets a script run time limit. Default 30 minutes.
--
-- @output
-- PORT   STATE SERVICE
-- 53/udp open  domain
-- | dns-nsec3-enum:
-- |   domain example.com
-- |   salt 123456
-- |   iterations 10
-- |   nexthash d1427bj0ahqnpi4t0t0aaun18oqpgcda vhnelm23s1m3japt7gohc82hgr9un2at
-- |   nexthash k7i4ekvi22ebrim5b6celtaniknd6ilj prv54a3cr1tbcvqslrb7bftf5ji5l0p8
-- |   nexthash 9ool6bk7r2diaiu81ctiemmb6n961mph nm7v0ig7h9c0agaedc901kojfj9bgabj
-- |   nexthash 430456af8svfvl98l66shhrgucoip7mi mges520acstgaviekurg3oksh9u31bmb
-- |_  Total hashes found: 8

author = {"Aleksandar Nikolic", "John R. Bond"}
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"discovery", "intrusive"}

portrule = shortport.port_or_service(53, "domain", {"tcp", "udp"})

all_results = {}

-- get time (in milliseconds) when the script should finish
local function get_end_time()
  local t = nmap.timing_level()
  local limit = stdnse.parse_timespec(stdnse.get_script_args('dns-nsec3-enum.timelimit') or "30m")
  local end_time  = 1000 * limit + nmap.clock_ms()
  return end_time
end

local function remove_empty(t)
  local result = {}
  for _, v in ipairs(t) do
    if v ~= "" then
      result[#result + 1] = v
    end
  end
  return result
end

local function split(domain)
  return stdnse.strsplit("%.", domain)
end

local function join(components)
  return stdnse.strjoin(".", remove_empty(components))
end

-- Remove the first component of a domain name. Return nil if the number of
-- components drops below min_length (default 0).
local function remove_component(domain, min_length)
  local components

  min_length = min_length or 0
  components = split(domain)
  if #components < min_length then
    return nil
  end
  table.remove(components, 1)

  return join(components)
end

-- Guess the domain given a host. Return nil on failure. This function removes
-- a domain name component unless the name would become shorter than 2
-- components.
local function guess_domain(host)
  local name
  local components

  name = stdnse.get_hostname(host)
  if name and name ~= host.ip then
    return remove_component(name, 2) or name
  else
    return nil
  end
end

-- Remove a suffix from a domain (to isolate a subdomain from its parent).
local function remove_suffix(domain, suffix)
  local dc, sc

  dc = split(domain)
  sc = split(suffix)
  while #dc > 0 and #sc > 0 and dc[#dc] == sc[#sc] do
    dc[#dc] = nil
    sc[#sc] = nil
  end

  return join(dc), join(sc)
end

-- Return the subset of authoritative records with the given label.
local function auth_filter(retPkt, label)
  local result = {}

  for _, rec in ipairs(retPkt.auth) do
    if rec[label] then
      result[#result + 1] = rec[label]
    end
  end

  return result
end


local function empty(t)
  return not next(t)
end

-- generate a random hash with domains suffix
-- return both domain and its hash
local function generate_hash(domain, iter, salt)
  local rand_str = stdnse.generate_random_string(8, "etaoinshrdlucmfw")
  local random_domain = rand_str .. "." .. domain
  local packed_domain = {}
  for word in string.gmatch(random_domain, "[^%.]+") do
    packed_domain[#packed_domain+1] = bin.pack("p", word)
  end
  salt = bin.pack("H", salt)
  local to_hash = bin.pack("AxA", table.concat(packed_domain), salt)
  iter = iter - 1
  local hash = openssl.sha1(to_hash)
  for i=0,iter do
    hash = openssl.sha1(hash .. salt)
  end
  return string.lower(base32.enc(hash,true)), random_domain
end

-- convenience function , returns size of a table
local function table_size(tbl)
  local numItems = 0
  for k,v in pairs(tbl) do
    numItems = numItems + 1
  end
  return numItems
end

-- convenience function , return first item in a table
local function get_first(tbl)
  for k,v in pairs(tbl) do
    return k,v
  end
end

-- queries the domain and parses the results
-- returns the list of new ranges
local function query_for_hashes(host,subdomain,domain)
  local status
  local result
  local ranges = {}
  status, result = dns.query(subdomain, {host = host.ip, dtype='NSEC3', retAll=true, retPkt=true, dnssec=true})
  if status then
    for _, nsec3 in ipairs(auth_filter(result, "NSEC3")) do
      local h1 = string.lower(remove_suffix(nsec3.dname,domain))
      local h2 = string.lower(nsec3.hash.base32)
      if not stdnse.contains(all_results,"nexthash " .. h1 .. " " .. h2) then
        table.insert(all_results, "nexthash " .. h1 .. " " .. h2)
        stdnse.debug1("nexthash " .. h1 .. " " .. h2)
      end
      ranges[h1] = h2
    end
  else
    stdnse.debug1("DNS error: %s", result)
  end
  return ranges
end

-- does the actual enumeration
local function enum(host, port, domain)

  local seen, seen_subdomain = {}, {}
  local ALG ={}
  ALG[1] = "SHA-1"
  local todo = {}
  local dnssec, status, result = false, false, "No Answer"
  local result = {}
  local subdomain = stdnse.generate_random_string(8, "etaoinshrdlucmfw")
  local full_domain = join({subdomain, domain})
  local iter
  local salt
  local end_time = get_end_time()

  -- do one query to determine the hash and if DNSSEC is actually used
  status, result = dns.query(full_domain, {host = host.ip, dtype='NSEC3', retAll=true, retPkt=true, dnssec=true})
  if status then
    local is_nsec3 = false
    for _, nsec3 in ipairs(auth_filter(result, "NSEC3")) do -- parse the results and add initial ranges
      is_nsec3 = true
      dnssec = true
      iter = nsec3.iterations
      salt = nsec3.salt.hex
      local h1 = string.lower(remove_suffix(nsec3.dname,domain))
      local h2 = string.lower(nsec3.hash.base32)
      if table_size(todo) == 0 then
        table.insert(all_results, "domain " .. domain)
        stdnse.debug1("domain " .. domain)
        table.insert(all_results, "salt " .. salt)
        stdnse.debug1("salt " .. salt)
        table.insert(all_results, "iterations " .. iter)
        stdnse.debug1("iterations " .. iter)
        if h1 < h2 then
          todo[h2] = h1
        else
          todo[h1] = h2
        end
      else
        for b,a in pairs(todo) do
          if h1 == b and h2 == a then -- h2:a  b:h1 case
            todo[b] = nil
            break
          end
          if h1 == b and h2 > h1 then -- a  b:h1   h2 case
            todo[b] = nil
            todo[h2] = a
            break
          end
          if h1 == b and h2 < a then -- h2  a  b:h1
            todo[b] = nil
            todo[b] = h2
            break
          end
          if h1 > b  then  -- a b h1 h2
            todo[b] = nil
            todo[b] = h1
            todo[h2] = a
            break
          end
          if h1 < a then -- h1 h2 a b
            todo[b] = nil
            todo[b] = h1
            todo[h2] = a
            break
          end
        end -- for
      end -- else
      table.insert(all_results, "nexthash " .. h1 .. " " .. h2)
      stdnse.debug1("nexthash " .. h1 .. " " .. h2)
    end
  end

  -- find hash that falls into one of the ranges and query for it
  while table_size(todo) > 0 and nmap.clock_ms() < end_time do
    local hash
    hash, subdomain  = generate_hash(domain,iter,salt)
    local queried = false
    for a,b in pairs(todo) do
      if a == b then
        todo[a] = nil
        break
      end
      if a < b then -- [] range
        if hash > a and hash < b then
          -- do the query
          local hash_pairs = query_for_hashes(host,subdomain,domain)
          queried = true
          local changed = false
          for h1,h2 in pairs(hash_pairs) do
            if h1 == a and h2 == b then -- h1:a h2:b case
              todo[a] = nil
              changed = true
            end
            if  h1 == a then -- h1:a h2 b case
              todo[a] = nil
              todo[h2] = b
              changed = true
            end
            if h2 == b then  -- a h1 bh:2 case
              todo[a] = nil
              todo[a] = h1
              changed = true
            end
            if h1 > a and h2 < b then -- a h1 h2 b case
              todo[a] = nil
              todo[a] = h1
              todo[h2] = b
              changed = true
            end
          end
          --if changed then
          --  stdnse.debug1("break[]")
          --break
          --  end
        end
      elseif a > b then -- ][ range
        if hash > a or hash < b then
          local hash_pairs = query_for_hashes(host,subdomain,domain)
          queried = true
          local changed = false
          for h1,h2 in pairs(hash_pairs) do
            if h1 == a  and h2 == b then -- h2:b  a:h1 case
              todo[a] = nil
              changed = true
            end
            if h1 == a and h2 > h1 then  -- b   a:h1 h2 case
              todo[a] = nil
              todo[h1] = b
              changed = true
            end
            if h1 == a and h2 < b then -- h2 b a:h1 case
              todo[a] = nil
              todo[h2] = b
              changed = true
            end
            if h1 > a and h2 > h1 then  -- b   a   h1 h2 case
              todo[a] = nil
              todo[a] = h1
              todo[h2] = b
              changed = true
            end
            if h1 > a and h2 < b then -- h2 b a h1 case
              todo[a] = nil
              todo[a] = h1
              todo[h2] = b
              changed = true
            end
            if h1 < b then -- h1 h2 b a case
              todo[a] = nil
              todo[a] = h1
              todo[h2] = b
              changed = true
            end
          end
          if changed then
            --break
          end
        end
      end
      if queried then
        break
      end
    end
  end
  return dnssec, status, all_results
end

action = function(host, port)
  local output = {}
  local domains
  domains = stdnse.get_script_args('dns-nsec3-enum.domains')
  if not domains then
    domains = guess_domain(host)
  end
  if not domains then
    return string.format("Can't determine domain for host %s; use %s.domains script arg.", host.ip, SCRIPT_NAME)
  end
  if type(domains) == 'string' then
    domains = { domains }
  end

  for _, domain in ipairs(domains) do
    local dnssec, status, result = enum(host, port, domain)
    if dnssec and type(result) == "table" then
      output[#output + 1] = result
      output[#output + 1] = "Total hashes found: " .. #result

    else
      output[#output + 1] = "DNSSEC NSEC3 not supported"
    end
  end
  return stdnse.format_output(true, output)
end
