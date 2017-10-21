local dns = require "dns"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates DNS names using the DNSSEC NSEC-walking technique.

Output is arranged by domain. Within a domain, subzones are shown with
increased indentation.

The NSEC response record in DNSSEC is used to give negative answers to
queries, but it has the side effect of allowing enumeration of all
names, much like a zone transfer. This script doesn't work against
servers that use NSEC3 rather than NSEC; for that, see
<code>dns-nsec3-enum</code>.
]]

---
-- @args dns-nsec-enum.domains The domain or list of domains to
-- enumerate. If not provided, the script will make a guess based on the
-- name of the target.
--
-- @usage
-- nmap -sSU -p 53 --script dns-nsec-enum --script-args dns-nsec-enum.domains=example.com <target>
--
-- @see dns-nsec3-enum.nse
-- @see dns-ip6-arpa-scan.nse
-- @see dns-brute.nse
-- @see dns-zone-transfer
--
-- @output
-- 53/udp open  domain  udp-response
-- | dns-nsec-enum:
-- |   example.com
-- |     bulbasaur.example.com
-- |     charmander.example.com
-- |     dugtrio.example.com
-- |     www.dugtrio.example.com
-- |     gyarados.example.com
-- |       johto.example.com
-- |       blue.johto.example.com
-- |       green.johto.example.com
-- |       ns.johto.example.com
-- |       red.johto.example.com
-- |     ns.example.com
-- |     snorlax.example.com
-- |_    vulpix.example.com

author = "John R. Bond"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"

categories = {"discovery", "intrusive"}


portrule = function (host, port)
  if not shortport.port_or_service(53, "domain", {"tcp", "udp"})(host, port) then
    return false
  end
  -- only check tcp if udp is not open or open|filtered
  if port.protocol == 'tcp' then
    local tmp_port = nmap.get_port_state(host, {number=port.number, protocol="udp"})
    if tmp_port then
      return not string.match(tmp_port.state, '^open')
    end
  end
  return true
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
  if #components <= min_length then
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

local function invert(t)
  local result = {}

  for k, v in pairs(t) do
    result[v] = k
  end

  return result
end

-- RFC 952: "A 'name' is a text string up to 24 characters drawn from the
-- alphabet (A-Z), digits (0-9), minus sign (-), and period (.). ... The first
-- character must be an alpha character."
-- RFC 1123, section 2.1: "One aspect of host name syntax is hereby changed:
-- the restriction on the first character is relaxed to allow either a letter
-- or a digit."
-- RFC 2782: An underscore (_) is prepended to the service identifier to avoid
-- collisions with DNS labels that occur in nature.
local DNS_CHARS = { string.byte("-0123456789_abcdefghijklmnopqrstuvwxyz", 1, -1) }
local DNS_CHARS_INV = invert(DNS_CHARS)

-- Return the lexicographically next component, or nil if component is the
-- lexicographically last.
local function increment_component(name)
  local i, bytes, indexes

  -- Easy cases first.
  if #name == 0 then
    return "0"
  elseif #name < 63 then
    return name .. "-"
  elseif #name > 64 then
    -- Shouldn't happen.
    return nil
  end

  -- Convert the string into an array of indexes into DNS_CHARS.
  indexes = {}
  for i, b in ipairs({ string.byte(name, 1, -1) }) do
    indexes[i] = DNS_CHARS_INV[b]
  end
  -- Increment.
  i = #name
  while i >= 1 do
    repeat
      indexes[i] = indexes[i] + 1
    -- No "-" in first position.
    until not (i == 1 and string.char(DNS_CHARS[indexes[i]]) == "-")
    if indexes[i] > #DNS_CHARS then
      -- Wrap around, next digit.
      indexes[i] = 1
    else
      break
    end
    i = i - 1
  end
  -- Overflow.
  if i == 0 then
    return nil
  end
  -- Convert array of indexes back into string.
  bytes = {}
  for i, index in ipairs(indexes) do
    bytes[i] = DNS_CHARS[index]
  end

  return string.char(table.unpack(bytes))
end

-- Return the lexicographically next domain name that does not add a new
-- subdomain. This is used after enumerating a whole subzone to jump out of the
-- subzone and on to more names.
local function bump_domain(domain)
  local components

  components = split(domain)
  while #components > 0 do
    components[1] = increment_component(components[1])
    if components[1] then
      break
    else
      table.remove(components[1])
    end
  end

  if #components == 0 then
    return nil
  else
    return join(components)
  end
end

-- Return the lexicographically next domain name. This adds a new subdomain
-- consisting of the smallest character. This function never returns a domain
-- outside the current subzone.
local function next_domain(domain)
  if #domain == 0 then
    return "0"
  else
    return "0" .. "." .. domain
  end
end

-- Cut out a portion of an array and return it as a new array, setting the
-- elements in the original array to nil.
local function excise(t, i, j)
  local result

  result = {}
  if j < 0 then
    j = #t + j + 1
  end
  for i = i, j do
    result[#result + 1] = t[i]
    t[i] = nil
  end

  return result
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

-- "Less than" function for two domain names. Compares starting with the last
-- component.
local function domain_lt(a, b)
  local a_parts, b_parts

  a_parts = split(a)
  b_parts = split(b)
  while #a_parts > 0 and #b_parts > 0 do
    if a_parts[#a_parts] < b_parts[#b_parts] then
      return true
    elseif a_parts[#a_parts] > b_parts[#b_parts] then
      return false
    end
    a_parts[#a_parts] = nil
    b_parts[#b_parts] = nil
  end

  return #a_parts < #b_parts
end

-- Find the NSEC record that brackets the given domain.
local function get_next_nsec(retPkt, domain)
  for _, nsec in ipairs(auth_filter(retPkt, "NSEC")) do
    -- The last NSEC record points backwards to the start of the subzone.
    if domain_lt(nsec.dname, domain) and not domain_lt(nsec.dname, nsec.next_dname) then
      return nsec
    end
    if domain_lt(nsec.dname, domain) and domain_lt(domain, nsec.next_dname) then
      return nsec
    end
  end
end

local function empty(t)
  return not next(t)
end

-- Enumerate a single domain.
local function enum(host, port, domain)
  local all_results = {}
  local seen = {}
  local subdomain = next_domain("")

  while subdomain do
    local result = {}
    local status, result, nsec
    stdnse.debug1("Trying %q.%q", subdomain, domain)
    status, result = dns.query(join({subdomain, domain}), {host = host.ip, port=port.number, proto=port.protocol, dtype='A', retAll=true, retPkt=true, dnssec=true})
    nsec = status and get_next_nsec(result, join({subdomain, domain})) or nil
    if nsec then
      local first, last, remainder
      local index

      first, remainder = remove_suffix(nsec.dname, domain)
      if #remainder > 0 then
        stdnse.debug1("Result name %q doesn't end in %q.", nsec.dname, domain)
        subdomain = nil
        break
      end
      last, remainder = remove_suffix(nsec.next_dname, domain)
      if #remainder > 0 then
        stdnse.debug1("Result name %q doesn't end in %q.", nsec.next_dname, domain)
        subdomain = nil
        break
      end
      if #last == 0 then
        stdnse.debug1("Wrapped")
        subdomain = nil
        break
      end

      if not seen[first] then
        table.insert(all_results, join({first, domain}))
        seen[first] = #all_results
      end
      index = seen[last]
      if index then
        -- Ignore if first is the original domain.
        if #first > 0 then
          subdomain = bump_domain(last)
          -- Replace a chunk of the output with a sub-table for the zone.
          all_results[index] = excise(all_results, index, -1)
        end
      else
        stdnse.debug1("adding %s", last)
        subdomain = next_domain(last)
        table.insert(all_results, join({last, domain}))
        seen[last] = #all_results
      end
    else
      local parent = remove_component(subdomain, 1)

      -- This branch is entered if name resolution failed or
      -- there were no NSEC records. If at the top, quit.
      -- Otherwise continue to the next subdomain.
      if parent then
        subdomain = bump_domain(parent)
      else
        return nil
      end
    end
  end

  return all_results
end

action = function(host, port)
  local output = {}
  local domains

  domains = stdnse.get_script_args('dns-nsec-enum.domains')
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
    local result = enum(host, port, domain)
    if type(result) == "table" then
      result["name"] = domain
      output[#output + 1] = result
    else
      output[#output + 1] = "No NSEC records found"
    end
  end

  return stdnse.format_output(true, output)
end
