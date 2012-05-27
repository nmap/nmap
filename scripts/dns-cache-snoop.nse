local dns = require "dns"
local math = require "math"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Performs DNS cache snooping against a DNS server.

There are two modes of operation, controlled by the
<code>dns-cache-snoop.mode</code> script argument. In
<code>nonrecursive</code> mode (the default), queries are sent to the
server with the RD (recursion desired) flag set to 0. The server should
respond positively to these only if it has the domain cached. In
<code>timed</code> mode, the mean and standard deviation response times
for a cached domain are calculated by sampling the resolution of a name
(www.google.com) several times. Then, each domain is resolved and the
time taken compared to the mean. If it is less than one standard
deviation over the mean, it is considered cached. The <code>timed</code>
mode inserts entries in the cache and can only be used reliably once.

The default list of domains to check consists of the top 50 most popular
sites, each site being listed twice, once with "www." and once without.
Use the <code>dns-cache-snoop.domains</code> script argument to use a
different list.
]]

---
-- @args dns-cache-snoop.mode which of two supported snooping methods to
-- use. <code>nonrecursive</code>, the default, checks if the server
-- returns results for non-recursive queries. Some servers may disable
-- this. <code>timed</code> measures the difference in time taken to
-- resolve cached and non-cached hosts. This mode will pollute the DNS
-- cache and can only be used once reliably.
-- @args dns-cache-snoop.domains an array of domain to check in place of
-- the default list.
--
-- @usage
-- nmap -sU -p 53 --script dns-cache-snoop.nse --script-args 'dns-cache-snoop.mode=timed,dns-cache-snoop.domains={host1,host2,host3}' <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 53/udp open  domain  udp-response
-- | dns-cache-snoop: 10 of 100 tested domains are cached.
-- | www.google.com
-- | facebook.com
-- | www.facebook.com
-- | www.youtube.com
-- | yahoo.com
-- | twitter.com
-- | www.twitter.com
-- | www.google.com.hk
-- | www.google.co.uk
-- |_www.linkedin.com


author = "Eugene V. Alexeev"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"intrusive", "discovery"}

portrule = shortport.port_or_service(53, "domain", "udp")

local DOMAINS = {}
local MODE = "nonrecursive"
-- This domain is used as a default cached entry in timed mode.
local TIMED_DUMMY_DOMAIN = "www.google.com"
-- How many samples to collect for the time taken to resolve the dummy domain.
local TIMED_NUM_SAMPLES = 25
-- In timed mode, times below mean + TIMED_MULTIPLIER * stddev are
-- accepted as cached. Using one standard deviation gives us a roughly
-- 84% chance that a domain with the same response time as the reference
-- domain will be detected as cached.
local TIMED_MULTIPLIER = 1.0

-- This list is the first 50 entries of
-- http://s3.amazonaws.com/alexa-static/top-1m.csv.zip on 2010-06-11.
local ALEXA_DOMAINS = {
	"google.com",
	"facebook.com",
	"youtube.com",
	"yahoo.com",
	"live.com",
	"wikipedia.org",
	"baidu.com",
	"blogger.com",
	"msn.com",
	"qq.com",
	"twitter.com",
	"yahoo.co.jp",
	"google.co.in",
	"taobao.com",
	"google.de",
	"google.com.hk",
	"wordpress.com",
	"amazon.com",
	"sina.com.cn",
	"google.co.uk",
	"microsoft.com",
	"bing.com",
	"google.fr",
	"ebay.com",
	"myspace.com",
	"yandex.ru",
	"google.co.jp",
	"linkedin.com",
	"163.com",
	"google.com.br",
	"mail.ru",
	"flickr.com",
	"craigslist.org",
	"google.it",
	"fc2.com",
	"conduit.com",
	"rapidshare.com",
	"vkontakte.ru",
	"google.es",
	"googleusercontent.com",
	"bbc.co.uk",
	"imdb.com",
	"soso.com",
	"doubleclick.com",
	"go.com",
	"livejasmin.com",
	"apple.com",
	"aol.com",
	"bp.blogspot.com",
	"youku.com",
}

-- Construct the default list of domains.
for _, domain in ipairs(ALEXA_DOMAINS) do
  DOMAINS[#DOMAINS + 1] = domain
  if not string.match(domain, "^www%.") then
    DOMAINS[#DOMAINS + 1] = "www." .. domain
  end
end

-- Return the mean and sample standard deviation of an array, using the
-- algorithm from Knuth Vol. 2, Section 4.2.2.
function mean_stddev(t)
  local i, m, s, sigma

  if #t == 0 then
    return 0, nil
  end

  m = t[1]
  s = 0
  for i = 2, #t do
    local mp = m
    m = m + (t[i] - m) / i
    s = s + (t[i] - mp) * (t[i] - m)
  end
  sigma = math.sqrt(s / (#t - 1))

  return m, sigma
end

local function nonrecursive_mode(host, port, domains)
  local cached = {}

  for _,domain in ipairs(domains) do
    if dns.query(domain, {host = host.ip, port = port.number, tries = 0, norecurse=true}) then
      cached[#cached + 1] = domain
    end
  end

  return cached
end

-- Return the time taken (in seconds) to resolve the given domain, or nil if
-- it could not be resolved.
local function timed_query(host, port, domain)
  local start, stop

  start = nmap.clock_ms()
  if dns.query(domain, {host = host.ip, port = port.number, tries = 0, norecurse = false}) then
    stop = nmap.clock_ms()
    return (stop - start) / 1000
  else
    return nil
  end
end

local function timed_mode(host, port, domains)
  local cached = {}
  local i, t

  -- Insert in the cache.
  timed_query(host, port, TIMED_DUMMY_DOMAIN)

  -- Measure how long it takes to resolve on average.
  local times = {}
  local mean, stddev
  local cutoff
  for i = 1, TIMED_NUM_SAMPLES do
    t = timed_query(host, port, TIMED_DUMMY_DOMAIN)
    if t then
      times[#times + 1] = t
    end
  end
  mean, stddev = mean_stddev(times)
  cutoff = mean + stddev * TIMED_MULTIPLIER
  stdnse.print_debug(1, "dns-cache-snoop: reference %s: mean %g  stddev %g  cutoff %g", TIMED_DUMMY_DOMAIN, mean, stddev, cutoff)

  -- Now try all domains one by one.
  for _, domain in ipairs(domains) do
    t = timed_query(host, port, domain)
    if t then
      if t < cutoff then
        stdnse.print_debug(1, "dns-cache-snoop: %s: %g is cached (cutoff %g)", domain, t, cutoff)
        cached[#cached + 1] = domain
      else
        stdnse.print_debug(1, "dns-cache-snoop: %s: %g not cached (cutoff %g)", domain, t, cutoff)
      end
    end
  end

  return cached
end

action = function(host, port)
  local domains = DOMAINS
  local mode = MODE

  local args = nmap.registry.args
  if args then
    if args["dns-cache-snoop.mode"] then
      mode = args["dns-cache-snoop.mode"]
    end
    if args["dns-cache-snoop.domains"] then
      domains = args["dns-cache-snoop.domains"]
    end
  end

  local cached

  mode = string.lower(mode)
  if mode == "nonrecursive" then
    cached = nonrecursive_mode(host, port, domains)
  elseif mode == "timed" then
    cached = timed_mode(host, port, domains)
  else
    return string.format("Error: \"%s\" is not a known mode. Use \"nonrecursive\" or \"timed\".")
  end

  if #cached > 0 then
    nmap.set_port_state(host, port, "open")
  end

  return string.format("%d of %d tested domains are cached.\n", #cached, #domains) ..  stdnse.strjoin("\n", cached)
end
