local coroutine = require "coroutine"
local dns = require "dns"
local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local tab = require "tab"
local table = require "table"

description = [[
Performs a quick reverse DNS lookup of an IPv6 network using a technique
which analyzes DNS server response codes to dramatically reduce the number of queries needed to enumerate large networks.

The technique essentially works by adding an octet to a given IPv6 prefix
and resolving it. If the added octet is correct, the server will return
NOERROR, if not a NXDOMAIN result is received.

The technique is described in detail on Peter's blog:
http://7bits.nl/blog/2012/03/26/finding-v6-hosts-by-efficiently-mapping-ip6-arpa
]]

---
-- @usage
-- nmap --script dns-ip6-arpa-scan --script-args='prefix=2001:0DB8::/48'
--
-- @output
-- Pre-scan script results:
-- | dns-ip6-arpa-scan: 
-- | ip                                 ptr
-- | 2001:0DB8:0:0:0:0:0:2              resolver1.example.com
-- |_2001:0DB8:0:0:0:0:0:3              resolver2.example.com
--
-- @args prefix the ip6 prefix to scan
-- @args mask the ip6 mask to start scanning from

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "discovery"}


local arg_prefix = stdnse.get_script_args(SCRIPT_NAME .. ".prefix")
local arg_mask = stdnse.get_script_args(SCRIPT_NAME .. ".mask")

-- Return a prefix and mask based on script arguments. First checks for "/"
-- netmask syntax; then looks for a "mask" script argument if that fails. The
-- "/" syntax wins over "mask" if both are present.
local function get_prefix_mask(arg_prefix, arg_mask)
	if not arg_prefix then
		return
	end
	local prefix, mask = string.match(arg_prefix, "^(.*)/(.*)$")
	if not mask then
		prefix, mask = arg_prefix, arg_mask
	end
	return prefix, mask
end

prerule = function()
	local prefix, mask = get_prefix_mask(arg_prefix, arg_mask)
	return prefix and mask
end

local function query_prefix(query, result)
	local condvar = nmap.condvar(result)
	local status, res = dns.query(query, { dtype='PTR' })
	if ( not(status) and res == "No Answers") then
		table.insert(result, query)
	elseif ( status ) then
		local ip = query:sub(1, -10):gsub('%.',''):reverse():gsub('(....)', '%1:'):sub(1, -2)
		ip = ipOps.bin_to_ip(ipOps.ip_to_bin(ip))
		table.insert(result, { ptr = res, query = query, ip = ip } )
	end
	condvar "signal"
end

action = function()

	local prefix, mask = get_prefix_mask(arg_prefix, arg_mask)
	local query = dns.reverse(prefix)

	-- cut the query name down to the length of the prefix
	local len = (( mask / 8 ) * 4) + #(".ip6.arpa") - 1

	local found = { query:sub(-len) }
	local threads = {}

	local i = 20

	local result
	repeat
		result = {}
		for _, f in ipairs(found) do
			for q in ("0123456789abcdef"):gmatch("(%w)") do
				local co = stdnse.new_thread(query_prefix, q .. "." .. f, result)
				threads[co] = true
			end
		end
		
		local condvar = nmap.condvar(result)
		repeat
			for t in pairs(threads) do
				if ( coroutine.status(t) == "dead" ) then threads[t] = nil end
			end
			if ( next(threads) ) then
				condvar "wait"
			end
		until( next(threads) == nil )
			
		if ( 0 == #result ) then
			return
		end
				
		found = result
		i = i + 1
	until( 128 == i * 2 + mask )

	table.sort(result, function(a,b) return (a.ip < b.ip) end)
	local output = tab.new(2)
	tab.addrow(output, "ip", "ptr")

	for _, item in ipairs(result) do
		tab.addrow(output, item.ip, item.ptr)
	end
	
	return "\n" .. tab.dump(output)
end
