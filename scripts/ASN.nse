---NOTE! FIX DNS ENTRY
id = "ASN"
description = "nmap <target> --script asn --script-args dns=<recursion_enabled_dns_server>"
author = "Jah, Michael"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery"}

require "comm"
require "ipOps"

hostrule = function( host )
 return true
end

if not nmap.registry.asn then
 nmap.registry.asn = {}
 nmap.registry.asn.cache = {}
end

local mutex = nmap.mutex( id )

action = function( host )

 -- get args or die
 local dns_server
 if nmap.registry.args.dns then
   dns_server = nmap.registry.args.dns
 else
   return
 end

 -- wait
 mutex "lock"

 -- check for cached data
 for _, cache in ipairs( nmap.registry.asn.cache ) do
   if ip_in_net( host.ip, cache.bgp) then
     mutex "done"
     return " \nBGP Prefix: " .. cache.bgp ..  "\nAS number: " .. cache.asn ..  "\nCountry Code: " .. cache.co_id
   end
 end

 -- format data
 local t = {}
 t[4], t[3], t[2], t[1] = host.ip:match( "([^\.]*)\.([^\.]*)\.([^\.]*)\.([^\.]*)" )
 local tsoh = labels( t )
 local z = { "nmap", "asn", "cymru", "com" }
 local zone = labels( z )

 local t_id = string.char( tonumber( t[2] ), tonumber( t[3] ) ) -- not at all random...
 local dns_std = string.char( 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 )
 local null_char = string.char( 0x00 )
 local qtype = string.char( 0x00, 0x10 )
 local qclass = string.char( 0x00, 0x01 )
 local query = tsoh .. zone .. null_char .. qtype .. qclass

 local data = t_id .. dns_std .. query

 -- send data
 local options = {}
 options.proto = "udp"
 options.lines = 1
 options.timeout = 1000
 local status, result = comm.exchange( dns_server, 53, data, options )
 if not status then
   mutex "done"
   return
 end

 -- read result - this method is tenuous!!
 local _, offset = string.find( result, query )
 local line = string.sub( result, offset + 13 )
 fields = {line:match( ("([^|]*)|"):rep(3) )}

 -- cache result
 local blob = {}
 blob.bgp = fields[2]:gsub( "^%s*(.-)%s*$", "%1" )
 blob.asn = fields[1]:gsub( "^%s*[^0](.-)%s*$", "%1" )
 blob.co_id = fields[3]:gsub( "^%s*(.-)%s*$", "%1" )
 table.insert( nmap.registry.asn.cache, blob )
 mutex "done"

 -- return result
 return " \nBGP Prefix: " .. blob.bgp .. "\nAS number: " .. blob.asn .. "\nCountry Code: " .. blob.co_id

end


-- labels
-- given a table of strings, return a string made up of concateneted labels
-- where each label consists of a length value (cast as char) followed by that number of characters.
function labels( t )
 local ret = ""
 for _, v in ipairs(t) do
     ret = ret .. string.char( string.len(v) ) .. v
 end
 return ret
end

-- ip_in_net
-- returns true if the supplied ip address falls inside the supplied range
function ip_in_net(ip, net)
 local i, j, net_lo, net_hi, dw_ip
 local m_dotted = "(%d+%.%d+%.%d+%.%d+)[%s]*[-][%s]*(%d+%.%d+%.%d+%.%d+)"
 local m_cidr = "(%d+)[.]*(%d*)[.]*(%d*)[.]*(%d*)[/]+(%d+)"

 if net:match(m_dotted) then
   net_lo, net_hi = net:match(m_dotted)
   net_lo = ipOps.todword(net_lo)
   net_hi = ipOps.todword(net_hi)
 elseif net:match(m_cidr) then
   net_lo, net_hi = two_dwords(net, m_cidr)
 end

 dw_ip = ipOps.todword(ip)
 if net_lo <= dw_ip  and dw_ip <= net_hi then return true end
 return false
end

-- two_dwords
-- returns the two ip addresses at either end of a cidr range, as dwords
function two_dwords(str, patt)
 local a, b, c, d, e, lo_net, host
 a, b, c, d, e = str:match(patt)
 local ipt = {b, c, d}
 local strip = ""
 for _, cap in ipairs(ipt) do
   if cap == "" then cap = "0" end
   strip = strip .. "." .. cap
 end
 lo_net = a .. strip
 if e ~= "" then e = tonumber(e)
   if e and e <=32 then
     host = 32 - e end
 end
 return ipOps.todword(lo_net), ipOps.todword(lo_net) + 2^host - 1
end