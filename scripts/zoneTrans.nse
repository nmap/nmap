id = "zone-transfer"
description = [[
Requests a zone transfer (AXFR) from a DNS server.

The script sends an AXFR query to a DNS server. The domain to query is
determined by examining the name given on the command line, the DNS
server's hostname, or it can be specified with the
<code>zoneTrans.domain</code> script argument. If the query is
successful all domains and domain types are returned along with common
type specific data (SOA/MX/NS/PTR/A).

If we don't have the "true" hostname for the DNS server we cannot
determine a likely zone to perform the transfer on.

Useful resources
* DNS for rocket scientists: http://www.zytrax.com/books/dns/
* How the AXFR protocol works: http://cr.yp.to/djbdns/axfr-notes.html
]]

---
-- @args zoneTrans.domain Domain to transfer.
-- @output
-- 53/tcp   open     domain
-- |  zone-transfer:
-- |  foo.com.            SOA     ns2.foo.com. piou.foo.com.
-- |  foo.com.            TXT  
-- |  foo.com.            NS      ns1.foo.com.               
-- |  foo.com.            NS      ns2.foo.com.               
-- |  foo.com.            NS      ns3.foo.com.               
-- |  foo.com.            A       127.0.0.1                  
-- |  foo.com.            MX      mail.foo.com.              
-- |  anansie.foo.com.    A       127.0.0.2                  
-- |  dhalgren.foo.com.   A       127.0.0.3                  
-- |  drupal.foo.com.     CNAME
-- |  goodman.foo.com.    A       127.0.0.4 i                
-- |  goodman.foo.com.    MX      mail.foo.com.              
-- |  isaac.foo.com.      A       127.0.0.5                  
-- |  julie.foo.com.      A       127.0.0.6                  
-- |  mail.foo.com.       A       127.0.0.7                  
-- |  ns1.foo.com.        A       127.0.0.7                  
-- |  ns2.foo.com.        A       127.0.0.8                  
-- |  ns3.foo.com.        A       127.0.0.9                  
-- |  stubing.foo.com.    A       127.0.0.10                 
-- |  vicki.foo.com.      A       127.0.0.11                 
-- |  votetrust.foo.com.  CNAME
-- |  www.foo.com.        CNAME
-- |_ foo.com.            SOA     ns2.foo.com. piou.foo.com.

require('shortport')
require('strbuf')
require('stdnse')
require('listop')
require('bit')
require('tab')

author = 'Eddie Bell <ejlbell@gmail.com>'
license = 'Same as Nmap--See http://nmap.org/book/man-legal.html'
categories = {'default', 'intrusive', 'discovery'}
runlevel = 1.0

portrule = shortport.portnumber(53, 'tcp') 

--- DNS query and response types.
--@class table
--@name typetab
local typetab = { 'A', 'NS', 'MD', 'MF', 'CNAME', 'SOA', 'MB', 'MG', 'MR', 
 'NULL', 'WKS', 'PTR', 'HINFO', 'MINFO', 'MX', 'TXT', 'RP', 'AFSDB', 'X25',
 'ISDN', 'RT', 'NSAP', 'NSAP-PTR', 'SIG', 'KEY', 'PX', 'GPOS', 'AAAAA', 'LOC',
 'NXT', 'EID', 'NIMLOC', 'SRV', 'ATMA', 'NAPTR', 'KX', 'CERT', 'A6', 'DNAME',
 'SINK', 'OPT', [250]='TSIG', [251]='IXFR', [252]='AXFR', [253]='MAILB', 
 [254]='MAILA', [255]='ANY', [256]='ZXFR'
}

--- Whitelist of TLDs. Only way to reliably determine the root of a domain
--@class table
--@name tld
local tld = {
 'aero', 'asia', 'biz', 'cat', 'com', 'coop', 'info', 'jobs', 'mobi', 'museum',
 'name', 'net', 'org', 'pro', 'tel', 'travel', 'gov', 'edu', 'mil', 'int',
 'ac','ad','ae','af','ag','ai','al','am','an','ao','aq','ar','as','at','au','aw',
 'ax','az','ba','bb','bd','be','bf','bg','bh','bi','bj','bm','bn','bo','br','bs',
 'bt','bv','bw','by','bz','ca','cc','cd','cf','cg','ch','ci','ck','cl','cm','cn',
 'co','cr','cu','cv','cx','cy','cz','de','dj','dk','dm','do','dz','ec','ee','eg',
 'eh','er','es','et','eu','fi','fj','fk','fm','fo','fr','ga','gb','gd','ge','gf',
 'gg','gh','gi','gl','gm','gn','gp','gq','gr','gs','gt','gu','gw','gy','hk','hm',
 'hn','hr','ht','hu','id','ie','il','im','in','io','iq','ir','is','it','je','jm',
 'jo','jp','ke','kg','kh','ki','km','kn','kp','kr','kw','ky','kz','la','lb','lc',
 'li','lk','lr','ls','lt','lu','lv','ly','ma','mc','md','me','mg','mh','mk','ml',
 'mm','mn','mo','mp','mq','mr','ms','mt','mu','mv','mw','mx','my','mz','na','nc',
 'ne','nf','ng','ni','nl','no','np','nr','nu','nz','om','pa','pe','pf','pg','ph',
 'pk','pl','pm','pn','pr','ps','pt','pw','py','qa','re','ro','rs','ru','rw','sa',
 'sb','sc','sd','se','sg','sh','si','sj','sk','sl','sm','sn','so','sr','st','su',
 'sv','sy','sz','tc','td','tf','tg','th','tj','tk','tl','tm','tn','to','tp','tr',
 'tt','tv','tw','tz','ua','ug','uk','um','us','uy','uz','va','vc','ve','vg','vi',
 'vn','vu','wf','ws','ye','yt','yu','za','zm','zw' 
}

--- Convert two bytes into a 16bit number. 
--@param data String of data.
--@param idx Index in the string (first of two consecutive bytes).
--@return 16 bit number represented by the two bytes.
function bto16(data, idx)
	local b1 = string.byte(data, idx)
	local b2 = string.byte(data, idx+1)
	-- (b2 & 0xff) | ((b1 & 0xff) << 8)
	return bit.bor(bit.band(b2, 255), bit.lshift(bit.band(b1, 255), 8))
end

--- Check if domain name element is a tld
--@param elm Domain name element to check.
--@return boolean
function valid_tld(elm)
	for i,v in ipairs(tld) do
		if elm == v then return true end
	end
	return false
end

--- Parse an RFC 1035 domain name.
--@param data String of data.
--@param offset Offset in the string to read the domain name.
function parse_domain(data, offset)
	local i, x, record, line, ptr

	record = strbuf.new()
	x = string.byte(data, offset)
	ptr = bto16(data, offset)

	while not(x == 0) do 
		-- if the first two bits are '11' then the next 14 
		-- point to another location in the packet
		if(bit.band(ptr, 49152) == 49152) then
 			ptr, line = parse_domain(data, bit.band(ptr, 16383) + 3)
			record = record .. line
			offset = offset + 1
			break
		end

		-- RFC 1035 format name
		for i=0, x-1 do
			offset = offset + 1
			record = record .. string.char(string.byte(data, offset))
		end

		offset = offset + 1

		-- replace length byte with a period
		record = record .. '.'
		
		x = string.byte(data, offset)
		ptr = bto16(data, offset)
	end

	return offset+1, string.gsub(strbuf.dump(record), 0, '.')
end 

--- Build RFC 1035 root domain name from the name of the DNS server
--  (e.g ns1.website.com.ar -> \007website\003com\002ar\000).
--@param host The host.
function build_domain(host)
	local names, buf, x 
	local abs_name, i, tmp 

	buf = strbuf.new()
	abs_name = {}

	names = stdnse.strsplit('%.', host)
	if names == nil then names = {host} end
	
	-- try to determine root of domain name
	for i, x in ipairs(listop.reverse(names)) do
		table.insert(abs_name, x)
		if not valid_tld(x) then break end
	end
	
	i = 1
	abs_name = listop.reverse(abs_name)

	-- prepend each element with its length
	while i <= table.getn(abs_name) do
		buf = buf .. string.char(string.len(abs_name[i])) .. abs_name[i]
		i = i + 1
	end

	buf = buf .. '\000'
	return strbuf.dump(buf) 
end

--- Retrieve type specific data (rdata) from dns packets
function get_rdata(data, offset, ttype)
	local field, info, i

	info = strbuf.new()
	info = info .. ''

	if typetab[ttype] == nil then
		return offset, ''

	elseif typetab[ttype] == 'SOA' then
		-- name server
		offset, field = parse_domain(data, offset)	
		info = info .. field;
		-- mail box
		offset, field = parse_domain(data, offset)	
		info = info .. field;
		-- ignore other values
		offset = offset + 20 

	elseif typetab[ttype] == 'MX' then
		-- mail server
		offset = offset + 2
		offset, field = parse_domain(data, offset)
		info = info .. field

	elseif typetab[ttype] == 'A' then
		-- ip address
		info = info .. 
		string.byte(data, offset) .. '.' ..
		string.byte(data, offset+1) .. '.' ..
		string.byte(data, offset+2) .. '.' ..
		string.byte(data, offset+3)
		offset = offset + 4

	elseif typetab[ttype] == 'PTR' or
               typetab[ttype] == 'NS' then
		-- domain/domain server name
		offset, field = parse_domain(data, offset)	
		info = info .. field;
	end

	return offset, strbuf.dump(info, ' ')
end

--- Get a single answer record from the current offset
function get_answer_record(table, data, offset)
	local line, rdlen, ttype
	
	-- answer domain
	offset, line = parse_domain(data, offset)
	tab.add(table, 1, line)

	-- answer record type
	ttype = bto16(data, offset)
	if not(typetab[ttype] == nil) then
		tab.add(table, 2, typetab[ttype])
	end

	-- length of type specific data
	rdlen = bto16(data, offset+8)

	-- extra data, ignore ttl and class
	offset, line =  get_rdata(data, offset+10, ttype)
	if(line == '') then
		offset = offset + rdlen
	else
		tab.add(table, 3, line)
	end

	return offset, tab
end

function parse_records(number, data, table, offset)
	while number > 0 do
		offset = get_answer_record(table, data, offset)
		number = number - 1
		if number > 0 then tab.nextrow(table) end
	end
	return offset
end

function dump_zone_info(table, data, offset)
	local answers, line
	local questions, auth_answers, add_answers
	
	-- number of available records
	questions = bto16(data, offset+6)
	answers = bto16(data, offset+8)
	auth_answers = bto16(data, offset+10)
	add_answers = bto16(data, offset+12)

	-- move to beginning of first section
	offset = offset + 14

	if questions > 1 then
		return 'More then 1 question record, something has gone wrong'
	end

	if answers == 0 then
		return 'transfer successful but no records'
	end

	-- skip over the question section, we don't need it
	if questions == 1 then
		offset, line = parse_domain(data, offset)
		offset = offset + 4
	end
		
	-- parse all available resource records
	offset = parse_records(answers, data, table, offset)
	offset = parse_records(auth_answers, data, table, offset)
	offset = parse_records(add_answers, data, table, offset)
	return offset
end

action = function(host, port)
	local soc, status, data
	local catch = function() soc:close() end
	local try = nmap.new_try(catch)
	
	local domain = nil
	local args = nmap.registry.args

	if args.zoneTrans and args.zoneTrans.domain then
		domain = args.zoneTrans.domain
	elseif args.domain then
		domain = args.domain
	elseif host.targetname then
		domain = host.targetname
	elseif host.name ~= "" then
		domain = host.name
	else
		-- can't do anything without a hostname
		return
	end

	assert(domain)

	soc = nmap.new_socket()
	soc:set_timeout(4000)
	try(soc:connect(host.ip, port.number))

	local req_id = '\222\173'
	local table = tab.new(3)
	local offset = 1 
	local name = build_domain(string.lower(domain))
	local pkt_len = string.len(name) + 16

	-- build axfr request
	local buf = strbuf.new()
	buf = buf .. '\000' .. string.char(pkt_len) .. req_id 	
	buf = buf .. '\000\000\000\001\000\000\000\000\000\000'
	buf = buf .. name .. '\000\252\000\001'
	try(soc:send(strbuf.dump(buf)))

	-- read all data returned. Common to have 
	-- multiple packets from a single request
	local response = strbuf.new()
	while true do
		status, data = soc:receive_bytes(1)
		if not status then break end
		response = response .. data 
	end

	local response_str = strbuf.dump(response)
	local length = string.len(response_str)

	-- check server response code
	if length < 6 or 
           not (bit.band(string.byte(response_str, 6), 15) == 0) then
		return nil
	end

	-- parse zone information from all returned packets
	while(offset < length) do
		offset = dump_zone_info(table, response_str, offset)
	end

	soc:close()
	return ' \n' .. tab.dump(table)
end
