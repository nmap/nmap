description = [[
Requests a zone transfer (AXFR) from a DNS server.

The script sends an AXFR query to a DNS server. The domain to query is
determined by examining the name given on the command line, the DNS
server's hostname, or it can be specified with the
<code>dns-zone-transfer.domain</code> script argument. If the query is
successful all domains and domain types are returned along with common
type specific data (SOA/MX/NS/PTR/A).

This script can run at different phases of an Nmap scan:
* Script Pre-scanning: in this phase the script will run before any
Nmap scan and use the defined DNS server in the arguments. The script
arguments in this phase are: <code>dns-zone-transfer.server</code> the
DNS server to use, can be a hostname or an IP address and must be
specified. The <code>dns-zone-transfer.port</code> argument is optional
and can be used to specify the DNS server port.
* Script scanning: in this phase the script will run after the other
Nmap phases and against an Nmap discovered DNS server. If we don't
have the "true" hostname for the DNS server we cannot determine a
likely zone to perform the transfer on.

Useful resources
* DNS for rocket scientists: http://www.zytrax.com/books/dns/
* How the AXFR protocol works: http://cr.yp.to/djbdns/axfr-notes.html
]]

---
-- @args dns-zone-transfer.domain Domain to transfer.
-- @args dns-zone-transfer.server DNS server. If set, this argument will
--       enable the script for the "Script Pre-scanning phase".
-- @args dns-zone-transfer.port DNS server port, this argument concerns
--       the "Script Pre-scanning phase" and it's optional, the default
--       value is <code>53</code>.
-- @args newtargets  If specified, adds returned DNS records onto Nmap
--       scanning queue.
-- @args dns-zone-transfer.addall  If specified, adds all IP addresses
--       including private ones onto Nmap scanning queue when the
--       script argument <code>newtargets</code> is given. The default
--       behavior is to skip private IPs (non-routable).
-- @output
-- 53/tcp   open     domain
-- |  dns-zone-transfer:
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
-- @usage
-- nmap --script dns-zone-transfer.nse \
--      --script-args dns-zone-transfer.domain=<domain>

require('shortport')
require('strbuf')
require('stdnse')
require('listop')
require('bit')
require('tab')
require('dns')
require('target')
require('ipOps')

author = "Eddie Bell"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {'intrusive', 'discovery'}

-- DNS options
local dns_opts = {}

prerule = function()
  dns_opts.domain, dns_opts.server,
  dns_opts.port, dns_opts.addall = stdnse.get_script_args(
    {"dns-zone-transfer.domain", "dnszonetransfer.domain"},
    {"dns-zone-transfer.server", "dnszonetransfer.server"},
    {"dns-zone-transfer.port", "dnszonetransfer.port"},
    {"dns-zone-transfer.addall","dnszonetransfer.addall"}
  )

  if not dns_opts.domain then
    stdnse.print_debug(3,
        "Skipping '%s' %s, 'dnszonetransfer.domain' argument is missing.",
        SCRIPT_NAME, SCRIPT_TYPE)
    return false
  end

  if not dns_opts.server then
    stdnse.print_debug(3,
        "Skipping '%s' %s, 'dnszonetransfer.server' argument is missing.",
        SCRIPT_NAME, SCRIPT_TYPE)
    return false
  end

  return true
end

portrule = function(host, port)
  if shortport.portnumber(53, 'tcp')(host, port) then
    dns_opts.domain, dns_opts.addall = stdnse.get_script_args(
      {"dns-zone-transfer.domain", "dnszonetransfer.domain"},
      {"dns-zone-transfer.addall","dnszonetransfer.addall"}
    )

    if not dns_opts.domain then
      if host.targetname then
        dns_opts.domain = host.targetname
      elseif host.name ~= "" then
        dns_opts.domain = host.name
      else
        -- can't do anything without a hostname
        stdnse.print_debug(3,
            "Skipping '%s' %s, 'dnszonetransfer.domain' argument is missing.",
            SCRIPT_NAME, SCRIPT_TYPE)
        return false
      end
    end
    dns_opts.server = host.ip
    dns_opts.port = port.number
    return true
  end

  return false
end

--- DNS query and response types.
--@class table
--@name typetab
local typetab = { 'A', 'NS', 'MD', 'MF', 'CNAME', 'SOA', 'MB', 'MG', 'MR',
 'NULL', 'WKS', 'PTR', 'HINFO', 'MINFO', 'MX', 'TXT', 'RP', 'AFSDB', 'X25',
 'ISDN', 'RT', 'NSAP', 'NSAP-PTR', 'SIG', 'KEY', 'PX', 'GPOS', 'AAAA', 'LOC',
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
    local offset, domain = dns.decStr(data, offset)
    domain = domain or "<parse error>"
    return offset, domain
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
    while i <= #abs_name do
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

    elseif typetab[ttype] == 'PTR' or typetab[ttype] == 'NS' or
            typetab[ttype] == 'CNAME' then
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
    table.domain = line

    -- answer record type
    ttype = bto16(data, offset)
    if not(typetab[ttype] == nil) then
        table.ttype = typetab[ttype]
    end

    -- length of type specific data
    rdlen = bto16(data, offset+8)

    -- extra data, ignore ttl and class
    offset, line =  get_rdata(data, offset+10, ttype)
    if(line == '') then
        offset = offset + rdlen
        return false, offset
    else
        table.rdata = line
    end

    return true, offset
end

-- parse and save uniq records in the results table
function parse_uniq_records(results, record)
  if record.domain and not results['Node Names'][record.domain] then
    local str = string.gsub(record.domain, "^%s*(.-)%s*$", "%1")
    if not results['Node Names'][str] then
      results['Node Names'][str] = 1
    end
  end
  if record.ttype and record.rdata then
    if not results[record.ttype] then
      results[record.ttype] = {}
    end
    local str = string.gsub(record.rdata, "^%s*(.-)%s*$", "%1")
    if not results[record.ttype][str] then
      results[record.ttype][str] = 1
    end
  end
end

-- parse and save only valid records
function parse_records(number, data, results, offset)
    while number > 0 do
        local answer, st = {}
        st, offset = get_answer_record(answer, data, offset)
        if st then
          parse_uniq_records(results, answer)
        end
        number = number - 1
    end
    return offset
end

-- parse and save all records in order to dump them to output
function parse_records_table(number, data, table, offset)
    while number > 0 do
        local answer, st = {}
        st, offset = get_answer_record(answer, data, offset)
        if st then
            if answer.domain then
                tab.add(table, 1, answer.domain)
            end
            if answer.ttype then
                tab.add(table, 2, answer.ttype)
            end
            if answer.rdata then
                tab.add(table, 3, answer.rdata)
            end
            tab.nextrow(table)
        end
        number = number - 1
    end
    return offset
end

-- An iterator that breaks up a concatentation of responses. In DNS over TCP,
-- each response is prefixed by a two-byte length (RFC 1035 section 4.2.2).
-- Responses returned by this iterator include the two-byte length prefix.
function responses_iter(data)
    local offset = 1

    return function()
        local length, remaining, response

        remaining = string.len(data) - offset + 1
        if remaining == 0 then
            return nil
        end
        assert(remaining >= 14 + 2)
        length = bto16(data, offset)
        assert(length <= remaining)
        -- Skip over the length field.
        offset = offset + 2
        response = string.sub(data, offset, offset + length - 1)
        offset = offset + length
        return response
    end
end

-- add axfr results to Nmap scan queue
function add_zone_info(response)
  local RR = {}
  for data in responses_iter(response) do

    local offset, line = 1
    local questions = bto16(data, offset+4)
    local answers = bto16(data, offset+6)
    local auth_answers = bto16(data, offset+8)
    local add_answers = bto16(data, offset+10)

    -- move to beginning of first section
    offset = offset + 12

    if questions > 1 then
        return false, 'More then 1 question record, something has gone wrong'
    end

    if answers == 0 then
      return false, 'transfer successful but no records'
    end

    -- skip over the question section, we don't need it
    if questions == 1 then
      offset, line = parse_domain(data, offset)
      offset = offset + 4
    end

    -- parse all available resource records
    stdnse.print_debug(3,
        "Script %s: parsing ANCOUNT == %d, NSCOUNT == %d, ARCOUNT == %d",
        SCRIPT_NAME, answers, auth_answers, add_answers)
    RR['Node Names'] = {}
    offset = parse_records(answers, data, RR, offset)
    offset = parse_records(auth_answers, data, RR, offset)
    offset = parse_records(add_answers, data, RR, offset)
  end

  local outtab, nhosts = tab.new(), 0
  local newhosts_count, status, ret = 0, false

  tab.addrow(outtab, "Domains", "Added Targets")
  for rdata in pairs(RR['Node Names']) do
    status, ret = target.add(rdata)
    if not status then
      stdnse.print_debug(3, "Error: failed to add all Node Names.")
      break
    end
    newhosts_count = newhosts_count + ret
  end
  if newhosts_count == 0 then
    return false, ret and ret or "Error: failed to add DNS records."
  end
  tab.addrow(outtab, "Node Names", newhosts_count)
  nhosts = newhosts_count 

  tab.nextrow(outtab)

  tab.addrow(outtab, "DNS Records", "Added Targets")
  for rectype in pairs(RR) do
    newhosts_count = 0
    -- filter Private IPs
    if rectype == 'A' then
      for rdata in pairs(RR[rectype]) do
        if dns_opts.addall or not ipOps.isPrivate(rdata) then
          status, ret = target.add(rdata) 
          if not status then
            stdnse.print_debug(3,
                "Error: failed to add all 'A' records.")
            break
          end
          newhosts_count = newhosts_count + ret
        end
      end
    elseif rectype ~= 'Node Names' then
      for rdata in pairs(RR[rectype]) do
        status, ret = target.add(rdata)
        if not status then
          stdnse.print_debug(3,
              "Error: failed to add all '%s' records.", rectype)
          break
        end
        newhosts_count = newhosts_count + ret
      end
    end

    if newhosts_count ~= 0 then
      tab.addrow(outtab, rectype, newhosts_count)
      nhosts = nhosts + newhosts_count
    elseif nhosts == 0 then
      -- error: we can't add new targets
      return false, ret and ret or "Error: failed to add DNS records."
    end
  end

  -- error: no *valid records* or we can't add new targets
  if nhosts == 0 then
    return false, "Error: failed to add valid DNS records."
  end

  return true, tab.dump(outtab) .. "\n" ..
      string.format("Total new targets added to Nmap scan queue: %d.",
          nhosts)
end

function dump_zone_info(table, response)
  for data in responses_iter(response) do
    local offset, line = 1

    -- number of available records
    local questions = bto16(data, offset+4)
    local answers = bto16(data, offset+6)
    local auth_answers = bto16(data, offset+8)
    local add_answers = bto16(data, offset+10)

    -- move to beginning of first section
    offset = offset + 12

    if questions > 1 then
        return false, 'More then 1 question record, something has gone wrong'
    end

    if answers == 0 then
        return false, 'transfer successful but no records'
    end

    -- skip over the question section, we don't need it
    if questions == 1 then
        offset, line = parse_domain(data, offset)
        offset = offset + 4
    end

    -- parse all available resource records
    stdnse.print_debug(3,
        "Script %s: parsing ANCOUNT == %d, NSCOUNT == %d, ARCOUNT == %d",
        SCRIPT_NAME, answers, auth_answers, add_answers)
    offset = parse_records_table(answers, data, table, offset)
    offset = parse_records_table(auth_answers, data, table, offset)
    offset = parse_records_table(add_answers, data, table, offset)
  end

  return true
end

action = function(host, port)
    if not dns_opts.domain then
      return stdnse.format_output(false,
                string.format("'%s' script needs a dnszonetransfer.domain argument.",
                    SCRIPT_TYPE))
    end
    if not dns_opts.port then
        dns_opts.port = 53
    end

    local soc = nmap.new_socket()
    local catch = function() soc:close() end
    local try = nmap.new_try(catch)
    soc:set_timeout(4000)
    try(soc:connect(dns_opts.server, dns_opts.port))

    local req_id = '\222\173'
    local offset = 1
    local name = build_domain(string.lower(dns_opts.domain))
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
        local status, data = soc:receive_bytes(1)
        if not status then break end
        response = response .. data
    end
    soc:close()

    local response_str = strbuf.dump(response)
    local length = string.len(response_str)

    -- check server response code
    if length < 6 or
            not (bit.band(string.byte(response_str, 6), 15) == 0) then
        return nil
    end

    -- add axfr results to Nmap scanning queue
    if target.ALLOW_NEW_TARGETS then
        local status, ret = add_zone_info(response_str)
        if not status then
            return stdnse.format_output(false, ret)
        end
        return stdnse.format_output(true, ret)
    -- dump axfr results
    else
        local table = tab.new()
        local status, ret = dump_zone_info(table, response_str)
        if not status then
            return stdnse.format_output(false, ret)
        end
        return '\n' .. tab.dump(table)
    end
end
