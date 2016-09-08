local bin = require "bin"
local bit = require "bit"
local dns = require "dns"
local ipOps = require "ipOps"
local listop = require "listop"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local strbuf = require "strbuf"
local string = require "string"
local tab = require "tab"
local table = require "table"
local target = require "target"

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


author = "Eddie Bell"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
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
    stdnse.debug3("Skipping '%s' %s, 'dnszonetransfer.domain' argument is missing.", SCRIPT_NAME, SCRIPT_TYPE)
    return false
  end

  if not dns_opts.server then
    stdnse.debug3("Skipping '%s' %s, 'dnszonetransfer.server' argument is missing.", SCRIPT_NAME, SCRIPT_TYPE)
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
        stdnse.debug3("Skipping '%s' %s, 'dnszonetransfer.domain' argument is missing.", SCRIPT_NAME, SCRIPT_TYPE)
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
  'SINK', 'OPT', 'APL', 'DS', 'SSHFP', 'IPSECKEY', 'RRSIG', 'NSEC', 'DNSKEY',
  'DHCID', 'NSEC3', 'NSEC3PARAM', 'TLSA', [55]='HIP', [56]='NINFO', [57]='RKEY',
  [58]='TALINK', [59]='CDS', [99]='SPF', [100]='UINFO', [101]='UID', [102]='GID',
  [103]='UNSPEC', [249]='TKEY', [250]='TSIG', [251]='IXFR', [252]='AXFR',
  [253]='MAILB', [254]='MAILA', [255]='ANY', [256]='ZXFR', [257]='CAA',
  [32768]='TA', [32769]='DLV',
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
  return (">I2"):unpack(data, idx)
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
  return offset, string.format("%s.", domain)
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
    buf = buf .. string.char(#abs_name[i]) .. abs_name[i]
    i = i + 1
  end

  buf = buf .. '\000'
  return strbuf.dump(buf)
end

local function parse_num_domain(data, offset)
  local number, domain
  number = bto16(data, offset)
  offset, domain = parse_domain(data, offset+2)
  return offset, string.format("%d %s", number, domain)
end

local function parse_txt(data, offset)
  local field, len
  len = string.byte(data, offset)
  offset = offset + 1
  offset, field = bin.unpack("A" .. len, data, offset)
  return offset, string.format('"%s"', field)
end

--- Retrieve type specific data (rdata) from dns packets
local RD = {
  A = function(data, offset)
    return offset+4, ipOps.str_to_ip(data:sub(offset, offset+3))
  end,
  NS = parse_domain,
  MD = parse_domain, -- obsolete per rfc1035, use MX
  MF = parse_domain, -- obsolete per rfc1035, use MX
  CNAME = parse_domain,
  SOA = function(data, offset)
    local field, info
    info = strbuf.new()
    -- name server
    offset, field = parse_domain(data, offset)
    info = info .. field;
    -- mail box
    offset, field = parse_domain(data, offset)
    info = info .. field;
    -- ignore other values
    offset = offset + 20
    return offset, strbuf.dump(info, ' ')
  end,
  MB = parse_domain, -- experimental per RFC 1035
  MG = parse_domain, -- experimental per RFC 1035
  MR = parse_domain, -- experimental per RFC 1035
  --NULL -- RFC 1035 says anything can go in this field. Hex dump is good.
  WKS = function(data, offset)
    local len, ip, proto, svcs
    len = bto16(data, offset-2) - 5 -- length of bit field
    ip = ipOps.str_to_ip(data:sub(offset, offset+3))
    proto = string.byte(data, offset+4)
    offset = offset + 5
    svcs = {}
    local p = 0
    local bits = {128, 64, 32, 16, 8, 4, 2, 1}
    for i=0, len-1 do
      local n = string.byte(data, offset + i)
      for _, v in ipairs(bits) do
        if bit.band(v, n) > 0 then table.insert(svcs, p) end
        p = p + 1
      end
    end
    if proto == 6 then
      proto = "TCP"
    elseif proto == 17 then
      proto = "UDP"
    end
    return offset + len, string.format("%s %s %s", ip, proto, table.concat(svcs, " "))
  end,
  PTR = parse_domain,
  HINFO = function(data, offset)
    local cpu, os -- See RFC 1010 for standard values for these
    offset, cpu = parse_txt(data, offset)
    offset, os = parse_txt(data, offset)
    return offset, string.format("%s %s", cpu, os)
  end,
  MINFO = function(data, offset)
    local rmailbx, emailbx
    offset, rmailbx = parse_domain(data, offset)
    offset, emailbx = parse_domain(data, offset)
    return offset, string.format("%s %s", rmailbx, emailbx)
  end,
  MX = parse_num_domain,
  TXT = parse_txt,
  RP = function(data, offset)
    local mbox_dname, txt_dname
    offset, mbox_dname = parse_domain(data, offset)
    offset, txt_dname = parse_domain(data, offset)
    return offset, string.format("%s %s", mbox_dname, txt_dname)
  end,
  AFSDB = parse_num_domain,
  X25 = parse_txt,
  ISDN = function(data, offset)
    local addr, sa
    offset, addr = parse_txt(data, offset)
    offset, sa = parse_txt(data, offset)
    return offset, string.format("%s %s", addr, sa)
  end,
  RT = parse_num_domain,
  NSAP = function(data, offset)
    local field
    offset, field = bin.unpack("A" .. bto16(data, offset-2), data, offset)
    return offset, ("0x%s"):format(stdnse.tohex(field))
  end,
  ["NSAP-PTR"] = parse_domain,
  --SIG KEY --obsolete RRs relating to DNSSEC
  PX = function(data, offset)
    local preference, map822, mapx400
    preference = bto16(data, offset)
    offset, map822 = parse_domain(data, offset+2)
    offset, mapx400 = parse_domain(data, offset)
    return offset, string.format("%d %s %s", preference, map822, mapx400)
  end,
  GPOS = function(data, offset)
    local lat, long, alt
    offset, lat = parse_txt(data, offset)
    offset, long = parse_txt(data, offset)
    offset, alt = parse_txt(data, offset)
    return offset, string.format("%s %s %s", lat, long, alt)
  end,
  AAAA = function(data, offset)
    return offset+16, ipOps.str_to_ip(data:sub(offset, offset+15))
  end,
  LOC = function(data, offset)
    local version, siz, hp, vp, lat, lon, alt
    version = string.byte(data, offset)
    if version ~= 0 then
      stdnse.debug2("Unknown LOC RR version: %d", version)
      return offset, ''
    end
    siz = string.byte(data, offset+1)
    siz = bit.rshift(siz,4) * 10 ^ bit.band(siz, 0x0f) / 100
    hp = string.byte(data, offset+2)
    hp = bit.rshift(hp,4) * 10 ^ bit.band(hp, 0x0f) / 100
    vp = string.byte(data, offset+3)
    vp = bit.rshift(vp,4) * 10 ^ bit.band(vp, 0x0f) / 100
    offset = offset + 4
    offset, lat, lon, alt = bin.unpack(">III", data, offset)
    lat = (lat-2^31)/3600000 --degrees
    local latd = 'N'
    if lat < 0 then
      latd = 'S'
      lat = 0-lat
    end
    lon = (lon-2^31)/3600000 --degrees
    local lond = 'E'
    if lon < 0 then
      lond = 'W'
      lon = 0-lon
    end
    return offset, string.format("%f %s %f %s %dm %0.1fm %0.1fm %0.1fm",
      lat, latd, lon, lond, alt/100 - 100000, siz, hp, vp)
  end,
  --NXT --obsolete RR relating to DNSSEC
  --EID NIMLOC --related to Nimrod DARPA project (Patton1995)
  SRV = function(data, offset)
    local priority, weight, port, info
    offset, priority, weight, port = bin.unpack(">SSS", data, offset)
    offset, info = parse_domain(data, offset)
    return offset, string.format("%d %d %d %s", priority, weight, port, info)
  end,
  ATMA = function(data, offset) --http://www.broadband-forum.org/ftp/pub/approved-specs/af-saa-0069.000.pdf
    local format, address
    format = string.byte(data, offset) -- 0 or 1
    offset, address = parse_txt(data, offset+1)
    return offset, string.format("%d %s", format, address)
  end,
  NAPTR = function(data, offset)
    local order, preference, flags, service, regexp, replacement
    order = bto16(data, offset)
    preference = bto16(data, offset+2)
    offset, flags = parse_txt(data, offset+4)
    offset, service = parse_txt(data, offset)
    offset, regexp = parse_txt(data, offset)
    offset, replacement = parse_domain(data, offset)
    return offset, string.format('%d %d %s %s %s %s',
      order, preference, flags, service, regexp, replacement)
  end,
  KX = parse_num_domain,
  --CERT
  A6 = function(data, offset) -- obsoleted by AAAA
    local prefix, addr, name
    prefix = string.byte(data, offset)
    local pbytes = bit.rshift(prefix,3)
    addr = ipOps.str_to_ip(string.rep("\000", pbytes) .. data:sub(offset+1, 16-pbytes))
    offset, name = parse_domain(data, offset + 17 - pbytes)
    return offset, string.format("%d %s %s", prefix, addr, name)
  end,
  DNAME = parse_domain,
  SINK = function(data, offset) -- http://bgp.potaroo.net/ietf/all-ids/draft-eastlake-kitchen-sink-02.txt
    local coding, subcoding, field
    coding = string.byte(data, offset)
    subcoding = string.byte(data, offset+1)
    offset, field = bin.unpack("A" .. (bto16(data, offset-2)-2), data, offset+2)
    return offset, string.format("%d %d %s", coding, subcoding, stdnse.tohex(field))
  end,
  --OPT APL DS
  SSHFP = function(data, offset)
    local algorithm, fptype, fplen, fingerprint
    algorithm = string.byte(data, offset)
    fptype = string.byte(data, offset+1)
    fplen = bto16(data, offset-2) - 2
    offset = offset + 2
    fingerprint = stdnse.tohex(data:sub(offset, offset+fplen-1))
    return offset + fplen, string.format("%d %d %s", algorithm, fptype, fingerprint)
  end,
  --IPSECKEY RRSIG NSEC DNSKEY DHCID NSEC3 NSEC3PARAM
  TLSA = function(data, offset) -- https://tools.ietf.org/html/rfc6698
    local rdatalen, cert_usage, selector, match_type, offset = (">I2BBB"):unpack(data, offset-2)
    local usages = {[0] = "PKIX-TA", [1] = "PKIX-EE", [2] = "DANE-TA", [3] = "DANE-EE", [255] = "PrivCert"}
    cert_usage = usages[cert_usage] or cert_usage
    local selectors = {[0] = "Cert", [1] = "SPKI", [255] = "PrivSel"}
    selector = selectors[selector] or selector
    local matches = {[0] = "Full", [1] = "SHA2-256", [2] = "SHA2-512", [255] = "PrivMatch"}
    match_type = matches[match_type] or match_type
    local offend = offset + rdatalen - 3
    local assoc_data = stdnse.tohex(data:sub(offset, offend - 1))
    return offend, string.format("%s %s %s %s", cert_usage, selector, match_type, assoc_data)
  end,
  --HIP NINFO RKEY TALINK CDS
  SPF = parse_txt,
  --UINFO UID GID UNSPEC TKEY TSIG IXFR AXFR
}

function get_rdata(data, offset, ttype)
  if typetab[ttype] == nil then
    return offset, ''
  elseif RD[typetab[ttype]] then
    return RD[typetab[ttype]](data, offset)
  else
    local field
    offset, field = bin.unpack("A" .. bto16(data, offset-2), data, offset)
    return offset, ("hex: %s"):format(stdnse.tohex(field))
  end
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

-- An iterator that breaks up a concatenation of responses. In DNS over TCP,
-- each response is prefixed by a two-byte length (RFC 1035 section 4.2.2).
-- Responses returned by this iterator include the two-byte length prefix.
function responses_iter(data)
  local offset = 1

  return function()
    local length, remaining, response

    remaining = #data - offset + 1
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
    stdnse.debug3("Script %s: parsing ANCOUNT == %d, NSCOUNT == %d, ARCOUNT == %d", answers, auth_answers, add_answers)
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
      stdnse.debug3("Error: failed to add all Node Names.")
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
            stdnse.debug3("Error: failed to add all 'A' records.")
            break
          end
          newhosts_count = newhosts_count + ret
        end
      end
    elseif rectype ~= 'Node Names' then
      for rdata in pairs(RR[rectype]) do
        status, ret = target.add(rdata)
        if not status then
          stdnse.debug3("Error: failed to add all '%s' records.", rectype)
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
    stdnse.debug3("parsing ANCOUNT == %d, NSCOUNT == %d, ARCOUNT == %d", answers, auth_answers, add_answers)
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
  local pkt_len = #name + 16

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
  local length = #response_str

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
