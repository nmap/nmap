---
-- Simple DNS library supporting packet creation, encoding, decoding,
-- and querying.
--
-- The most common interface to this module are the <code>query</code> and
-- <code>reverse</code> functions. <code>query</code> performs a DNS query,
-- and <code>reverse</code> prepares an ip address to have a reverse query
-- performed.
--
-- <code>query</code> takes two options - a domain name to look up and an
-- optional table of options. For more information on the options table,
-- see the documentation for <code>query</code>.
--
-- Example usage:
-- <code>
--  -- After this call, <code>status</code> is <code>true</code> and <code>result</code> is <code>"72.14.204.104"</code>
--  local status, result = dns.query('www.google.ca')
--
--  -- After this call, <code>status</code> is <code>false</code> and <code>result</code> is <code>"No such name"</code>
--  local status, result = dns.query('www.google.abc')
--
--  -- After this call, <code>status</code> is <code>true</code> and <code>result</code> is the table <code>{"72.14.204.103", "72.14.204.104", "72.14.204.147", "72.14.204.99"}</code>
--  local status, result = dns.query('www.google.ca', {retAll=true})
--
--  -- After this call, <code>status</code> is <code>true</code> and <code>result</code> is the <code>"2001:19f0:0:0:0:dead:beef:cafe"</code>
--  local status, result = dns.query('irc.ipv6.efnet.org', {dtype='AAAA'})
--</code>
--
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html


local coroutine = require "coroutine"
local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local stringaux = require "stringaux"
local table = require "table"
local base32 = require "base32"
local unittest = require "unittest"
_ENV = stdnse.module("dns", stdnse.seeall)

get_servers = nmap.get_dns_servers

---
-- Table of DNS resource types.
-- @name types
-- @class table
types = {
  A = 1,
  NS = 2,
  SOA = 6,
  CNAME = 5,
  PTR = 12,
  HINFO = 13,
  MX = 15,
  TXT = 16,
  AAAA = 28,
  SRV = 33,
  OPT = 41,
  SSHFP = 44,
  NSEC = 47,
  NSEC3 = 50,
  AXFR = 252,
  ANY = 255
}

CLASS = {
  IN = 1,
  CH = 3,
  ANY = 255
}


---
-- Repeatedly sends UDP packets to host, waiting for an answer.
-- @param data Data to be sent.
-- @param host Host to connect to.
-- @param port Port to connect to.
-- @param timeout Number of ms to wait for a response.
-- @param cnt Number of tries.
-- @param multiple If true, keep reading multiple responses until timeout.
-- @return Status (true or false).
-- @return Response (if status is true).
local function sendPacketsUDP(data, host, port, timeout, cnt, multiple)
  local socket = nmap.new_socket("udp")
  local responses = {}

  socket:set_timeout(timeout)

  if ( not(multiple) ) then
    socket:connect( host, port, "udp" )
  end

  for i = 1, cnt do
    local status, err

    if ( multiple ) then
      status, err = socket:sendto(host, port, data)
    else
      status, err = socket:send(data)
    end

    if (not(status)) then return false, err end

    local response

    if ( multiple ) then
      while(true) do
        status, response = socket:receive()
        if( not(status) ) then break end

        local status, _, _, ip, _ = socket:get_info()
        table.insert(responses, { data = response, peer = ip } )
      end
    else
      status, response = socket:receive()
      if ( status ) then
        local status, _, _, ip, _ = socket:get_info()
        table.insert(responses, { data = response, peer = ip } )
      end
    end

    if (#responses>0) then
      socket:close()
      return true, responses
    end
  end
  socket:close()
  return false
end

---
-- Send TCP DNS query
-- @param data Data to be sent.
-- @param host Host to connect to.
-- @param port Port to connect to.
-- @param timeout Number of ms to wait for a response.
-- @return Status (true or false).
-- @return Response (if status is true).
local function sendPacketsTCP(data, host, port, timeout)
  local socket = nmap.new_socket()
  local response
  local responses = {}
  socket:set_timeout(timeout)
  socket:connect(host, port)
  -- add payload size we are assuming a minimum size here of 256?
  local send_data = '\000' .. string.char(#data) .. data
  socket:send(send_data)
  local response = ''
  local got_response = false
  while true do
    local status, recv_data = socket:receive_bytes(1)
    if not status then break end
    got_response = true
    response = response .. recv_data
  end
  local status, _, _, ip, _ = socket:get_info()
  socket:close()
  if not got_response then
    return false
  end
  -- remove payload size
  table.insert(responses, { data = string.sub(response,3), peer = ip } )
  return true, responses
end

---
-- Call appropriate protocol handler
-- @param data Data to be sent.
-- @param host Host to connect to.
-- @param port Port to connect to.
-- @param timeout Number of ms to wait for a response.
-- @param cnt Number of tries.
-- @param multiple If true, keep reading multiple responses until timeout.
-- @return Status (true or false).
local function sendPackets(data, host, port, timeout, cnt, multiple, proto)
  if proto == nil or proto == 'udp' then
    return sendPacketsUDP(data, host, port, timeout, cnt, multiple)
  else
    return sendPacketsTCP(data, host, port, timeout)
  end
end

---
-- Checks if a DNS response packet contains a useful answer.
-- @param rPkt Decoded DNS response packet.
-- @return True if useful, false if not.
local function gotAnswer(rPkt)
  -- have we even got answers?
  if #rPkt.answers > 0 then

    -- some MDNS implementation incorrectly return an empty question section
    -- if this is the case return true
    if rPkt.questions[1] == nil then
      return true
    end

    -- are those answers not just cnames?
    if rPkt.questions[1].dtype == types.A then
      for _, v in ipairs(rPkt.answers) do
        -- if at least one answer is an A record, it's an answer
        if v.dtype == types.A then
          return true
        end
      end
      -- if none was an A record, it's not really an answer
      return false
    else -- there was no A request, CNAMEs are not of interest
      return true
    end
    -- no such name is the answer
  elseif rPkt.flags.RC3 and rPkt.flags.RC4 then
    return true
    -- really no answer
  else
    return false
  end
end


---
-- Tries to find the next nameserver with authority to get a result for
-- query.
-- @param rPkt Decoded DNS response packet
-- @return String or table of next server(s) to query, or false.
local function getAuthDns(rPkt)
  if #rPkt.auth == 0 then
    if #rPkt.answers == 0 then
      return false
    else
      if rPkt.answers[1].dtype == types.CNAME then
        return {cname = rPkt.answers[1].domain}
      end
    end
  end
  if rPkt.auth[1].dtype == types.NS then
    if #rPkt.add > 0 then
      local hosts = {}
      for _, v in ipairs(rPkt.add) do
        if v.dtype == types.A then
          table.insert(hosts, v.ip)
        end
      end
      if #hosts > 0 then return hosts end
    end
    local status, next = query(rPkt.auth[1].domain, {dtype = "A" })
    return next
  end
  return false
end

local function processResponse( response, dname, dtype, options )

  local rPkt = decode(response)
  -- is it a real answer?
  if gotAnswer(rPkt) then
    if (options.retPkt) then
      return true, rPkt
    else
      return findNiceAnswer(dtype, rPkt, options.retAll)
    end
  elseif ( not(options.noauth) ) then -- if not, ask the next server in authority

    local next_server = getAuthDns(rPkt)

    -- if we got a CNAME, ask for the CNAME
    if type(next_server) == 'table' and next_server.cname then
      options.tries = options.tries - 1
      return query(next_server.cname, options)
    end

    -- only ask next server in authority, if
    -- we got an auth dns and
    -- it isn't the one we just asked
    if next_server and next_server ~= options.host and options.tries > 1 then
      options.host = next_server
      options.tries = options.tries - 1
      return query(dname, options)
    end
  elseif ( options.retPkt ) then
    return true, rPkt
  end

  -- nothing worked
  stdnse.debug1("dns.query() failed to resolve the requested query%s%s", dname and ": " or ".", dname or "")
  return false, "No Answers"

end

---
-- Query DNS servers for a DNS record.
-- @param dname Desired domain name entry.
-- @param options A table containing any of the following fields:
-- * <code>dtype</code>: Desired DNS record type (default: <code>"A"</code>).
-- * <code>host</code>: DNS server to be queried (default: DNS servers known to Nmap).
-- * <code>port</code>: Port of DNS server to connect to (default: <code>53</code>).
-- * <code>tries</code>: How often should <code>query</code> try to contact another server (for non-recursive queries).
-- * <code>retAll</code>: Return all answers, not just the first.
-- * <code>retPkt</code>: Return the packet instead of using the answer-fetching mechanism.
-- * <code>norecurse</code>: If true, do not set the recursion (RD) flag.
-- * <code>noauth</code>: If true, do not try to find authoritative server
-- * <code>multiple</code>: If true, expects multiple hosts to respond to multicast request
-- * <code>flags</code>: numeric value to set flags in the DNS query to a specific value
-- * <code>id</code>: numeric value to use for the DNS transaction id
-- * <code>nsid</code>: If true, queries the server for the nameserver identifier (RFC 5001)
-- * <code>subnet</code>: table, if set perform a edns-client-subnet lookup. The table should contain the fields:
--                        <code>family</code> - IPv4: "inet" or 1 (default), IPv6: "inet6" or 2
--                        <code>address</code> - string containing the originating subnet IP address
--                        <code>mask</code> - number containing the number of subnet bits
-- @return <code>true</code> if a dns response was received and contained an answer of the requested type,
--  or the decoded dns response was requested (retPkt) and is being returned - or <code>false</code> otherwise.
-- @return String answer of the requested type, table of answers or a String error message of one of the following:
--  "No Such Name", "No Servers", "No Answers", "Unable to handle response"
function query(dname, options)
  if not options then options = {} end

  local dtype, host, port, proto = options.dtype, options.host, options.port, options.proto
  if proto == nil then proto = 'udp' end
  if port == nil then port = '53' end

  local class = options.class or CLASS.IN
  if not options.tries then options.tries = 10 end -- don't get into an infinite loop

  if not options.sendCount then options.sendCount = 2 end

  if type( options.timeout ) ~= "number" then options.timeout = get_default_timeout() end

  if type(dtype) == "string" then
    dtype = types[dtype]
  end
  if not dtype then dtype = types.A end

  local srv
  local srvI = 1
  if not port then port = 53 end
  if not host then
    srv = get_servers()
    if srv and srv[1] then
      host = srv[1]
    else
      return false, "No Servers"
    end
  elseif type(host) == "table" then
    srv = host
    host = srv[1]
  end

  local pkt = newPacket()
  addQuestion(pkt, dname, dtype, class)
  if options.norecurse then pkt.flags.RD = false end

  local dnssec = {}
  if ( options.dnssec ) then
    dnssec = { DO = true }
  end

  if ( options.nsid ) then
    addNSID(pkt, dnssec)
  elseif ( options.subnet ) then
    addClientSubnet(pkt, dnssec, options.subnet )
  elseif ( dnssec.DO ) then
    addOPT(pkt, {DO = true})
  end

  if ( options.flags ) then pkt.flags.raw = options.flags end
  if ( options.id ) then pkt.id = options.id end

  local data = encode(pkt)

  local status, response = sendPackets(data, host, port, options.timeout, options.sendCount, options.multiple, proto)


  -- if working with know nameservers, try the others
  while((not status) and srv and srvI < #srv) do
    srvI = srvI + 1
    host = srv[srvI]
    status, response = sendPackets(data, host, port, options.timeout, options.sendCount)
  end

  -- if we got any response:
  if status then
    if ( options.multiple ) then
      local multiresponse = {}
      for _, r in ipairs( response ) do
        local status, presponse = processResponse( r.data, dname, dtype, options )
        if( status ) then
          table.insert( multiresponse, { ['output']=presponse, ['peer']=r.peer } )
        end
      end
      return true, multiresponse
    else
      return processResponse( response[1].data, dname, dtype, options)
    end
  else
    stdnse.debug1("dns.query() got zero responses attempting to resolve query%s%s", dname and ": " or ".", dname or "")
    return false, "No Answers"
  end
end


---
-- Formats an IP address for reverse lookup.
-- @param ip IP address string.
-- @return "Domain"-style representation of IP as subdomain of in-addr.arpa or
-- ip6.arpa.
function reverse(ip)
  ip = ipOps.expand_ip(ip)
  if type(ip) ~= "string" then return nil end
  local delim = "%."
  local arpa = ".in-addr.arpa"
  if ip:match(":") then
    delim = ":"
    arpa = ".ip6.arpa"
  end
  local ipParts = stringaux.strsplit(delim, ip)
  if #ipParts == 8 then
    -- padding
    local mask = "0000"
    for i, part in ipairs(ipParts) do
      ipParts[i] = mask:sub(1, #mask - #part) .. part
    end
    -- 32 parts from 8
    local temp = {}
    for i, hdt in ipairs(ipParts) do
      for part in hdt:gmatch("%x") do
        temp[#temp+1] = part
      end
    end
    ipParts = temp
  end
  local ipReverse = {}
  for i = #ipParts, 1, -1 do
    table.insert(ipReverse, ipParts[i])
  end
  return table.concat(ipReverse, ".") .. arpa
end

-- Table for answer fetching functions.
local answerFetcher = {}

-- Answer fetcher for TXT records.
-- @param dec Decoded DNS response.
-- @param retAll If true, return all entries, not just the first.
-- @return True if one or more answers of the required type were found - otherwise false.
-- @return String first dns TXT record or Table of TXT records or String Error message.
answerFetcher[types.TXT] = function(dec, retAll)
  local answers = {}
  if not retAll and dec.answers[1].data then
    return true, string.sub(dec.answers[1].data, 2)
  elseif not retAll then
    stdnse.debug1("dns.answerFetcher found no records of the required type: TXT")
    return false, "No Answers"
  else
    for _, v in ipairs(dec.answers) do
      if v.TXT and v.TXT.text then
        for _, v in ipairs( v.TXT.text ) do
          table.insert(answers, v)
        end
      end
    end
  end
  if #answers == 0 then
    stdnse.debug1("dns.answerFetcher found no records of the required type: TXT")
    return false, "No Answers"
  end
  return true, answers
end

-- Answer fetcher for A records
-- @param dec Decoded DNS response.
-- @param retAll If true, return all entries, not just the first.
-- @return True if one or more answers of the required type were found - otherwise false.
-- @return String first dns A record or Table of A records or String Error message.
answerFetcher[types.A] = function(dec, retAll)
  local answers = {}
  for _, ans in ipairs(dec.answers) do
    if ans.dtype == types.A then
      if not retAll then
        return true, ans.ip
      end
      table.insert(answers, ans.ip)
    end
  end
  if not retAll or #answers == 0 then
    stdnse.debug1("dns.answerFetcher found no records of the required type: A")
    return false, "No Answers"
  end
  return true, answers
end


-- Answer fetcher for CNAME records.
-- @param dec Decoded DNS response.
-- @param retAll If true, return all entries, not just the first.
-- @return True if one or more answers of the required type were found - otherwise false.
-- @return String first Domain entry or Table of domain entries or String Error message.
answerFetcher[types.CNAME] = function(dec, retAll)
  local answers = {}
  if not retAll and dec.answers[1].domain then
    return true, dec.answers[1].domain
  elseif not retAll then
    stdnse.debug1("dns.answerFetcher found no records of the required type: NS, PTR or CNAME")
    return false, "No Answers"
  else
    for _, v in ipairs(dec.answers) do
      if v.domain then table.insert(answers, v.domain) end
    end
  end
  if #answers == 0 then
    stdnse.debug1("dns.answerFetcher found no records of the required type: NS, PTR or CNAME")
    return false, "No Answers"
  end
  return true, answers
end

-- Answer fetcher for MX records.
-- @param dec Decoded DNS response.
-- @param retAll If true, return all entries, not just the first.
-- @return True if one or more answers of the required type were found - otherwise false.
-- @return String first dns MX record or Table of MX records or String Error message.
--  Note that the format of a returned MX answer is "preference:hostname:IPaddress" where zero
--  or more IP addresses may be present.
answerFetcher[types.MX] = function(dec, retAll)
  local mx, ip, answers = {}, {}, {}
  for _, ans in ipairs(dec.answers) do
    if ans.MX then mx[#mx+1] = ans.MX end
    if not retAll then break end
  end
  if #mx == 0 then
    stdnse.debug1("dns.answerFetcher found no records of the required type: MX")
    return false, "No Answers"
  end
  for _, add in ipairs(dec.add) do
    if ip[add.dname] then table.insert(ip[add.dname], add.ip)
    else ip[add.dname] = {add.ip} end
  end
  for _, mxrec in ipairs(mx) do
    if ip[mxrec.server] then
      table.insert( answers, ("%s:%s:%s"):format(mxrec.pref or "-", mxrec.server or "-", table.concat(ip[mxrec.server], ":")) )
      if not retAll then return true, answers[1] end
    else
      -- no IP ?
      table.insert( answers, ("%s:%s"):format(mxrec.pref or "-", mxrec.server or "-") )
      if not retAll then return true, answers[1] end
    end
  end
  return true, answers
end

-- Answer fetcher for SRV records.
-- @param dec Decoded DNS response.
-- @param retAll If true, return all entries, not just the first.
-- @return True if one or more answers of the required type were found - otherwise false.
-- @return String first dns SRV record or Table of SRV records or String Error message.
--  Note that the format of a returned SRV answer is "priority:weight:port:target" where zero
--  or more IP addresses may be present.
answerFetcher[types.SRV] = function(dec, retAll)
  local srv, ip, answers = {}, {}, {}
  for _, ans in ipairs(dec.answers) do
    if ans.dtype == types.SRV then
      if not retAll then
        return true, ("%s:%s:%s:%s"):format( ans.SRV.prio, ans.SRV.weight, ans.SRV.port, ans.SRV.target )
      end
      table.insert( answers, ("%s:%s:%s:%s"):format( ans.SRV.prio, ans.SRV.weight, ans.SRV.port, ans.SRV.target ) )
    end
  end
  if #answers == 0 then
    stdnse.debug1("dns.answerFetcher found no records of the required type: SRV")
    return false, "No Answers"
  end

  return true, answers
end

-- Answer fetcher for NSEC records.
-- @param dec Decoded DNS response.
-- @param retAll If true, return all entries, not just the first.
-- @return True if one or more answers of the required type were found - otherwise false.
-- @return String first dns NSEC record or Table of NSEC records or String Error message.
--  Note that the format of a returned NSEC answer is "name:dname:types".
answerFetcher[types.NSEC] = function(dec, retAll)
  local nsec, answers = {}, {}
  for _, auth in ipairs(dec.auth) do
    if auth.NSEC then nsec[#nsec+1] = auth.NSEC end
    if not retAll then break end
  end
  if #nsec == 0 then
    stdnse.debug1("dns.answerFetcher found no records of the required type: NSEC")
    return false, "No Answers"
  end
  for _, nsecrec in ipairs(nsec) do
    table.insert( answers, ("%s:%s:%s"):format(nsecrec.name or "-", nsecrec.dname or "-", table.concat(nsecrec.types, ":") or "-"))
  end
  if not retAll then return true, answers[1] end
  return true, answers
end

-- Answer fetcher for NS records.
-- @name answerFetcher[types.NS]
-- @class function
-- @param dec Decoded DNS response.
-- @return True if one or more answers of the required type were found - otherwise false.
-- @return String first Domain entry or Table of domain entries or String Error message.
answerFetcher[types.NS] = answerFetcher[types.CNAME]

-- Answer fetcher for PTR records.
-- @name answerFetcher[types.PTR]
-- @class function
-- @param dec Decoded DNS response.
-- @param retAll If true, return all entries, not just the first.
-- @return True if one or more answers of the required type were found - otherwise false.
-- @return String first Domain entry or Table of domain entries or String Error message.
answerFetcher[types.PTR] = answerFetcher[types.CNAME]

-- Answer fetcher for AAAA records.
-- @param dec Decoded DNS response.
-- @param retAll If true, return all entries, not just the first.
-- @return True if one or more answers of the required type were found - otherwise false.
-- @return String first dns AAAA record or Table of AAAA records or String Error message.
answerFetcher[types.AAAA] = function(dec, retAll)
  local answers = {}
  for _, ans in ipairs(dec.answers) do
    if ans.dtype == types.AAAA then
      if not retAll then
        return true, ans.ipv6
      end
      table.insert(answers, ans.ipv6)
    end
  end
  if not retAll or #answers == 0 then
    stdnse.debug1("dns.answerFetcher found no records of the required type: AAAA")
    return false, "No Answers"
  end
  return true, answers
end


---Calls the answer fetcher for <code>dtype</code> or returns an error code in
-- case of a "no such name" error.
--
-- @param dtype DNS resource record type.
-- @param dec Decoded DNS response.
-- @param retAll If true, return all entries, not just the first.
-- @return True if one or more answers of the required type were found - otherwise false.
-- @return Answer according to the answer fetcher for <code>dtype</code> or an Error message.
function findNiceAnswer(dtype, dec, retAll)
  if (#dec.answers > 0) then
    if answerFetcher[dtype] then
      return answerFetcher[dtype](dec, retAll)
    else
      stdnse.debug1("dns.findNiceAnswer() does not have an answerFetcher for dtype %s", tostring(dtype))
      return false, "Unable to handle response"
    end
  elseif (dec.flags.RC3 and dec.flags.RC4) then
    return false, "No Such Name"
  else
    stdnse.debug1("dns.findNiceAnswer() found zero answers in a response, but got an unexpected flags.replycode")
    return false, "No Answers"
  end
end

-- Table for additional fetching functions.
-- Some servers return their answers in the additional section. The
-- findNiceAdditional function with its relevant additionalFetcher functions
-- addresses this. This unfortunately involved some code duplication (because
-- of current design of the dns library) from the answerFetchers to the
-- additionalFetchers.
local additionalFetcher = {}

-- Additional fetcher for TXT records.
-- @param dec Decoded DNS response.
-- @param retAll If true, return all entries, not just the first.
-- @return True if one or more answers of the required type were found - otherwise false.
-- @return String first dns TXT record or Table of TXT records or String Error message.
additionalFetcher[types.TXT] = function(dec, retAll)
  local answers = {}
  if not retAll and dec.add[1].data then
    return true, string.sub(dec.add[1].data, 2)
  elseif not retAll then
    stdnse.debug1("dns.additionalFetcher found no records of the required type: TXT")
    return false, "No Answers"
  else
    for _, v in ipairs(dec.add) do
      if v.TXT and v.TXT.text then
        for _, v in ipairs( v.TXT.text ) do
          table.insert(answers, v)
        end
      end
    end
  end
  if #answers == 0 then
    stdnse.debug1("dns.answerFetcher found no records of the required type: TXT")
    return false, "No Answers"
  end
  return true, answers
end

-- Additional fetcher for A records
-- @param dec Decoded DNS response.
-- @param retAll If true, return all entries, not just the first.
-- @return True if one or more answers of the required type were found - otherwise false.
-- @return String first dns A record or Table of A records or String Error message.
additionalFetcher[types.A] = function(dec, retAll)
  local answers = {}
  for _, ans in ipairs(dec.add) do
    if ans.dtype == types.A then
      if not retAll then
        return true, ans.ip
      end
      table.insert(answers, ans.ip)
    end
  end
  if not retAll or #answers == 0 then
    stdnse.debug1("dns.answerFetcher found no records of the required type: A")
    return false, "No Answers"
  end
  return true, answers
end


-- Additional fetcher for SRV records.
-- @param dec Decoded DNS response.
-- @param retAll If true, return all entries, not just the first.
-- @return True if one or more answers of the required type were found - otherwise false.
-- @return String first dns SRV record or Table of SRV records or String Error message.
--  Note that the format of a returned SRV answer is "priority:weight:port:target" where zero
--  or more IP addresses may be present.
additionalFetcher[types.SRV] = function(dec, retAll)
  local srv, ip, answers = {}, {}, {}
  for _, ans in ipairs(dec.add) do
    if ans.dtype == types.SRV then
      if not retAll then
        return true, ("%s:%s:%s:%s"):format( ans.SRV.prio, ans.SRV.weight, ans.SRV.port, ans.SRV.target )
      end
      table.insert( answers, ("%s:%s:%s:%s"):format( ans.SRV.prio, ans.SRV.weight, ans.SRV.port, ans.SRV.target ) )
    end
  end
  if #answers == 0 then
    stdnse.debug1("dns.answerFetcher found no records of the required type: SRV")
    return false, "No Answers"
  end

  return true, answers
end


-- Additional fetcher for AAAA records.
-- @param dec Decoded DNS response.
-- @param retAll If true, return all entries, not just the first.
-- @return True if one or more answers of the required type were found - otherwise false.
-- @return String first dns AAAA record or Table of AAAA records or String Error message.
additionalFetcher[types.AAAA] = function(dec, retAll)
  local answers = {}
  for _, ans in ipairs(dec.add) do
    if ans.dtype == types.AAAA then
      if not retAll then
        return true, ans.ipv6
      end
      table.insert(answers, ans.ipv6)
    end
  end
  if not retAll or #answers == 0 then
    stdnse.debug1("dns.answerFetcher found no records of the required type: AAAA")
    return false, "No Answers"
  end
  return true, answers
end

---
-- Calls the answer fetcher for <code>dtype</code> or returns an error code in
-- case of a "no such name" error.
-- @param dtype DNS resource record type.
-- @param dec Decoded DNS response.
-- @param retAll If true, return all entries, not just the first.
-- @return True if one or more answers of the required type were found - otherwise false.
-- @return Answer according to the answer fetcher for <code>dtype</code> or an Error message.
function findNiceAdditional(dtype, dec, retAll)
  if (#dec.add > 0) then
    if additionalFetcher[dtype] then
      return additionalFetcher[dtype](dec, retAll)
    else
      stdnse.debug1("dns.findNiceAdditional() does not have an additionalFetcher for dtype %s",
      (type(dtype) == 'string' and dtype) or type(dtype) or "nil")
      return false, "Unable to handle response"
    end
  elseif (dec.flags.RC3 and dec.flags.RC4) then
    return false, "No Such Name"
  else
    stdnse.debug1("dns.findNiceAdditional() found zero answers in a response, but got an unexpected flags.replycode")
    return false, "No Answers"
  end
end

--
-- Encodes a FQDN
-- @param fqdn containing the fully qualified domain name
-- @return encQ containing the encoded value
local function encodeFQDN(fqdn)
  if ( not(fqdn) or #fqdn == 0 ) then return "\0" end

  local encQ = {}
  for part in string.gmatch(fqdn, "[^%.]+") do
    encQ[#encQ+1] = string.pack("s1", part)
  end
  encQ[#encQ+1] = "\0"
  return table.concat(encQ)
end

---
-- Encodes the question part of a DNS request.
-- @param questions Table of questions.
-- @return Encoded question string.
local function encodeQuestions(questions)
  if type(questions) ~= "table" then return nil end
  local encQ = {}
  for _, v in ipairs(questions) do
    encQ[#encQ+1] = encodeFQDN(v.dname)
    encQ[#encQ+1] = string.pack(">I2I2", v.dtype, v.class)
  end
  return table.concat(encQ)
end

---
-- Encodes the zone part of a DNS request.
-- @param questions Table of questions.
-- @return Encoded question string.
local function encodeZones(zones)
  return encodeQuestions(zones)
end

local function encodeUpdates(updates)
  if type(updates) ~= "table" then return nil end
  local encQ = {}
  for _, v in ipairs(updates) do
    encQ[#encQ+1] = encodeFQDN(v.dname)
    encQ[#encQ+1] = string.pack(">I2I2I4s2", v.dtype, v.class, v.ttl, v.data)
  end
  return table.concat(encQ)
end

---
-- Encodes the additional part of a DNS request.
-- @param additional Table of additional records. Each must have the keys
-- <code>type</code>, <code>class</code>, <code>ttl</code>,
-- and <code>rdata</code>.
-- @return Encoded additional string.
local function encodeAdditional(additional)
  if type(additional) ~= "table" then return nil end
  local encA = {}
  for _, v in ipairs(additional) do
    encA[#encA+1] = string.pack(">xI2I2I4s2",  v.type, v.class, v.ttl, v.rdata)
  end
  return table.concat(encA)
end

---
-- Encodes DNS flags to a binary digit string.
-- @param flags Flag table, each entry representing a flag (QR, OCx, AA, TC, RD,
-- RA, RCx).
-- @return Binary digit string representing flags.
local function encodeFlags(flags)
  if type(flags) == "number" then return flags end
  if type(flags) ~= "table" then return nil end
  local fb = 0
  if flags.QR  then fb = fb|0x8000 end
  if flags.OC1 then fb = fb|0x4000 end
  if flags.OC2 then fb = fb|0x2000 end
  if flags.OC3 then fb = fb|0x1000 end
  if flags.OC4 then fb = fb|0x0800 end
  if flags.AA  then fb = fb|0x0400 end
  if flags.TC  then fb = fb|0x0200 end
  if flags.RD  then fb = fb|0x0100 end
  if flags.RA  then fb = fb|0x0080 end
  if flags.RC1 then fb = fb|0x0008 end
  if flags.RC2 then fb = fb|0x0004 end
  if flags.RC3 then fb = fb|0x0002 end
  if flags.RC4 then fb = fb|0x0001 end
  return fb
end

---
-- Encode a DNS packet.
--
-- Caution: doesn't encode answer and authority part.
-- @param pkt Table representing DNS packet, initialized by
-- <code>newPacket</code>.
-- @return Encoded DNS packet.
function encode(pkt)
  if type(pkt) ~= "table" then return nil end
  local encFlags = encodeFlags(pkt.flags)
  local additional = encodeAdditional(pkt.additional)
  local aorplen = #pkt.answers
  local data, qorzlen, aorulen

  if ( #pkt.questions > 0 ) then
    data = encodeQuestions( pkt.questions )
    qorzlen = #pkt.questions
    aorulen = 0
  else
    -- The packet has no questions, assume we're dealing with an update
    data = encodeZones( pkt.zones ) .. encodeUpdates( pkt.updates )
    qorzlen = #pkt.zones
    aorulen = #pkt.updates
  end

  local encStr
  if ( pkt.flags.raw ) then
    encStr = string.pack(">I2I2I2I2I2I2", pkt.id, pkt.flags.raw, qorzlen, aorplen, aorulen, #pkt.additional) .. data .. additional
  else
    encStr = string.pack(">I2I2I2I2I2I2", pkt.id, encFlags, qorzlen, aorplen, aorulen, #pkt.additional) .. data .. additional
  end
  return encStr
end


---
-- Decodes a domain in a DNS packet. Handles "compressed" data too.
-- @param data Complete DNS packet.
-- @param pos Starting position in packet.
-- @return Position after decoding.
-- @return Decoded domain, or <code>nil</code> on error.
function decStr(data, pos)
  local function dec(data, pos, limit)
    assert(pos > 0)
    local partlen
    local parts = {}
    local part

    -- Avoid infinite recursion on malformed compressed messages.
    limit = limit or 10
    if limit < 0 then
      return pos, nil
    end

    partlen, pos = string.unpack(">B", data, pos)
    while (partlen ~= 0) do
      if (partlen < 64) then
        if (#data - pos + 1) < partlen then
          return pos
        end
        part, pos = string.unpack("c" .. partlen, data, pos)
        table.insert(parts, part)
        partlen, pos = string.unpack(">B", data, pos)
      else
        partlen, pos = string.unpack(">I2", data, pos - 1)
        local _, part = dec(data, partlen - 0xC000 + 1, limit - 1)
        if part == nil then
          return pos
        end
        table.insert(parts, part)
        partlen = 0
      end
    end
    return pos, table.concat(parts, ".")
  end

  return dec(data, pos)
end


---
-- Decodes questions in a DNS packet.
-- @param data Complete DNS packet.
-- @param count Value of question counter in header.
-- @param pos Starting position in packet.
-- @return Position after decoding.
-- @return Table of decoded questions.
local function decodeQuestions(data, count, pos)
  local q = {}
  for i = 1, count do
    local currQ = {}
    pos, currQ.dname = decStr(data, pos)
    currQ.dtype, currQ.class, pos = string.unpack(">I2I2", data, pos)
    table.insert(q, currQ)
  end
  return pos, q
end


---
-- Table of functions to decode resource records
local decoder = {}

-- Decodes IP of A record, puts it in <code>entry.ip</code>.
-- @param entry RR in packet.
decoder[types.A] = function(entry)
  entry.ip = ipOps.str_to_ip(entry.data:sub(1,4))
end

-- Decodes IP of AAAA record, puts it in <code>entry.ipv6</code>.
-- @param entry RR in packet.
decoder[types.AAAA] = function(entry)
  entry.ipv6 = ipOps.str_to_ip(entry.data:sub(1,16))
end

-- Decodes SSH fingerprint record, puts it in <code>entry.SSHFP</code> as
-- defined in RFC 4255.
--
-- <code>entry.SSHFP</code> has the fields <code>algorithm</code>,
-- <code>fptype</code>, and <code>fingerprint</code>.
-- @param entry RR in packet.
decoder[types.SSHFP] = function(entry)
  local pos
  entry.SSHFP = {}
  entry.SSHFP.algorithm, entry.SSHFP.fptype, pos = string.unpack(">BB", entry.data)
  entry.SSHFP.fingerprint = stdnse.tohex(entry.data:sub(pos))
end


-- Decodes SOA record, puts it in <code>entry.SOA</code>.
--
-- <code>entry.SOA</code> has the fields <code>mname</code>, <code>rname</code>,
-- <code>serial</code>, <code>refresh</code>, <code>retry</code>,
-- <code>expire</code>, and <code>minimum</code>.
-- @param entry RR in packet.
-- @param data Complete encoded DNS packet.
-- @param pos Position in packet after RR.
decoder[types.SOA] = function(entry, data, pos)

  local np = pos - #entry.data

  entry.SOA = {}

  np, entry.SOA.mname = decStr(data, np)
  np, entry.SOA.rname = decStr(data, np)
  entry.SOA.serial,
  entry.SOA.refresh,
  entry.SOA.retry,
  entry.SOA.expire,
  entry.SOA.minimum,
  np = string.unpack(">I4I4I4I4I4", data, np)
end

-- An iterator that returns the positions of nonzero bits in the given binary
-- string.
local function bit_iter(bits)
  return coroutine.wrap(function()
    for i = 1, #bits do
      local n = string.byte(bits, i)
      local j = 0
      local mask = 0x80

      while mask > 0 do
        if (n & mask) ~= 0 then
          coroutine.yield((i - 1) * 8 + j)
        end
        j = j + 1
        mask = (mask >> 1)
      end
    end
  end)
end

-- Decodes NSEC records, puts result in <code>entry.NSEC</code>. See RFC 4034,
-- section 4.
--
-- <code>entry.NSEC</code> has the fields <code>dname</code>,
-- <code>next_dname</code>, and <code>types</code>.
-- @param entry RR in packet.
-- @param data Complete encoded DNS packet.
-- @param pos Position in packet after RR.
decoder[types.NSEC] = function (entry, data, pos)
  local np = pos - #entry.data
  entry.NSEC = {}
  entry.NSEC.dname = entry.dname
  np, entry.NSEC.next_dname = decStr(data, np)
  while np < pos do
    local block_num, type_bitmap
    block_num, type_bitmap, np = string.unpack(">Bs1", data, np)
    entry.NSEC.types = {}
    for i in bit_iter(type_bitmap) do
      entry.NSEC.types[(block_num - 1) * 256 + i] = true
    end
  end
end
-- Decodes NSEC3 records, puts result in <code>entry.NSEC3</code>. See RFC 5155.
--
-- <code>entry.NSEC3</code> has the fields <code>dname</code>,
-- <code>hash.alg</code>, and <code>hash.base32</code>.
-- <code>hash.bin</code>, and <code>hash.hex</code>.
-- <code>salt.bin</code>, and <code>salt.hex</code>.
-- <code>iterations</code>, and <code>types</code>.
-- @param entry RR in packet.
-- @param data Complete encoded DNS packet.
-- @param pos Position in packet after RR.
decoder[types.NSEC3] = function (entry, data, pos)
  local np = pos - #entry.data
  local _
  local flags

  entry.NSEC3 = {}
  entry.NSEC3.dname = entry.dname
  entry.NSEC3.salt, entry.NSEC3.hash = {}, {}

  entry.NSEC3.hash.alg, entry.NSEC3.flags, entry.NSEC3.iterations, np = string.unpack(">BBI2", data, np)
  -- do we even need to decode these do we care about opt out?
  -- entry.NSEC3.flags = decodeFlagsNSEC3(flags)

  entry.NSEC3.salt.bin, np = string.unpack(">s1",  data, np)
  entry.NSEC3.salt.hex = stdnse.tohex(entry.NSEC3.salt.bin)

  entry.NSEC3.hash.bin, np = string.unpack(">s1" , data, np)
  entry.NSEC3.hash.hex = stdnse.tohex(entry.NSEC3.hash.bin)
  entry.NSEC3.hash.base32 = base32.enc(entry.NSEC3.hash.bin, true)

  entry.NSEC3.WinBlockNo, entry.NSEC3.bin, np = string.unpack(">Bs1", data, np)
  entry.NSEC3.types = {}
  for i in bit_iter(entry.NSEC3.bin) do
    entry.NSEC3.types[(entry.NSEC3.WinBlockNo - 1) * 256 + i] = true
  end
end

-- Decodes records that consist only of one domain, for example CNAME, NS, PTR.
-- Puts result in <code>entry.domain</code>.
-- @param entry RR in packet.
-- @param data Complete encoded DNS packet.
-- @param pos Position in packet after RR.
local function decDomain(entry, data, pos)
  local np = pos - #entry.data
  local _
  _, entry.domain = decStr(data, np)
end

-- Decodes CNAME records.
-- Puts result in <code>entry.domain</code>.
-- @name decoder[types.CNAME]
-- @class function
-- @param entry RR in packet.
-- @param data Complete encoded DNS packet.
-- @param pos Position in packet after RR.
decoder[types.CNAME] = decDomain

-- Decodes NS records.
-- Puts result in <code>entry.domain</code>.
-- @name decoder[types.NS]
-- @class function
-- @param entry RR in packet.
-- @param data Complete encoded DNS packet.
-- @param pos Position in packet after RR.
decoder[types.NS] = decDomain

-- Decodes PTR records.
-- Puts result in <code>entry.domain</code>.
-- @name decoder[types.PTR]
-- @class function
-- @param entry RR in packet.
-- @param data Complete encoded DNS packet.
-- @param pos Position in packet after RR.
decoder[types.PTR] = decDomain

-- Decodes TXT records.
-- Puts result in <code>entry.domain</code>.
-- @name decoder[types.TXT]
-- @class function
-- @param entry RR in packet.
-- @param data Complete encoded DNS packet.
-- @param pos Position in packet after RR.
decoder[types.TXT] =
function (entry, data, pos)

  local len = #entry.data
  local np = pos - len
  local txt

  if len > 0 then
    entry.TXT = {}
    entry.TXT.text = {}
  end

  while np < pos do
    txt, np = string.unpack("s1", data, np)
    table.insert( entry.TXT.text, txt )
  end

end

---
-- Decodes OPT record, puts it in <code>entry.OPT</code>.
--
-- <code>entry.OPT</code> has the fields <code>mname</code>, <code>rname</code>,
-- <code>serial</code>, <code>refresh</code>, <code>retry</code>,
-- <code>expire</code>, and <code>minimum</code>.
-- @param entry RR in packet.
-- @param data Complete encoded DNS packet.
-- @param pos Position in packet after RR.
decoder[types.OPT] =
function(entry, data, pos)
  local np = pos - #entry.data - 6
  local opt = { bufsize = entry.class }
  opt.rcode, opt.version, opt.zflags, opt.data, np = string.unpack(">BBI2s2", data, np)
  entry.OPT = opt
end


-- Decodes MX record, puts it in <code>entry.MX</code>.
--
-- <code>entry.MX</code> has the fields <code>pref</code> and
-- <code>server</code>.
-- @param entry RR in packet.
-- @param data Complete encoded DNS packet.
-- @param pos Position in packet after RR.
decoder[types.MX] =
function(entry, data, pos)
  local np = pos - #entry.data + 2
  local _
  entry.MX = {}
  entry.MX.pref = string.unpack(">I2", entry.data)
  _, entry.MX.server = decStr(data, np)
end

-- Decodes SRV record, puts it in <code>entry.SRV</code>.
--
-- <code>entry.SRV</code> has the fields <code>prio</code>,
-- <code>weight</code>, <code>port</code> and
-- <code>target</code>.
-- @param entry RR in packet.
-- @param data Complete encoded DNS packet.
-- @param pos Position in packet after RR.
decoder[types.SRV] =
function(entry, data, pos)
  local np = pos - #entry.data
  local _
  entry.SRV = {}
  entry.SRV.prio, entry.SRV.weight, entry.SRV.port, np = string.unpack(">I2I2I2", data, np)
  np, entry.SRV.target = decStr(data, np)
end

-- Decodes returned resource records (answer, authority, or additional part).
-- @param data Complete encoded DNS packet.
-- @param count Value of according counter in header.
-- @param pos Starting position in packet.
-- @return Table of RRs.
local function decodeRR(data, count, pos)
  local ans = {}
  for i = 1, count do
    local currRR = {}
    pos, currRR.dname = decStr(data, pos)
    currRR.dtype, currRR.class, currRR.ttl, pos = string.unpack(">I2I2I4", data, pos)

    currRR.data, pos = string.unpack(">s2", data, pos)

    -- try to be smart: decode per type
    if decoder[currRR.dtype] then
      decoder[currRR.dtype](currRR, data, pos)
    end

    table.insert(ans, currRR)
  end
  return pos, ans
end

---
-- Decodes DNS flags.
-- @param flgStr Flags as a binary digit string.
-- @return Table representing flags.
local function decodeFlags(flags)
  local tflags = {}
  if (flags & 0x8000) ~= 0 then tflags.QR  = true end
  if (flags & 0x4000) ~= 0 then tflags.OC1 = true end
  if (flags & 0x2000) ~= 0 then tflags.OC2 = true end
  if (flags & 0x1000) ~= 0 then tflags.OC3 = true end
  if (flags & 0x0800) ~= 0 then tflags.OC4 = true end
  if (flags & 0x0400) ~= 0 then tflags.AA  = true end
  if (flags & 0x0200) ~= 0 then tflags.TC  = true end
  if (flags & 0x0100) ~= 0 then tflags.RD  = true end
  if (flags & 0x0080) ~= 0 then tflags.RA  = true end
  if (flags & 0x0008) ~= 0 then tflags.RC1 = true end
  if (flags & 0x0004) ~= 0 then tflags.RC2 = true end
  if (flags & 0x0002) ~= 0 then tflags.RC3 = true end
  if (flags & 0x0001) ~= 0 then tflags.RC4 = true end
  return tflags
end

---
-- Decodes a DNS packet.
-- @param data Encoded DNS packet.
-- @return Table representing DNS packet.
function decode(data)
  local pos
  local pkt = {}
  local encFlags
  local cnt = {}
  pkt.id, encFlags, cnt.q, cnt.a, cnt.auth, cnt.add, pos = string.unpack(">I2I2I2I2I2I2", data)
  -- for now, don't decode the flags
  pkt.flags = decodeFlags(encFlags)

  --
  -- check whether this is an update response or not
  -- a quick fix to allow decoding of non updates and not break for updates
  -- the flags are enough for the current code to determine whether an update was successful or not
  --
  local flags = encodeFlags(pkt.flags)
  -- QR, OC2
  if (flags & 0xF000) == 0xA000 then
    return pkt
  else
    pos, pkt.questions = decodeQuestions(data, cnt.q, pos)
    pos, pkt.answers = decodeRR(data, cnt.a, pos)
    pos, pkt.auth = decodeRR(data, cnt.auth, pos)
    pos, pkt.add = decodeRR(data, cnt.add, pos)
  end
  return pkt
end


---
-- Creates a new table representing a DNS packet.
-- @return Table representing a DNS packet.
function newPacket()
  local pkt = {}
  pkt.id = 1
  pkt.flags = {}
  pkt.flags.RD = true
  pkt.questions = {}
  pkt.zones = {}
  pkt.updates = {}
  pkt.answers = {}
  pkt.auth = {}
  pkt.additional = {}
  return pkt
end


---
-- Adds a question to a DNS packet table.
-- @param pkt Table representing DNS packet.
-- @param dname Domain name to be asked.
-- @param dtype RR to be asked.
function addQuestion(pkt, dname, dtype, class)
  if type(pkt) ~= "table" then return nil end
  if type(pkt.questions) ~= "table" then return nil end
  local class = class or CLASS.IN
  local q = {}
  q.dname = dname
  q.dtype = dtype
  q.class = class
  table.insert(pkt.questions, q)
  return pkt
end


get_default_timeout = function()
  local timeout = {[0] = 10000, 7000, 5000, 4000, 4000, 4000}
  return timeout[nmap.timing_level()] or 4000
end

---
-- Adds a zone to a DNS packet table
-- @param pkt Table representing DNS packet.
-- @param dname Domain name to be asked.
function addZone(pkt, dname)
  if ( type(pkt) ~= "table" ) or (type(pkt.updates) ~= "table") then return nil end
  table.insert(pkt.zones, { dname=dname, dtype=types.SOA, class=CLASS.IN })
  return pkt
end

---
-- Encodes the Z bitfield of an OPT record.
-- @param flags Flag table, each entry representing a flag (only DO flag implmented).
-- @return Binary digit string representing flags.
local function encodeOPT_Z(flags)
  if type(flags) == "number" then return flags end
  assert(type(flags) == "table")
  local bits = 0
  if flags.DO then bits = bits|0x8000 end
  return bits
end

---
-- Adds an client-subnet payload to the OPT packet
--
-- implementing https://tools.ietf.org/html/rfc7871
-- @param pkt Table representing DNS packet.
-- @param Z Table of Z flags. Only DO is supported.
-- @param client_subnet table containing the following fields
--        <code>family</code>  - IPv4: "inet" or 1 (default), IPv6: "inet6" or 2
--        <code>mask</code>    - byte containing the length of the subnet mask
--        <code>address</code> - string containing the IP address
function addClientSubnet(pkt,Z,subnet)
  local family = subnet.family or 1
  if type(family) == "string" then
    family = ({inet=1,inet6=2})[family]
  end
  assert(family == 1 or family == 2, "Unsupported subnet family")
  local code = 8 -- https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
  local mask = subnet.mask
  local scope_mask = 0 -- In requests, it MUST be set to 0
  -- Per RFC 7871, section 6:
  -- Address must have all insignificant bits zeroed out and insignificant bytes
  -- must be trimmed off. (/24 IPv4 address is submitted as 3 octets, not 4.)
  local addr = ipOps.get_first_ip(subnet.address, mask)
  addr = ipOps.ip_to_str(addr):sub(1, (mask + 7) // 8)
  local data = string.pack(">I2BB", family, mask, scope_mask) .. addr
  local opt = string.pack(">I2s2", code, data)
  addOPT(pkt,Z,opt)
end

---
-- Adds an NSID payload to the OPT packet
-- @param pkt Table representing DNS packet.
-- @param Z Table of Z flags. Only DO is supported.
function addNSID (pkt,Z)
  local opt = string.pack(">I2I2", 3, 0) -- nsid data
  addOPT(pkt,Z,opt)
end

---
-- Adds an OPT RR to a DNS packet's additional section.
--
-- Only the table of Z flags is supported (i.e., not RDATA). See RFC 2671
-- section 4.3.
-- @param pkt Table representing DNS packet.
-- @param Z Table of Z flags. Only DO is supported.
function addOPT(pkt, Z, opt)
  local rdata = opt or ""
  if type(pkt) ~= "table" then return nil end
  if type(pkt.additional) ~= "table" then return nil end
  local Z_int = encodeOPT_Z(Z)
  local opt = {
    type = types.OPT,
    class = 4096,  -- Actually the sender UDP payload size.
    ttl = 0 * (0x01000000) + 0 * (0x00010000) + Z_int,
    rdata = rdata,
  }
  table.insert(pkt.additional, opt)
  return pkt
end

---
-- Adds a update to a DNS packet table
-- @param pkt Table representing DNS packet.
-- @param dname Domain name to be asked.
-- @param dtype to be updated
-- @param ttl the time-to-live of the record
-- @param data type specific data
function addUpdate(pkt, dname, dtype, ttl, data, class)
  if ( type(pkt) ~= "table" ) or (type(pkt.updates) ~= "table") then return nil end
  table.insert(pkt.updates, { dname=dname, dtype=dtype, class=class, ttl=ttl, data=(data or "") } )
  return pkt
end


--- Adds a record to the Zone
-- @param dname containing the hostname to add
-- @param options A table containing any of the following fields:
-- * <code>dtype</code>: Desired DNS record type (default: <code>"A"</code>).
-- * <code>host</code>: DNS server to be queried (default: DNS servers known to Nmap).
-- * <code>timeout</code>: The time to wait for a response
-- * <code>sendCount</code>: The number of send attempts to perform
-- * <code>zone</code>: If not supplied deduced from hostname
-- * <code>data</code>: Table or string containing update data (depending on record type):
--  A     - String containing the IP address
--  CNAME - String containing the FQDN
--  MX   - Table containing <code>pref</code>, <code>mx</code>
--  SRV - Table containing <code>prio</code>, <code>weight</code>, <code>port</code>, <code>target</code>
--
-- @return status true on success false on failure
-- @return msg containing the error message
--
-- Examples
--
-- Adding different types of records to a server
--  * update( "www.cqure.net", { host=host, port=port, dtype="A", data="10.10.10.10" } )
--  * update( "alias.cqure.net", { host=host, port=port, dtype="CNAME", data="www.cqure.net" } )
--  * update( "cqure.net", { host=host, port=port, dtype="MX", data={ pref=10, mx="mail.cqure.net"} })
--  * update( "_ldap._tcp.cqure.net", { host=host, port=port, dtype="SRV", data={ prio=0, weight=100, port=389, target="ldap.cqure.net" } } )
--
-- Removing the above records by setting an empty data and a ttl of zero
--  * update( "www.cqure.net", { host=host, port=port, dtype="A", data="", ttl=0 } )
--  * update( "alias.cqure.net", { host=host, port=port, dtype="CNAME", data="", ttl=0 } )
--  * update( "cqure.net", { host=host, port=port, dtype="MX", data="", ttl=0 } )
--  * update( "_ldap._tcp.cqure.net", { host=host, port=port, dtype="SRV", data="", ttl=0 } )
--
function update(dname, options)
  local options = options or {}
  local pkt = newPacket()
  local flags = pkt.flags
  local host, port = options.host, options.port
  local timeout = ( type(options.timeout) == "number" ) and options.timeout or get_default_timeout()
  local sendcount = options.sendCount or 2
  local dtype = ( type(options.dtype) == "string" ) and types[options.dtype] or types.A
  local updata = options.data
  local ttl = options.ttl or 86400
  local zone = options.zone or dname:match("^.-%.(.+)$")
  local class = CLASS.IN

  assert(host, "dns.update needs a valid host in options")
  assert(port, "dns.update needs a valid port in options")

  if ( options.zone ) then dname = dname .. "." .. options.zone end

  if ( not(zone) and not( dname:match("^.-%..+") ) ) then
    return false, "hostname needs to be supplied as FQDN"
  end

  flags.RD = false
  flags.OC1, flags.OC2, flags.OC3, flags.OC4 = false, true, false, true

  -- If ttl is zero and updata is nil or a string of zero length, assume delete record
  if ttl == 0 and (not updata or (type(updata) == "string" and #updata == 0)) then
    class = CLASS.ANY
    updata = ""
    if ( types.MX == dtype and not(options.zone) ) then zone=dname end
    if ( types.SRV == dtype and not(options.zone) ) then
      zone=dname:match("^_.-%._.-%.(.+)$")
    end
    -- if not, let's try to update the zone
  else
    if ( dtype == types.A or dtype == types.AAAA ) then
      updata = updata and ipOps.ip_to_str(updata) or ""
    elseif( dtype == types.CNAME ) then
      updata = encodeFQDN(updata)
    elseif( dtype == types.MX ) then
      assert( not( type(updata) ~= "table" ), "dns.update expected options.data to be a table")
      if ( not(options.zone) ) then zone = dname end
      local data = string.pack(">I2", updata.pref)
      data = data .. encodeFQDN(updata.mx)
      updata = data
    elseif ( dtype == types.SRV ) then
      assert( not( type(updata) ~= "table" ), "dns.update expected options.data to be a table")
      local data = string.pack(">I2I2I2", updata.prio, updata.weight, updata.port )
      data = data .. encodeFQDN(updata.target)
      updata = data
      zone = options.zone or dname:match("^_.-%._.-%.(.+)$")
    else
      return false, "Unsupported record type"
    end
  end

  pkt = addZone(pkt, zone)
  pkt = addUpdate(pkt, dname, dtype, ttl, updata, class)

  local data = encode(pkt)
  local status, response = sendPackets(data, host, port, timeout, sendcount, false)

  if ( status ) then
    local decoded = decode(response[1].data)
    local flags = encodeFlags(decoded.flags)
    if (flags & 0xF) == 0 then
      return true
    end
  end
  return false
end

if not unittest.testing() then
  return _ENV
end

-- Self test
test_suite = unittest.TestSuite:new()

test_suite:add_test(unittest.equal(encodeFQDN("test.me.com"), "\x04test\x02me\x03com\0"), "encodeFQDN")
local tests = { {
    pkt = string.char(0x92, 0xdc, -- Trsnsaction ID
      0x81, 0x80, -- Flags
      0x00, 0x01, -- Questions count
      0x00, 0x01, -- Answers RRs count
      0x00, 0x00, -- Authorities RRs count
      0x00, 0x00, -- Additionals RRs count
      0x06, -- Label length <-- [12]
      0x73, 0x63, 0x61, 0x6e, 0x6d, 0x65, -- "scanme"
      0x04, -- Label length
      0x6e, 0x6d, 0x61, 0x70, -- "nmap"
      0x03, -- Label length
      0x6f, 0x72, 0x67, -- "org"
      0x00, -- Name terminator
      0x00, 0x01, -- A
      0x00, 0x01, -- CLASS_IN
      0xc0, 0x0c, -- Compressed name pointer to offset 12
      0x00, 0x01, -- A
      0x00, 0x01, -- CLASS_IN
      0x00, 0x00, 0x0e, 0x0f, -- TTL 3599
      0x00, 0x04, -- Record Length
      0x2d, 0x21, 0x20, 0x9c ), -- 45.33.32.156
    qname = "scanme.nmap.org",
    qtype = "A",
    ans = {"ip", "45.33.32.156"}
  },
  {
    pkt = string.char(
      0x08, 0xf2, -- ID
      0x81, 0x80, -- Flags
      0x00, 0x01, -- Questions count
      0x00, 0x01, -- Answers RRs count
      0x00, 0x00, -- Authorities RRs count
      0x00, 0x00, -- Additionals RRs count
      0x03, -- Label length
      0x31, 0x35, 0x36, -- "156"
      0x02, -- Label length
      0x33, 0x32, -- "32"
      0x02, -- Label length
      0x33, 0x33, -- "33"
      0x02, -- Label length
      0x34, 0x35, -- "45"
      0x07, -- Label length
      0x69, 0x6e, 0x2d, 0x61, 0x64, 0x64, 0x72, -- "in-addr"
      0x04, -- Label length
      0x61, 0x72, 0x70, 0x61, -- "arpa"
      0x00, -- Name terminator
      0x00, 0x0c, -- PTR
      0x00, 0x01, -- CLASS_IN
      0xc0, 0x0c, -- Compressed name pointer to offset 12
      0x00, 0x0c, -- PTR
      0x00, 0x01, -- CLASS_IN
      0x00, 0x01, 0x51, 0x78, -- TTL 86392
      0x00, 0x11, -- Record Length
      0x06, -- Label length
      0x73, 0x63, 0x61, 0x6e, 0x6d, 0x65, -- "scanme"
      0x04, -- Label length
      0x6e, 0x6d, 0x61, 0x70, -- "nmap"
      0x03, -- Label length
      0x6f, 0x72, 0x67, -- "org"
      0x00),  -- Name terminator
    qname = "156.32.33.45.in-addr.arpa",
    qtype = "PTR",
    ans = {"domain", "scanme.nmap.org"}
  },
}
for _, t in ipairs(tests) do
  local decoded = decode(t.pkt)
  local q = decoded.questions[1]
  local a = decoded.answers[1]
  test_suite:add_test(unittest.equal(q.dname, t.qname), "decode question name")
  test_suite:add_test(unittest.equal(q.dtype, types[t.qtype]), "decode question type")
  test_suite:add_test(unittest.equal(a[t.ans[1]], t.ans[2]), "decode answer")
end
local axfr = stdnse.fromhex(
"dead840000010032000000000c7a\z
6f6e657472616e73666572026d650000\z
fc0001c00c0006000100001c20002f06\z
6e737a746d310464696769056e696e6a\z
610005726f62696ec034785908810002\z
a300000003840012750000000e10c00c\z
000d00010000012c00190d436173696f\z
2066782d373030470a57696e646f7773\z
205850c00c001000010000012d004544\z
676f6f676c652d736974652d76657269\z
6669636174696f6e3d74795032384a37\z
4a41554841396677327348584d676343\z
4330493658426d6d6f56693034566c4d\z
65777841c00c000f000100001c200016\z
0000054153504d58014c06474f4f474c\z
4503434f4d00c00c000f000100001c20\z
0009000a04414c5431c0e0c00c000f00\z
0100001c200009000a04414c5432c0e0\z
c00c000f000100001c20001600140641\z
53504d58320a474f4f474c454d41494c\z
c0efc00c000f000100001c20000b0014\z
064153504d5833c133c00c000f000100\z
001c20000b0014064153504d5834c133\z
c00c000f000100001c20000b00140641\z
53504d5835c133c00c0001000100001c\z
20000405c4690ec00c0002000100001c\z
200002c02dc00c0002000100001c2000\z
09066e737a746d32c0340f5f61636d65\z
2d6368616c6c656e6765c00c00100001\z
0000012d002c2b364f6130356862554a\z
39785373765979377041705176774355\z
535347677876726264697a6a65504573\z
5a49045f736970045f746370c00c0021\z
0001000036b0001b0000000013c40377\z
77770c7a6f6e657472616e7366657202\z
6d650002313403313035033139360135\z
07494e2d414444520441525041c22000\z
0c000100001c200002c21c0c61736664\z
6261757468646e73c220001200010000\z
1edc001c0001086173666462626f780c\z
7a6f6e657472616e73666572026d6500\z
c2740001000100001c2000047f000001\z
0b6173666462766f6c756d65c27d0012\z
000100001e78001c0001086173666462\z
626f780c7a6f6e657472616e73666572\z
026d65000f63616e62657272612d6f66\z
66696365c2c10001000100001c200004\z
ca0e51e607636d6465786563c2c10010\z
00010000012c0005043b206c7307636f\z
6e74616374c2c10010000100278d0000\z
646352656d656d62657220746f206361\z
6c6c206f7220656d61696c2050697070\z
61206f6e202b34342031323320343536\z
37383930206f72207069707061407a6f\z
6e657472616e736665722e6d65207768\z
656e206d616b696e6720444e53206368\z
616e6765730964632d6f6666696365c2\z
c10001000100001c2000048fe4b58408\z
6465616462656566c2c1001c00010000\z
1c210010deadbeaf0000000000000000\z
00000000026472c2c1001d0001000001\z
2c0010001216138b728cee7fa5c44a00\z
98968003445a43c2c10010000100001c\z
200008074162436445664705656d6169\z
6cc2c100230001000008ae0038000100\z
010150094532552b656d61696c000565\z
6d61696c0c7a6f6e657472616e736665\z
72026d650c7a6f6e657472616e736665\z
72026d6500c3f90001000100001c2000\z
044a7dce1a0548656c6c6fc432001000\z
0100001c20001d1c486920746f204a6f\z
736820616e6420616c6c206869732063\z
6c61737304686f6d65c4320001000100\z
001c2000047f00000104496e666fc432\z
0010000100001c20008b8a5a6f6e6554\z
72616e736665722e6d65207365727669\z
63652070726f76696465642062792052\z
6f62696e20576f6f64202d20726f6269\z
6e40646967692e6e696e6a612e205365\z
6520687474703a2f2f646967692e6e69\z
6e6a612f70726f6a656374732f7a6f6e\z
657472616e736665726d652e70687020\z
666f72206d6f726520696e666f726d61\z
74696f6e2e08696e7465726e616cc432\z
000200010000012c000906696e746e73\z
31c432c533000200010000012c000906\z
696e746e7332c432c548000100010000\z
012c000451046c29c55d000100010000\z
012c0004a7582a5e066f6666696365c4\z
320001000100001c200004041727fe0a\z
697076366163746e6f77036f7267c432\z
001c000100001c2000102001067c02e8\z
001100000000c1001332036f7761c432\z
0001000100001c200004cf2ec5200972\z
6f62696e776f6f64c432001000010000\z
012e000b0a526f62696e20576f6f6402\z
7270c432001100010000014100320572\z
6f62696e0c7a6f6e657472616e736665\z
72026d650009726f62696e776f6f640c\z
7a6f6e657472616e73666572026d6500\z
03736970c62d0023000100000d05003b\z
000200030150074532552b7369702b21\z
5e2e2a24217369703a637573746f6d65\z
722d73657276696365407a6f6e657472\z
616e736665722e6d6521000473716c69\z
c62d001000010000012c000c0b27206f\z
7220313d31202d2d067373686f636bc6\z
2d0010000100001c20001c1b2829207b\z
203a5d7d3b206563686f205368656c6c\z
53686f636b65640773746167696e67c6\z
2d0005000100001c20001a0377777710\z
7379646e65796f70657261686f757365\z
03636f6d000f616c6c746370706f7274\z
736f70656e086669726577616c6c0474\z
657374c62d000100010000012d00047f\z
0000010774657374696e67c62d000500\z
010000012d0002c21c0376706ec62d00\z
01000100000fa00004ae243b9ac21c00\z
01000100001c20000405c4690e037873\z
73c62d001000010000012c00201f273e\z
3c7363726970743e616c657274282742\z
6f6f27293c2f7363726970743ec62d00\z
06000100001c200018c02dc040785908\z
810002a300000003840012750000000e\z
10")
local axfr_decoded = decode(axfr)
local answers = {
  {dname="zonetransfer.me", dtype=types["SOA"], mname="nsztm1.digi.ninja", rname="robin.digi.ninja"},
  {dname="zonetransfer.me", dtype=types["HINFO"]}, --  "Casio fx-700G" "Windows XP"
  {dname="zonetransfer.me", dtype=types["TXT"], text="google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"},
  {dname="zonetransfer.me", dtype=types["MX"], pref=0,  server="ASPMX.L.GOOGLE.COM"},
  {dname="zonetransfer.me", dtype=types["MX"], pref=10, server="ALT1.ASPMX.L.GOOGLE.COM"},
  {dname="zonetransfer.me", dtype=types["MX"], pref=10, server="ALT2.ASPMX.L.GOOGLE.COM"},
  {dname="zonetransfer.me", dtype=types["MX"], pref=20, server="ASPMX2.GOOGLEMAIL.COM"},
  {dname="zonetransfer.me", dtype=types["MX"], pref=20, server="ASPMX3.GOOGLEMAIL.COM"},
  {dname="zonetransfer.me", dtype=types["MX"], pref=20, server="ASPMX4.GOOGLEMAIL.COM"},
  {dname="zonetransfer.me", dtype=types["MX"], pref=20, server="ASPMX5.GOOGLEMAIL.COM"},
  {dname="zonetransfer.me", dtype=types["A"],  ip="5.196.105.14"},
  {dname="zonetransfer.me", dtype=types["NS"], domain="nsztm1.digi.ninja"},
  {dname="zonetransfer.me", dtype=types["NS"], domain="nsztm2.digi.ninja"},
  {dname="_acme-challenge.zonetransfer.me", dtype=types["TXT"], text="6Oa05hbUJ9xSsvYy7pApQvwCUSSGgxvrbdizjePEsZI"},
  {dname="_sip._tcp.zonetransfer.me", dtype=types["SRV"], prio=0, weight=0, port=5060, target="www.zonetransfer.me"},
  {dname="14.105.196.5.IN-ADDR.ARPA.zonetransfer.me", dtype=types["PTR"], domain="www.zonetransfer.me"},
  {dname="asfdbauthdns.zonetransfer.me", dtype=types["AFSDB"]}, -- 1 asfdbbox.zonetransfer.me.
  {dname="asfdbbox.zonetransfer.me", dtype=types["A"], ip="127.0.0.1"},
  {dname="asfdbvolume.zonetransfer.me", dtype=types["AFSDB"]}, -- 1 asfdbbox.zonetransfer.me.
  {dname="canberra-office.zonetransfer.me", dtype=types["A"], ip="202.14.81.230"},
  {dname="cmdexec.zonetransfer.me", dtype=types["TXT"], text="; ls"},
  {dname="contact.zonetransfer.me", dtype=types["TXT"], text="Remember to call or email Pippa on +44 123 4567890 or pippa@zonetransfer.me when making DNS changes"},
  {dname="dc-office.zonetransfer.me", dtype=types["A"], ip="143.228.181.132"},
  {dname="deadbeef.zonetransfer.me", dtype=types["AAAA"], ipv6="dead:beaf::"},
  {dname="dr.zonetransfer.me", dtype=types["LOC"]}, -- 53.349044 N 1.642646 W 0m 1.0m 10000.0m 10.0m
  {dname="DZC.zonetransfer.me", dtype=types["TXT"], text="AbCdEfG"},
  {dname="email.zonetransfer.me", dtype=types["NAPTR"]}, -- 1 1 "P" "E2U+email" "" email.zonetransfer.me.zonetransfer.me.
  {dname="email.zonetransfer.me", dtype=types["A"], ip="74.125.206.26"},
  {dname="Hello.zonetransfer.me", dtype=types["TXT"], text="Hi to Josh and all his class"},
  {dname="home.zonetransfer.me", dtype=types["A"], ip="127.0.0.1"},
  {dname="Info.zonetransfer.me", dtype=types["TXT"], text="ZoneTransfer.me service provided by Robin Wood - robin@digi.ninja. See http://digi.ninja/projects/zonetransferme.php for more information."},
  {dname="internal.zonetransfer.me", dtype=types["NS"], domain="intns1.zonetransfer.me"},
  {dname="internal.zonetransfer.me", dtype=types["NS"], domain="intns2.zonetransfer.me"},
  {dname="intns1.zonetransfer.me", dtype=types["A"], ip="81.4.108.41"},
  {dname="intns2.zonetransfer.me", dtype=types["A"], ip="167.88.42.94"},
  {dname="office.zonetransfer.me", dtype=types["A"], ip="4.23.39.254"},
  {dname="ipv6actnow.org.zonetransfer.me", dtype=types["AAAA"], ipv6="2001:67c:2e8:11::c100:1332"},
  {dname="owa.zonetransfer.me", dtype=types["A"], ip="207.46.197.32"},
  {dname="robinwood.zonetransfer.me", dtype=types["TXT"], text="Robin Wood"},
  {dname="rp.zonetransfer.me", dtype=types["RP"]}, -- robin.zonetransfer.me. robinwood.zonetransfer.me.
  {dname="sip.zonetransfer.me", dtype=types["NAPTR"]}, -- 2 3 "P" "E2U+sip" "!^.*$!sip:customer-service@zonetransfer.me!" .
  {dname="sqli.zonetransfer.me", dtype=types["TXT"], text="' or 1=1 --"},
  {dname="sshock.zonetransfer.me", dtype=types["TXT"],text="() { :]}; echo ShellShocked"},
  {dname="staging.zonetransfer.me", dtype=types["CNAME"], domain="www.sydneyoperahouse.com"},
  {dname="alltcpportsopen.firewall.test.zonetransfer.me", dtype=types["A"], ip="127.0.0.1"},
  {dname="testing.zonetransfer.me", dtype=types["CNAME"], domain="www.zonetransfer.me"},
  {dname="vpn.zonetransfer.me", dtype=types["A"], ip="174.36.59.154"},
  {dname="www.zonetransfer.me", dtype=types["A"], ip="5.196.105.14"},
  {dname="xss.zonetransfer.me", dtype=types["TXT"], text="'><script>alert('Boo')</script>"},
  {dname="zonetransfer.me", dtype=types["SOA"], mname="nsztm1.digi.ninja", rname="robin.digi.ninja"},
}
for i, a in ipairs(axfr_decoded.answers) do
  ta = answers[i]
  if ta.dtype == types.TXT then
    test_suite:add_test(unittest.equal(a.dname, ta.dname), i .. ".dname")
    test_suite:add_test(unittest.equal(a.dtype, ta.dtype), i .. ".dtype")
    test_suite:add_test(unittest.equal(a.TXT.text[1], ta.text), i .. ".text")
  elseif ta.dtype == types.SOA then
    test_suite:add_test(unittest.equal(a.dname, ta.dname), i .. ".dname")
    test_suite:add_test(unittest.equal(a.dtype, ta.dtype), i .. ".dtype")
    test_suite:add_test(unittest.equal(a.SOA.mname, ta.mname), i .. ".mname")
    test_suite:add_test(unittest.equal(a.SOA.rname, ta.rname), i .. ".rname")
  elseif ta.dtype == types.MX then
    test_suite:add_test(unittest.equal(a.dname, ta.dname), i .. ".dname")
    test_suite:add_test(unittest.equal(a.dtype, ta.dtype), i .. ".dtype")
    test_suite:add_test(unittest.equal(a.MX.pref, ta.pref), i .. ".pref")
    test_suite:add_test(unittest.equal(a.MX.server, ta.server), i .. ".server")
  elseif ta.dtype == types.SRV then
    test_suite:add_test(unittest.equal(a.dname, ta.dname), i .. ".dname")
    test_suite:add_test(unittest.equal(a.dtype, ta.dtype), i .. ".dtype")
    test_suite:add_test(unittest.equal(a.SRV.prio, ta.prio), i .. ".prio")
    test_suite:add_test(unittest.equal(a.SRV.weight, ta.weight), i .. ".weight")
    test_suite:add_test(unittest.equal(a.SRV.port, ta.port), i .. ".port")
  else
    for k, v in pairs(ta) do
      test_suite:add_test(unittest.equal(a[k], v), ("%d.%s"):format(i, k))
    end
  end
end
return _ENV;
