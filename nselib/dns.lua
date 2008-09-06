module(... or "dns", package.seeall)

-- simple DNS library
-- packet creation, encoding, decoding, querying

require("ipOps")
require("stdnse")

get_servers = nmap.get_dns_servers


types = {
   A = 1,
   AAAA = 28,
   NS = 2,
   SOA = 6,
   CNAME = 5,
   PTR = 12,
   HINFO = 13,
   MX = 15,
   TXT = 16,
   SRV = 33,
   SSHFP = 44,
   AXFR = 252,
   ANY = 255
}


err = {
   noSuchName = 3,
   noServers = 9
}


---
-- sends repeatedly udp packets to host, 
-- waiting for an answer
--@param data Data to be sent
--@param host Host to connect to
--@param port Port to connect to
--@param cnt Number of tries
--@return success as boolean and response if available
local function sendPackets(data, host, port, cnt)
   local socket = nmap.new_socket()
   socket:set_timeout(10000)
   socket:connect(host, port, "udp")

   for i = 1, cnt do 
      socket:send(data)
      local response
      local status, response = socket:receive_bytes(1)
      
      if (status) then
         socket:close()
         return true, response
      end
   end
   socket:close()
   return false
end


---
-- Checks if DNS response packet contains a useful answer
--@param rPkt decoded DNS response packet
--@return True if useful, false if not
local function gotAnswer(rPkt)
   -- have we even got answers?
   if #rPkt.answers > 0 then
      
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
-- Tries to find next nameserver with authority
-- to get result to query
--@param rPkt decoded DNS response packet
--@return string or table of next server(s) to query or false
local function getAuthDns(rPkt)
   if #rPkt.auth == 0 then 
      if #rPkt.answers == 0 then
         return false 
      else
         if #rPkt.answers[1].dtype == types.CNAME then
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
      local next = query(rPkt.auth[1].domain, {dtype = "A" })
      return next
   end
   return false
end

---
-- Query DNS servers for a DNS record
--@param dname wanted domain name entry
--@param options
-- dtype wanted DNS record type (default: A)
-- host DNS server to be queried (default: DNS servers known to nmap)
-- port Port of DNS server to connect to (default: 53)
-- tries How often should query try to contact another server (for non-recursive queries)
-- retAll Return all answers, not just the first
-- retPkt Return the packet instead of using the answer fetching mechanism
-- norecurse
--@return Nice answer string by an answer fetcher on success or false and an error code (see: dns.err.*)
function query(dname, options)
   if not options then options = {} end

   local dtype, host, port, tries = options.dtype, options.host, options.port, options.tries

   if not tries then tries = 10 end -- don't get into an infinite loop

   if not options.sendCount then options.sendCount = 2 end

   if type(dtype) == "string" then
      dtype = types[dtype]
   end
   if not dtype then dtype = types.A end

   local srv
   local srvI = 1
   if not port then port = 53 end
   if not host then 
      -- IF PATCH NOT APPLIED!
      if type(get_servers) == "function" then
         srv = get_servers()
      end
      -- !
      
      if srv and srv[1] then 
         host = srv[1]
      else
         return false, err.noServers
      end
   elseif type(host) == "table" then
      srv = host
      host = srv[1]
   end

   local pkt = newPacket()
   addQuestion(pkt, dname, dtype)
   if options.norecurse then pkt.flags.RD = false end

   local data = encode(pkt)

   local status, response = sendPackets(data, host, port, options.sendCount)


   -- if working with know nameservers, try the others
   while((not status) and srv and srvI < #srv) do
      srvI = srvI + 1
      host = srv[srvI]
      status, response = sendPackets(data, host, port, options.sendCount)
   end

   -- if we got any response:
   if status then
      local rPkt = decode(response)
      -- is it a real answer?
      if gotAnswer(rPkt) then
         if (options.retPkt) then 
            return rPkt 
         else
            return findNiceAnswer(dtype, rPkt, options.retAll)
         end
      else -- if not, ask the next server in authority

         local next_server = getAuthDns(rPkt)
         
         -- if we got a CNAME, ask for the CNAME
         if type(next_server) == 'table' and next_server.cname then
            options.tries = tries - 1
            return query(next_server.cname, options)
         end

         -- only ask next server in authority, if 
         -- we got an auth dns and
         -- it isn't the one we just asked
         if next_server and next_server ~= host and tries > 1 then 
            options.host = next_server
            options.tries = tries - 1
            return query(dname, options) 
         end
      end
      
      -- nothing worked, maybe user finds decoded packet useful
      return false, rPkt 
   else
      return false
   end
end


---
-- Formats IP for reverse lookup
--@param ip IP address string
--@return "Domain" style representation of IP as subdomain of in-addr.arpa or ip6.arpa
function reverse(ip)
   ip = ipOps.expand_ip(ip)
   if type(ip) ~= "string" then return nil end
   local delim = "%."
   local arpa = ".in-addr.arpa"
   if ip:match(":") then
      delim = ":"
      arpa = ".ip6.arpa"
   end
   local ipParts = stdnse.strsplit(delim, ip)
   if #ipParts == 8 then
      -- padding
      local mask = "0000"
      for i, part in ipairs(ipParts) do
          ipParts[i] = mask:sub(1, string.len(mask) - string.len(part)) .. part
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

---
-- Table for answer fetching functions
local answerFetcher = {}

---
-- answer fetcher for TXT records
--@param dec Decoded DNS response
--@param retAll If true return all entries, not just the first
--@return first entry (or all) treated as TXT
answerFetcher[types.TXT] = 
   function(dec, retAll)
      if not retAll then
         return string.sub(dec.answers[1].data, 2)
      else
         local answers = {}
         for _, v in ipairs(dec.answers) do
            if v.data then table.insert(answers, string.sub(v.data, 2)) end
         end
         return answers
      end
   end

---
-- answer fetcher for A records
--@param dec Decoded DNS response
--@param retAll If true return all entries, not just the first
--@return first IP (or all) of response packet
answerFetcher[types.A] = 
   function(dec, retAll)
      local answers = {}
      for _, ans in ipairs(dec.answers) do
         if ans.dtype == types.A then
            if not retAll then
               return ans.ip
            else
               table.insert(answers, ans.ip)
            end
         end
      end
      if retAll then return answers end
      return dec
   end


---
-- answer fetcher for A records
--@param dec Decoded DNS response
--@param retAll If true return all entries, not just the first
--@return Domain entry of first answer RR (or all) in response packet
answerFetcher[types.CNAME] = 
   function(dec, retAll)
      if not retAll then
         return dec.answers[1].domain
      else
         local answers = {}
         for _, v in ipairs(dec.answers) do
            if v.domain then table.insert(answers, v.domain) end
         end
         return answers
      end
   end

---
-- answer fetcher for A records
--@param dec Decoded DNS response
--@param retAll If true return all entries, not just the first
--@return Domain entry of first answer RR (or all) in response packet
answerFetcher[types.MX] = 
   function(dec, retAll)
      if not retAll then
         if dec.answers[1] then
            return dec.answers[1].MX.pref .. ":" .. dec.answers[1].MX.server .. ":" .. dec.add[1].ip
         else
            return dec
         end
      else
         local answers = {}
         for _, v in ipairs(dec.answers) do
            if v.MX then table.insert(answers, v.MX.pref .. ":" .. v.MX.server .. ":" .. v.MX.ip) end
         end
         return answers
      end
   end


answerFetcher[types.NS] = answerFetcher[types.CNAME]
answerFetcher[types.PTR] = answerFetcher[types.CNAME]

---
-- answer fetcher for AAAA records
--@param dec Decoded DNS response
--@param retAll If true return all entries, not just the first
--@return first IPv6 (or all) of response packet
answerFetcher[types.AAAA] = 
   function(dec, retAll)
      local answers = {}
      for _, ans in ipairs(dec.answers) do
         if ans.dtype == types.AAAA then
            if not retAll then
               return ans.ipv6
            else
               table.insert(answers, ans.ipv6)
            end
         end
      end
      if retAll then return answers end
      return dec
   end


---
-- Calls answer fetcher for asked type or returns
-- error code on a no such name error
--@param dtype DNS resource record type
--@param dec Decoded DNS response
--@param retAll If true return all entries, not just the first
--@return answer by according answer fetcher or packet if none applicable or false and error code if flags indicate an error
function findNiceAnswer(dtype, dec, retAll) 
   if (#dec.answers > 0) then
      if answerFetcher[dtype] then 
         return answerFetcher[dtype](dec, retAll)
      else 
         return dec
      end
   else
      if (dec.flags.RC3 and dec.flags.RC4) then return false, err.noSuchName
      end
   end
end


---
-- Encodes the question part of a DNS request
--@param questions Table of questions
--@return Encoded question string
local function encodeQuestions(questions)
   if type(questions) ~= "table" then return nil end
   local encQ = ""
   for _, v in ipairs(questions) do
      local parts = stdnse.strsplit("%.", v.dname)
      for _, part in ipairs(parts) do
         encQ = encQ .. bin.pack("p", part)
      end
      encQ = encQ .. string.char(0)
      encQ = encQ .. bin.pack(">SS", v.dtype, v.class)
   end
   return encQ
end

---
-- Encodes DNS flags to binary digit string
--@param flags Flag table, each entry representing a flag (QR, OCx, AA, TC, RD, RA, RCx)
--@return Binary digit string representing flags
local function encodeFlags(flags)
   if type(flags) == "string" then return flags end
   if type(flags) ~= "table" then return nil end
   local fb = ""
   if flags.QR then fb = fb .. "1" else fb = fb .. "0" end
   if flags.OC1 then fb = fb .. "1" else fb = fb .. "0" end
   if flags.OC2 then fb = fb .. "1" else fb = fb .. "0" end
   if flags.OC3 then fb = fb .. "1" else fb = fb .. "0" end
   if flags.OC4 then fb = fb .. "1" else fb = fb .. "0" end
   if flags.AA then fb = fb .. "1" else fb = fb .. "0" end
   if flags.TC then fb = fb .. "1" else fb = fb .. "0" end
   if flags.RD then fb = fb .. "1" else fb = fb .. "0" end
   if flags.RA then fb = fb .. "1" else fb = fb .. "0" end
   fb = fb .. "000"
   if flags.RC1 then fb = fb .. "1" else fb = fb .. "0" end
   if flags.RC2 then fb = fb .. "1" else fb = fb .. "0" end
   if flags.RC3 then fb = fb .. "1" else fb = fb .. "0" end
   if flags.RC4 then fb = fb .. "1" else fb = fb .. "0" end
   return fb
end

---
-- Takes a table representing a DNS packet to encode
-- Caution: doesn't encode answer, authority and additional part
--@param pkt Table representing DNS packet, initialized by newPacket()
--@return Encoded DNS packet
function encode(pkt)
   if type(pkt) ~= "table" then return nil end
   local encFlags = encodeFlags(pkt.flags)
   local encQs = encodeQuestions(pkt.questions)
   local encStr = bin.pack(">SBS4", pkt.id, encFlags, #pkt.questions, #pkt.answers, #pkt.auth, #pkt.additional) .. encQs
   return encStr
end


---
-- Decodes a domain in a DNS packet, 
-- handles "compressed" data, too
--@param data Complete DNS packet
--@param pos Starting position in packet
--@return Position after decoding and decoded domain
local function decStr(data, pos)
   local partlen
   local parts = {}
   local part
   pos, partlen = bin.unpack(">C", data, pos)
   while (partlen ~= 0) do
      if (partlen < 64) then 
         pos, part = bin.unpack("A" .. partlen, data, pos)
         table.insert(parts, part)
         pos, partlen = bin.unpack(">C", data, pos)
      else
         pos, partlen = bin.unpack(">S", data, pos - 1)
         local _, part = decStr(data, partlen - 0xC000 + 1)
         table.insert(parts, part)
         partlen = 0
      end
   end
   return pos, table.concat(parts, ".")
end


---
-- Decodes questions in a DNS packet
--@param data Complete DNS packet
--@param count Value of question counter in header
--@param pos Starting position in packet
--@return Position after decoding and table of decoded questions
local function decodeQuestions(data, count, pos)
   local q = {}
   for i = 1, count do
      local currQ = {}
      pos, currQ.dname = decStr(data, pos)
      pos, currQ.dtype, currQ.class = bin.unpack(">SS", data, pos)
      table.insert(q, currQ)
   end
   return pos, q
end


---
-- Table of functions to decode resource records
local decoder = {}

---
-- Decodes IP of A record, puts it in entry.ip
--@param entry RR in packet
decoder[types.A] = 
   function(entry)
      local ip = {}
      local _
      _, ip[1], ip[2], ip[3], ip[4] = bin.unpack(">C4", entry.data)
      entry.ip = table.concat(ip, ".")
   end

---
-- Decodes IP of AAAA record, puts it in entry.ipv6
--@param entry RR in packet
decoder[types.AAAA] = 
   function(entry)
      local ip = {}
      local pos = 1
      local num
      for i = 1, 8 do
         pos, num = bin.unpack(">S", entry.data, pos)
         table.insert(ip, string.format('%x', num))
      end
      entry.ipv6 = table.concat(ip, ":")
   end

---
-- Decodes ssh fingerprint record, puts it 
-- in entry.SSHFP as defined in RFC 4255:
-- .algorithm
-- .fptype
-- .fingerprint
--@param entry RR in packet
decoder[types.SSHFP] =
   function(entry)
      local _
      entry.SSHFP = {}
      _, entry.SSHFP.algorithm, 
      entry.SSHFP.fptype, entry.SSHFP.fingerprint = bin.unpack(">C2H" .. (#entry.data - 2), entry.data)
   end


---
-- Decodes SOA record, puts it in entry.SOA.*
--@param entry RR in packet
--@param data Complete encoded DNS packet
--@param pos Position in packet after RR
decoder[types.SOA] = 
   function(entry, data, pos)

      local np = pos - #entry.data

      entry.SOA = {}

      np, entry.SOA.mname = decStr(data, np)
      np, entry.SOA.rname = decStr(data, np)
      np, entry.SOA.serial, 
        entry.SOA.refresh, 
        entry.SOA.retry, 
        entry.SOA.expire, 
        entry.SOA.minimum 
         = bin.unpack(">I5", data, np)
   end

---
-- Decodes records which consist only of one domain,
-- for example CNAME, NS, PTR.
-- Puts result in entry.domain
--@param entry RR in packet
--@param data Complete encoded DNS packet
--@param pos Position in packet after RR
local function decDomain(entry, data, pos)
      local np = pos - #entry.data
      local _
      _, entry.domain = decStr(data, np)
   end

decoder[types.CNAME] = decDomain

decoder[types.NS] = decDomain

decoder[types.PTR] = decDomain

decoder[types.TXT] = function () end

---
-- Decodes MX record, puts it in entry.MX.*
--@param entry RR in packet
--@param data Complete encoded DNS packet
--@param pos Position in packet after RR
decoder[types.MX] = 
   function(entry, data, pos)
      local np = pos - #entry.data + 2
      local _
      entry.MX = {}
      _, entry.MX.pref = bin.unpack(">S", entry.data)
      _, entry.MX.server = decStr(data, np)
   end


---
-- Decodes returned resource records (answer, authority
-- or additional part).
--@param data Complete encoded DNS packet
--@param count Value of according counter in header
--@param pos Starting position in packet
--@return Table of RRs
local function decodeRR(data, count, pos)
   local ans = {}
   for i = 1, count do
      local currRR = {}
      pos, currRR.dname = decStr(data, pos)
      pos, currRR.dtype, currRR.class, currRR.ttl = bin.unpack(">SSI", data, pos)

      local reslen
      pos, reslen = bin.unpack(">S", data, pos)

      pos, currRR.data = bin.unpack("A" .. reslen, data, pos)

      -- try to be smart: decode per type
      decoder[currRR.dtype](currRR, data, pos)

      table.insert(ans, currRR)
   end
   return pos, ans
end

---
-- Splits string up into table of single characters
--@param str String to be split up
--@return Table of characters
local function str2tbl(str)
   local tbl = {}
   for i = 1, #str do
      table.insert(tbl, string.sub(str, i, i))
   end
   return tbl
end

---
-- Decodes DNS flags
--@param Flags as binary digit string
--@result Table representing flags
local function decodeFlags(flgStr)
   flags = {}
   flgTbl = str2tbl(flgStr)
   if flgTbl[1] == '1' then flags.QR = true end
   if flgTbl[2] == '1' then flags.OC1 = true end   
   if flgTbl[3] == '1' then flags.OC2 = true end
   if flgTbl[4] == '1' then flags.OC3 = true end   
   if flgTbl[5] == '1' then flags.OC4 = true end   
   if flgTbl[6] == '1' then flags.AA = true end   
   if flgTbl[7] == '1' then flags.TC = true end   
   if flgTbl[8] == '1' then flags.RD = true end   
   if flgTbl[9] == '1' then flags.RA = true end   
   if flgTbl[13] == '1' then flags.RC1 = true end   
   if flgTbl[14] == '1' then flags.RC2 = true end   
   if flgTbl[15] == '1' then flags.RC3 = true end   
   if flgTbl[16] == '1' then flags.RC4 = true end   
   return flags
end

---
-- Decodes DNS packet
--@param data Encoded DNS packet
--@result Table representing DNS packet
function decode(data)
   local pos
   local pkt = {}
   local encFlags
   local cnt = {}
   pos, pkt.id, encFlags, cnt.q, cnt.a, cnt.auth, cnt.add = bin.unpack(">SB2S4", data)
   -- for now, don't decode the flags
   pkt.flags = decodeFlags(encFlags)

   pos, pkt.questions = decodeQuestions(data, cnt.q, pos)

   pos, pkt.answers = decodeRR(data, cnt.a, pos)

   pos, pkt.auth = decodeRR(data, cnt.auth, pos)

   pos, pkt.add = decodeRR(data, cnt.add, pos)

   return pkt
end


---
-- Creates new table representing a DNS packet
--@return Table representing a DNS packet
function newPacket()
   local pkt = {}
   pkt.id = 1
   pkt.flags = {}
   pkt.flags.RD = true
   pkt.questions = {}
   pkt.answers = {}
   pkt.auth = {}
   pkt.additional = {}
   return pkt
end


---
-- Adds a question to a DNS packet table
--@param pkt Table representing DNS packet
--@param dname Domain name to be asked
--@param dtype RR to be asked
function addQuestion(pkt, dname, dtype)
   if type(pkt) ~= "table" then return nil end
   if type(pkt.questions) ~= "table" then return nil end
   local q = {}
   q.dname = dname
   q.dtype = dtype
   q.class = 1
   table.insert(pkt.questions, q)
   return pkt
end

