local dns = require "dns"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries a DNS server configured with DNSSEC and displays some parameters of a signed resource record.

DNSSEC is mainly defined in RFC 4033,4034,4035. A DNSSEC configured server must
reply with a signed resource record(RRSIG) for every RR. This script displays information
about Algorithm used in signing the record, Inception and Expiration date of signature and signer's name.
]]

---
-- @usage
-- nmap --script dnssec-check-config -p 53 <host>
-- nmap --script dnssec-check-config --script-args 'dnssec-check-config.domains={abcd.example.com, a.b.c.org},dnssec-check-config.records={SOA,DNSKEY}'-p 53 <host>
--
-- @args dnssec-check-config.domains Specify domains over which script should be run
-- @args dnssec-check-config.records Records to look for while querying DNS servers
--
-- @output
-- PORT   STATE SERVICE
-- 53/tcp open  domain
-- | dnssec-check-config: 
-- |   SOA
-- |       Algorithm: RSASHA1-NSEC3-SHA1
-- |       Signature Inception: 07/23/16 02:38:08
-- |       Signature Expiration: 08/22/16 02:38:08
-- |       Signer Name: nyc3.example.com
-- |   A
-- |       can't retrieve A record
-- |   AAAA
-- |_      can't retrieve AAAA record

author = "Abhishek Singh"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

ALGO = {
  "RSAMD5 (Not Recommended)", --1
  "DH", --2
  "DSA (Optional)",  --3
  "RESERVED", --4
  "RSASHA1 (Mandatory)",  --5
  "DSA-NSEC3-SHA1", --6
  "RSASHA1-NSEC3-SHA1",  --7
  "RSASHA256",  --8
  "RESERVED",  --9
  "RSASHA512",  --10
  "RESERVED", --11
  "ECC-GOST",  --12
  "ECDSAP256SHA256",  --13
  "ECDSAP384SHA384",  --14
}

local function get_parameters()
  local input_table = {}

  input_table.zones = stdnse.get_script_args("dnssec-check-config.domains") or "unspecified"
  if input_table.zones == "unspecified" then
    stdnse.debug(1, "warning: domain not given, script will try few random string as domain name")
    local name = stdnse.get_hostname()
    if name and name ~= host.ip then
      input_table.zones = {}
      table.insert(input_table.zones, name)
    end
  end
  if type(input_table.zones) == "string" then
    input_table.zones = {input_table.zones}
  end

  local default_list = {"SOA", "A", "AAAA"}
  input_table.records = stdnse.get_script_args("dnssec-check-config.records") or default_list
  return input_table
end

Zone = {
  
  new = function (self, domain, host)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.options = {}
    o.options.domain = domain
    o.options.host = host
    o.output = {}
    o.rrset = {}
    return o
  end,

  get_record = function(self, recordtype)
    self.rrset = {}
    local status, result = dns.query(self.options.domain, {host = self.options.host.ip, dtype=recordtype, retAll=true, retPkt=true, dnssec=true})
    if result.answers then
      for _, record in ipairs(result.answers) do
        if record[recordtype] or record.RRSIG then
          table.insert(self.rrset, record)
        end  
      end
    end

    return status
  end,

  make_output = function(self)
    local output = {}
    for _, record in ipairs(self.rrset) do
      if record.RRSIG then
        -- If it's a RRSIG for DNSKEY then we need to specify what kind of key it is.
        if record.RRSIG.typecovered == 48 then
          for _, rec in ipairs(self.rrset) do
            if rec['DNSKEY'] and rec.DNSKEY.keyTag == record.RRSIG.keytag then
              if rec.DNSKEY.flags == 256 then
                table.insert(output, "Zone signing key")
              elseif rec.DNSKEY.flags == 257 then
                table.insert(output, "Key signing key")
              else
                table.insert(output, "Unknown DNS public key")
              end
              break
            end
          end
        end

        local algo = ALGO[record.RRSIG.algorithm]
        if not algo then
          if (record.RRSIG.algorithm >= 15 and record.RRSIG.algorithm <= 122) or record.RRSIG.algorithm == 255 then
            algo = "Unassigned"
          elseif record.RRSIG.algorithm >= 123 and record.RRSIG.algorithm <= 252 then
            algo = "Reserved"
          elseif record.RRSIG.algorithm == 253 or record.RRSIG.algorithm == 254 then
            algo = "Private"
          end
        end

        table.insert(output, "Algorithm: " .. algo)
        table.insert(output, "Signature Inception: " .. os.date("%x %X", record.RRSIG.sigincept, record.RRSIG.sigincept))
        table.insert(output, "Signature Expiration: " .. os.date("%x %X", record.RRSIG.sigexpire, record.RRSIG.sigexpire))
        table.insert(output, "Signer Name: " .. record.RRSIG.signee)
      end
    end
    table.insert(self.output[#self.output], output)
  end,
}

portrule = shortport.port_or_service(53, "domain", {"tcp", "udp"})

action = function(host, port)
  local input = {}
  input = get_parameters()
  local final_output = {}
  for _, domain in pairs(input.zones) do
    table.insert(final_output, domain)
    local x = Zone:new(domain, host)
    for _, record_type in pairs(input.records) do
      local status = x:get_record(record_type)
      table.insert(x.output, record_type)
      local output={}
      if not status then
        table.insert(x.output, output)
        table.insert(x.output[#x.output], {"can't retrieve " .. record_type .. " record"})
      else
        table.insert(x.output, output)
        x:make_output()
      end
    end
    table.insert(final_output, x.output)
  end
  return stdnse.format_output(true, final_output)
end
