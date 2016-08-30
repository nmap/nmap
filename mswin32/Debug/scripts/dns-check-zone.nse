local dns = require "dns"
local stdnse = require "stdnse"
local table = require "table"
local ipOps = require "ipOps"

description = [[
Checks DNS zone configuration against best practices, including RFC 1912.
The configuration checks are divided into categories which each have a number
of different tests.
]]

---
-- @usage
-- nmap -sn -Pn ns1.example.com --script dns-check-zone --script-args='dns-check-zone.domain=example.com'
--
-- @output
-- | dns-check-zone:
-- | DNS check results for domain: example.com
-- |   SOA
-- |     PASS - SOA REFRESH
-- |       SOA REFRESH was within recommended range (7200s)
-- |     PASS - SOA RETRY
-- |       SOA RETRY was within recommended range (3600s)
-- |     PASS - SOA EXPIRE
-- |       SOA EXPIRE was within recommended range (1209600s)
-- |     FAIL - SOA MNAME entry check
-- |       SOA MNAME record is NOT listed as DNS server
-- |     PASS - Zone serial numbers
-- |       Zone serials match
-- |   MX
-- |     ERROR - Reverse MX A records
-- |       Failed to retrieve list of mail servers
-- |   NS
-- |     PASS - Recursive queries
-- |       None of the servers allow recursive queries.
-- |     PASS - Multiple name servers
-- |       Server has 2 name servers
-- |     PASS - DNS name server IPs are public
-- |       All DNS IPs were public
-- |     PASS - DNS server response
-- |       All servers respond to DNS queries
-- |     PASS - Missing nameservers reported by parent
-- |       All DNS servers match
-- |     PASS - Missing nameservers reported by your nameservers
-- |_      All DNS servers match
--
-- @args dns-check-zone.domain the dns zone to check
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "external"}

local arg_domain = stdnse.get_script_args(SCRIPT_NAME .. '.domain')


hostrule = function(host) return ( arg_domain ~= nil ) end

local PROBE_HOST = "scanme.nmap.org"

local Status = {
  PASS = "PASS",
  FAIL = "FAIL",
}

local function isValidSOA(res)
  if ( not(res) or type(res.answers) ~= "table" or type(res.answers[1].SOA) ~= "table" ) then
    return false
  end
  return true
end

local dns_checks = {

  ["NS"] = {
    {
      desc = "Recursive queries",
      func = function(domain, server)
        local status, res = dns.query(domain, { host = server, dtype='NS', retAll = true })
        local result = {}

        if ( not(status) ) then
          return false, "Failed to retrieve list of DNS servers"
        end
        for _, srv in ipairs(res or {}) do
          local status, res = dns.query(PROBE_HOST, { host = srv, dtype='A' })
          if ( status ) then
            table.insert(result, res)
          end
        end

        local output = "None of the servers allow recursive queries."
        if ( 0 < #result ) then
          output = ("The following servers allow recursive queries: %s"):format(stdnse.strjoin(", ", result))
          return true, { status = Status.FAIL, output = output }
        end
        return true, { status = Status.PASS, output = output }
      end
    },

    {
      desc = "Multiple name servers",
      func = function(domain, server)
        local status, res = dns.query(domain, { host = server, dtype='NS', retAll = true })

        if ( not(status) ) then
          return false, "Failed to retrieve list of DNS servers"
        end

        local status = Status.FAIL
        if ( 1 < #res ) then
          status = Status.PASS
        end
        return true, { status = status, output = ("Server has %d name servers"):format(#res) }
      end
    },

    {
      desc = "DNS name server IPs are public",
      func = function(domain, server)

        local status, res = dns.query(domain, { host = server, dtype='NS', retAll = true })
        if ( not(status) ) then
          return false, "Failed to retrieve list of DNS servers"
        end

        local result = {}
        for _, srv in ipairs(res or {}) do
          local status, res = dns.query(srv, { dtype='A', retAll = true })
          if ( not(status) ) then
            return false, ("Failed to retrieve IP for DNS: %s"):format(srv)
          end
          for _, ip in ipairs(res) do
            if ( ipOps.isPrivate(ip) ) then
              table.insert(result, ip)
            end
          end
        end

        local output = "All DNS IPs were public"
        if ( 0 < #result ) then
          output = ("The following private IPs were detected: %s"):format(stdnse.strjoin(", ", result))
          status = Status.FAIL
        else
          status = Status.PASS
        end

        return true, { status = status, output = output }
      end
    },

    {
      desc = "DNS server response",
      func = function(domain, server)
        local status, res = dns.query(domain, { host = server, dtype='NS', retAll = true })
        if ( not(status) ) then
          return false, "Failed to retrieve list of DNS servers"
        end

        local result = {}
        for _, srv in ipairs(res or {}) do
          local status, res = dns.query(domain, { host = srv, dtype='SOA', retPkt = true })
          if ( not(status) ) then
            table.insert(result, res)
          end
        end

        local output = "All servers respond to DNS queries"
        if ( 0 < #result ) then
          output = ("The following servers did not respond to DNS queries: %s"):format(stdnse.strjoin(", ", result))
          return true, { status = Status.FAIL, output = output }
        end
        return true, { status = Status.PASS, output = output }
      end
    },

    {
      desc = "Missing nameservers reported by parent",
      func = function(domain, server)
        local tld = domain:match("%.(.*)$")
        local status, res = dns.query(tld, { dtype = "NS", retAll = true })
        if ( not(status) ) then
          return false, "Failed to retrieve list of TLD DNS servers"
        end

        local status, parent_res = dns.query(domain, { host = res, dtype = "NS", retAll = true, retPkt = true, noauth = true } )
        if ( not(status) ) then
          return false, "Failed to retrieve a list of parent DNS servers"
        end

        if ( not(status) or not(parent_res) or type(parent_res.auth) ~= "table"  ) then
          return false, "Failed to retrieve a list of parent DNS servers"
        end

        local parent_dns = {}
        for _, auth in ipairs(parent_res.auth) do
          parent_dns[auth.domain] = true
        end

        status, res = dns.query(domain, { host = server, dtype = "NS", retAll = true } )
        if ( not(status) ) then
          return false, "Failed to retrieve a list of DNS servers"
        end

        local domain_dns = {}
        for _,srv in ipairs(res) do domain_dns[srv] = true end

        local result = {}
        for srv in pairs(domain_dns) do
          if ( not(parent_dns[srv]) ) then
            table.insert(result, srv)
          end
        end

        if ( 0 < #result ) then
          local output = ("The following servers were found in the zone, but not in the parent: %s"):format(stdnse.strjoin(", ", result))
          return true, { status = Status.FAIL, output = output }
        end

        return true, { status = Status.PASS, output = "All DNS servers match" }
      end,
    },


    {
      desc = "Missing nameservers reported by your nameservers",
      func = function(domain, server)
        local tld = domain:match("%.(.*)$")
        local status, res = dns.query(tld, { dtype = "NS", retAll = true })
        if ( not(status) ) then
          return false, "Failed to retrieve list of TLD DNS servers"
        end

        local status, parent_res = dns.query(domain, { host = res, dtype = "NS", retAll = true, retPkt = true, noauth = true } )
        if ( not(status) ) then
          return false, "Failed to retrieve a list of parent DNS servers"
        end

        if ( not(status) or not(parent_res) or type(parent_res.auth) ~= "table"  ) then
          return false, "Failed to retrieve a list of parent DNS servers"
        end

        local parent_dns = {}
        for _, auth in ipairs(parent_res.auth) do
          parent_dns[auth.domain] = true
        end

        status, res = dns.query(domain, { host = server, dtype = "NS", retAll = true } )
        if ( not(status) ) then
          return false, "Failed to retrieve a list of DNS servers"
        end

        local domain_dns = {}
        for _,srv in ipairs(res) do  domain_dns[srv] = true end

        local result = {}
        for srv in pairs(parent_dns) do
          if ( not(domain_dns[srv]) ) then
            table.insert(result, srv)
          end
        end

        if ( 0 < #result ) then
          local output = ("The following servers were found in the parent, but not in the zone: %s"):format(stdnse.strjoin(", ", result))
          return true, { status = Status.FAIL, output = output }
        end

        return true, { status = Status.PASS, output = "All DNS servers match" }
      end,
    },

  },

  ["SOA"] =
  {
    {
      desc = "SOA REFRESH",
      func = function(domain, server)
        local status, res = dns.query(domain, { host = server, dtype='SOA', retPkt=true })
        if ( not(status) or not(isValidSOA(res)) ) then
          return false, "Failed to retrieve SOA record"
        end

        local refresh = tonumber(res.answers[1].SOA.refresh)
        if ( not(refresh) ) then
          return false, "Failed to retrieve SOA REFRESH"
        end

        if ( refresh < 1200 or refresh > 43200 ) then
          return true, { status = Status.FAIL, output = ("SOA REFRESH was NOT within recommended range (%ss)"):format(refresh) }
        else
          return true, { status = Status.PASS, output = ("SOA REFRESH was within recommended range (%ss)"):format(refresh) }
        end
      end
    },

    {
      desc = "SOA RETRY",
      func = function(domain, server)
        local status, res = dns.query(domain, { host = server, dtype='SOA', retPkt=true })
        if ( not(status) or not(isValidSOA(res)) ) then
          return false, "Failed to retrieve SOA record"
        end

        local retry = tonumber(res.answers[1].SOA.retry)
        if ( not(retry) ) then
          return false, "Failed to retrieve SOA RETRY"
        end

        if ( retry < 180 ) then
          return true, { status = Status.FAIL, output = ("SOA RETRY was NOT within recommended range (%ss)"):format(retry) }
        else
          return true, { status = Status.PASS, output = ("SOA RETRY was within recommended range (%ss)"):format(retry) }
        end
      end
    },

    {
      desc = "SOA EXPIRE",
      func = function(domain, server)
        local status, res = dns.query(domain, { host = server, dtype='SOA', retPkt=true })
        if ( not(status) or not(isValidSOA(res)) ) then
          return false, "Failed to retrieve SOA record"
        end

        local expire = tonumber(res.answers[1].SOA.expire)
        if ( not(expire) ) then
          return false, "Failed to retrieve SOA EXPIRE"
        end

        if ( expire < 1209600 or expire > 2419200 ) then
          return true, { status = Status.FAIL, output = ("SOA EXPIRE was NOT within recommended range (%ss)"):format(expire) }
        else
          return true, { status = Status.PASS, output = ("SOA EXPIRE was within recommended range (%ss)"):format(expire) }
        end
      end
    },

    {
      desc = "SOA MNAME entry check",
      func = function(domain, server)
        local status, res = dns.query(domain, { host = server, dtype='SOA', retPkt=true })
        if ( not(status) or not(isValidSOA(res)) ) then
          return false, "Failed to retrieve SOA record"
        end
        local mname = res.answers[1].SOA.mname

        status, res = dns.query(domain, { host = server, dtype='NS', retAll = true })
        if ( not(status) ) then
          return false, "Failed to retrieve list of DNS servers"
        end

        for _, srv in ipairs(res or {}) do
          if ( srv == mname ) then
            return true, { status = Status.PASS, output = "SOA MNAME record is listed as DNS server" }
          end
        end
        return true, { status = Status.FAIL, output = "SOA MNAME record is NOT listed as DNS server" }
      end
    },

    {
      desc = "Zone serial numbers",
      func = function(domain, server)
        local status, res = dns.query(domain, { host = server, dtype='NS', retAll = true })
        if ( not(status) ) then
          return false, "Failed to retrieve list of DNS servers"
        end

        local result = {}
        local serial

        for _, srv in ipairs(res or {}) do
          local status, res = dns.query(domain, { host = srv, dtype='SOA', retPkt = true })
          if ( not(status) or not(isValidSOA(res)) ) then
            return false, "Failed to retrieve SOA record"
          end

          local s = res.answers[1].SOA.serial
          if ( not(serial) ) then
            serial = s
          elseif( serial ~= s ) then
            return true, { status = Status.FAIL, output = "Different zone serials were detected" }
          end
        end

        return true, { status = Status.PASS, output = "Zone serials match" }
      end,
    },
  },

  ["MX"] = {

    {
      desc = "Reverse MX A records",
      func = function(domain, server)
        local status, res = dns.query(domain, { host = server, dtype='MX', retAll = true })
        if ( not(status) ) then
          return false, "Failed to retrieve list of mail servers"
        end

        local result = {}
        for _, record in ipairs(res or {}) do
          local prio, mx = record:match("^(%d*):([^:]*)")
          local ips
          status, ips = dns.query(mx, { dtype='A', retAll=true })
          if ( not(status) ) then
            return false, "Failed to retrieve A records for MX"
          end

          for _, ip in ipairs(ips) do
            local status, res = dns.query(dns.reverse(ip), { dtype='PTR' })
            if ( not(status) ) then
              table.insert(result, ip)
            end
          end
        end

        local output = "All MX records have PTR records"
        if ( 0 < #result ) then
          output = ("The following IPs do not have PTR records: %s"):format(stdnse.strjoin(", ", result))
          return true, { status = Status.FAIL, output = output }
        end
        return true, { status = Status.PASS, output = output }
      end
    },

  }
}

action = function(host, port)
  local server = host.ip
  local output = { name = ("DNS check results for domain: %s"):format(arg_domain) }

  for group in pairs(dns_checks) do
    local group_output = { name = group }
    for _, check in ipairs(dns_checks[group]) do
      local status, res = check.func(arg_domain, server)
      if ( status ) then
        local test_res = ("%s - %s"):format(res.status, check.desc)
        table.insert(group_output, { name = test_res, res.output })
      else
        local test_res = ("ERROR - %s"):format(check.desc)
        table.insert(group_output, { name = test_res, res })
      end
    end
    table.insert(output, group_output)
  end
  return stdnse.format_output(true, output)
end
