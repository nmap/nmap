local dns = require "dns"
local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Performs a Forward-confirmed Reverse DNS lookup and reports anomalous results.

References:
* https://en.wikipedia.org/wiki/Forward-confirmed_reverse_DNS
]]

---
-- @usage
-- nmap -sn -Pn --script fcrdns <target>
--
-- @output
-- Host script results:
-- |_fcrdns: FAIL (12.19.29.17, 12.19.20.14, 23.10.13.25)
--
-- Host script results:
-- |_fcrdns: PASS (37.58.100.86-static.reverse.softlayer.com)
--
-- Host script results:
-- | fcrdns:
-- |   <none>:
-- |     status: fail
-- |_    reason: No PTR record
--
-- Host script results:
-- | fcrdns:
-- |   mail.example.com:
-- |     status: fail
-- |     reason: FCRDNS mismatch
-- |     addresses:
-- |       12.19.29.17
-- |   mail.contoso.net:
-- |     status: fail
-- |     reason: FCRDNS mismatch
-- |     addresses:
-- |       12.19.20.14
-- |_      23.10.13.25
--
--@xmloutput
-- <table key="mail.example.com">
--   <elem key="status">fail</elem>
--   <elem key="reason">FCRDNS mismatch</elem>
--   <table key="addresses">
--     <elem>12.19.29.17</elem>
--   </table>
-- </table>
-- <table key="mail.contoso.net">
--   <elem key="status">fail</elem>
--   <elem key="reason">FCRDNS mismatch</elem>
--   <table key="addresses">
--     <elem>12.19.20.14</elem>
--     <elem>23.10.13.25</elem>
--   </table>
-- </table>

author = "Daniel Miller"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

-- not default, because user may choose -n and expect no DNS
categories = {"discovery", "safe"}


hostrule = function(host)
  -- Every host with an IP address can be checked
  return true
end

action = function(host)
  -- Do reverse-DNS lookup of the IP
  -- Can't just use host.name because some IPs have multiple PTR records
  local status, rdns = dns.query(dns.reverse(host.ip), {dtype="PTR", retAll=true})
  if not status then
    stdnse.debug("PTR request for %s failed: %s", host.ip, rdns)
    local ret = stdnse.output_table()
    ret.status = "fail"
    ret.reason = "No PTR record"
    return {["<none>"]=ret}, "FAIL (No PTR record)"
  end

  local str_out = nil
  -- Now do forward lookup of the name(s) we got
  local names = stdnse.output_table()
  local fcrdns
  local fail_addrs = {}
  local forward_type = nmap.address_family() == "inet" and "A" or "AAAA"
  local no_record_err = string.format("No %s record", forward_type)
  table.sort(rdns)
  for _, n in ipairs(rdns) do
    local name = stdnse.output_table()
    -- assume failure, we can override when/if we succeed
    name.status = "fail"
    name.reason = "FCRDNS mismatch"
    names[n] = name

    status, fcrdns = dns.query(n, {dtype=forward_type, retAll=true})
    if not status then
      stdnse.debug("%s request for %s failed: %s", forward_type, n, fcrdns)
      name.reason = no_record_err
    else
      for _, ip in ipairs(fcrdns) do
        if ipOps.compare_ip( ip, "eq", host.ip) then
          name.status = "pass"
          name.reason = nil
          str_out = string.format("PASS (%s)", n)
        end
      end
      name.addresses = fcrdns
      if name.status == "fail" then
        -- keep a list of unique addresses for short output
        for _, a in ipairs(name.addresses) do
          fail_addrs[a] = true
        end
      end
    end
  end

  if nmap.verbosity() > 0 then
    -- use default structured output for verbosity
    str_out = nil
  elseif str_out == nil then
    -- we failed, and need to format a short output string
    fail_addrs = stdnse.keys(fail_addrs)
    if #fail_addrs > 0 then
      table.sort(fail_addrs)
      str_out = string.format("FAIL (%s)", table.concat(fail_addrs, ", "))
    else
      str_out = string.format("FAIL (%s)", no_record_err)
    end
  end

  return names, str_out
end
