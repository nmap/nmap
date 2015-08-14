-- -*- mode: lua; lua-indent-level: 2; ispell-local-dictionary: "british" -*-

local dns = require "dns"
local nmap = require "nmap"
local math = require "math"
local string = require "string"
local stdnse = require "stdnse"
local shortport = require "shortport"


description = [[
Show responses to dns query, optionally limited to responses matching
certain conditions, see the report arg.
]]


---
-- @usage
-- nmap -sUS -p53 --script=dns-server -- <target>
--
-- @args
-- dns-server.name string naming domain to look up, default: nmap.org.
--
-- dns-server.type string naming type to look up, default: a.
--
-- dns-server.class string naming class to look up, default: in.
--
-- dns-server.clear-do boolean requesting that no dnssec ok (do) flag
-- should be sent in an opt pseudo rr, default false.
--
-- dns-server.clear-opt boolean requesting that no opt pseudo rr
-- should be included int the query, implies clear-do, default false.
--
-- dns-server.report string naming conditions that should cause non
-- nil report, colon separated list of one or more of these: 'ra' to
-- report answers with ra flag (recursion), 'upref' to report answers
-- over udp with upward referral, 'amp>n' to report answers over udp
-- with bandwidth amplification factor greater than n (an integer).
--
-- @output
-- PORT   STATE SERVICE
-- 53/tcp open  domain
-- | dns-server:
-- |   status: noerror (0)
-- |   id: 31530
-- |   flags: qr rd ra
-- |   rr counts: query: 1, answer: 1, authority: 0, additional: 1
-- |   opt pseudosection:
-- |     edns: version: 0, flags: do, udp: 4096
-- |   question section:
-- |     nmap.org.                    IN      A
-- |   answer section:
-- |_    nmap.org.            3562    IN      A       45.33.49.119
-- 53/udp open  domain
-- | dns-server:
-- |   payload amplification: 53/37=1.4
-- |   status: noerror (0)
-- |   id: 63004
-- |   flags: qr rd ra
-- |   rr counts: query: 1, answer: 1, authority: 0, additional: 1
-- |   opt pseudosection:
-- |     edns: version: 0, flags: do, udp: 4096
-- |   question section:
-- |     nmap.org.                    IN      A
-- |   answer section:
-- |_    nmap.org.            3562    IN      A       45.33.49.119
--
-- @xmloutput
-- <ports>
--   <port protocol="tcp" portid="53">
--     <state state="open" reason="syn-ack" reason_ttl="62"/>
--     <service name="domain" method="table" conf="3"/>
--     <script id="dns-server" output="See @output.">
--       <elem key="status">noerror (0)</elem>
--       <elem key="id">31530</elem>
--       <elem key="flags">qr rd ra</elem>
--       <elem key="rr counts">query: 1, answer: 1, authority: 0, additional: 1</elem>
--       <table key="opt pseudosection">
--         <elem>edns: version: 0, flags: do, udp: 4096</elem>
--       </table>
--       <table key="question section">
--         <elem>nmap.org.                    IN      A</elem>
--       </table>
--       <table key="answer section">
--         <elem>nmap.org.            3562    IN      A       45.33.49.119</elem>
--       </table>
--     </script>
--   </port>
--   <port protocol="udp" portid="53">
--     <state state="open" reason="udp-response" reason_ttl="62"/>
--     <service name="domain" method="table" conf="3"/>
--     <script id="dns-server" output="See @output.">
--       <elem key="payload amplification">53/37=1.4</elem>
--       <elem key="status">noerror (0)</elem>
--       <elem key="id">63004</elem>
--       <elem key="flags">qr rd ra</elem>
--       <elem key="rr counts">query: 1, answer: 1, authority: 0, additional: 1</elem>
--       <table key="opt pseudosection">
--         <elem>edns: version: 0, flags: do, udp: 4096</elem>
--       </table>
--       <table key="question section">
--         <elem>nmap.org.                    IN      A</elem>
--       </table>
--       <table key="answer section">
--         <elem>nmap.org.            3562    IN      A       45.33.49.119</elem>
--       </table>
--     </script>
--   </port>
-- </ports>


categories = { "default", "discovery", "safe" }
author = "Ulrik Haugen"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

-- https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml

portrule = shortport.service('domain', { 'udp', 'tcp' })


--- Like assert but put /message/ in the ERROR key in /results_table/ to
-- better suit collate_results and pass 0 as level to error to ensure
-- the error message will not be prefixed with file and line number.
-- /results_table/ may be left out.
local function assert_w_table(condition, message, results_table)
  if condition then
    return condition
  else
    results_table = results_table or {}
    results_table.ERROR = message
    error(results_table, 0)
  end
end


--- Return sorted keys of /tab/.
local function sorted_keys(tab)
  local keys = {}
  for key in pairs(tab) do
    keys.insert(key)
  end
  table.sort(keys)
  return keys
end


--- Computed tables.
local class_by_id = {}
local type_by_id = {}
local rcode_by_id = {}


--- Constants.
local short_max = (1 << 16) - 1


--- Return string listing flags set in /flags/ ordered as in
-- /flags_order/ and lower cased.
local function list_flags(flags, flags_order)
  local flags_list = ''
  for idx, flag in pairs(flags_order) do
    if flags[flag] then
      flags_list = flags_list .. flag:lower() .. ' '
    end
  end
  return flags_list:sub(1, -2)
end


--- Translate /rcode/ to status string.
local function status_for_rcode(rcode)
  return ("%s (%u)"):format(rcode_by_id[rcode], rcode)
end


--- Formatter for cname, ns and ptr rr.
local function domain_formatter(rr)
  return ("%s."):format(rr.domain)
end


--- Formatter for soa rr.
local function soa_formatter(rr)
  return ("%s. %s. %u %u %u %u %u"):format(
    rr.SOA.mname, rr.SOA.rname, rr.SOA.serial, rr.SOA.refresh,
    rr.SOA.retry, rr.SOA.expire, rr.SOA.minimum)
end


--- Formatters for an rr indexed by rr type value.
local formatter_by_dtype = {
  [ dns.types.A ] = function(rr) return rr.ip end,
  [ dns.types.AAAA ] = function(rr) return rr.ipv6 end,
  [ dns.types.SSHFP ] = function(rr) return ("%u %s"):format(
      rr.SSHFP.fptype, rr.SSHFP.fingerprint) end,
  [ dns.types.SOA ] = soa_formatter,
  [ dns.types.NSEC ] = function(rr) return ("%s. %s. %s"):format(
      rr.NSEC.dname, rr.NSEC.next_dname,
      sorted_keys(rr.NSEC.types)) end,
  [ dns.types.NSEC3 ] = function(rr) return ("%s. %u %s %s"):format(
      rr.NSEC3.dname, rr.NSEC3.hash.alg,
      rr.NSEC3.hash.base32, rr.NSEC3.salt.hex) end,
  [ dns.types.CNAME ] = domain_formatter,
  [ dns.types.NS ] = domain_formatter,
  [ dns.types.PTR ] = domain_formatter,
  [ dns.types.TXT ] = function(rr) return ('"%s"'):format(
      table.concat(rr.TXT.text, '" "')) end,
  [ dns.types.MX ] = function(rr) return ("%u %s."):format(
      rr.MX.pref, rr.MX.server) end,
  [ dns.types.SRV ] = function(rr) return ("%u %u %u %s."):format(
      rr.SRV.prio, rr.SRV.weight, rr.SRV.port,
      rr.SRV.target) end,
}


--- Return /rr/ as string of dname, ttl, class and type and rrdata.
--
-- Formatted according to formatter_by_dtype or just type number,
-- rdata length and rdata in hex.
local function answer_by_dtype(rr)
  if formatter_by_dtype[rr.dtype] then
    return ("%-20s %-7d %-7s %-7s %s"):format(
      rr.dname .. '.', rr.ttl,
      class_by_id[rr.class],
      type_by_id[rr.dtype],
      formatter_by_dtype[rr.dtype](rr))
  else
    local unpacked_data, len = string.unpack("c" .. rr.data:len(), rr.data)
    return ("%-20s %-7d %-7s unparsed_type(%u, %u, %s)"):format(
      rr.dname .. '.', rr.ttl,
      class_by_id[rr.class],
      rr.dtype,
      len,
      stdnse.tohex(unpacked_data))
  end
end


--- Decode opt pseudo rr, rfc 6891.
local function decode_opt(rr)
  local do_bit = 1 << 15
  local opt = { ext_rcode = rr.OPT.rcode,
                version = rr.OPT.version,
                flags = { DO = (rr.OPT.zflags & do_bit) ~= 0, },
                zflags = rr.OPT.zflags & ~do_bit,
                max_udp_pl = rr.OPT.bufsize,
                rdlen = #rr.OPT.data,
                rdata = rr.OPT.data, }
  return opt
end


--- Check /response/ for ra flag and nonempty answer section. Return a
-- boolean.
local function has_ra_flag_and_answers(_, port, response)
  return response.flags.RA and #response.answers > 0
end


--- Check udp /response/ for upward referrals. Return a boolean.
--
-- https://www.dns-oarc.net/oarc/articles/upward-referrals-considered-harmful
local function has_upref(_, port, response)
  if port.protocol ~= 'udp' then
    return false
  end
  local root_server_name_pattern = '%.root%-servers%.net$'
  local idx, rr
  for idx, rr in ipairs(response.auth) do
    if (rr.dtype == dns.types.NS
        and rr.domain:lower():match(root_server_name_pattern)) then
      return true
    end
  end
  for idx, rr in ipairs(response.add) do
    if ((rr.dtype == dns.types.A or rr.dtype == dns.types.AAAA)
      and rr.dname:lower():match(root_server_name_pattern)) then
      return true
    end
  end
  return false
end

--- Check udp /response/ for amplification factor greater than
-- /limit/. Return a boolean.
local function has_amp_gt(limit, port, response)
  if port.protocol ~= 'udp' then
    return false
  end
  assert_w_table(limit > 0, ("Invalid limit for report.amp>: %s"):format(limit))
  return response.response_pl_len / response.query_pl_len > limit
end


--- Parse /report_arg/ and return an object to help with testing
-- port/response.
local function parse_report_arg(report_arg)
  local report_response = {
    __conds = {},
    __order = {},
    __enabled = {},
    --- Define /condition/ with /reason/ and /test/.
    define = function(ct, condition, reason, test)
      ct.__conds[condition] = { reason = reason, test = test, }
      table.insert(ct.__order, condition)
    end,
    --- Enable /condition/.
    enable = function(ct, condition, limit)
      ct.__enabled[condition] = true
      ct.__conds[condition].limit = limit
      return ct.__conds[condition] ~= nil
    end,
    --- Return true if no conditions are enabled, false otherwise.
    empty = function(ct)
      return next(ct.__enabled) == nil
    end,
    --- Iterate over enabled conditions in the order they were
    --- defined, yield reason and test for each condition.
    enabled_conditions = function(ct)
      return coroutine.wrap(
        function()
          local idx, condition
          for idx, condition in ipairs(ct.__order) do
            if ct.__enabled[condition] then
              coroutine.yield(ct.__conds[condition])
            end
          end
        end)
    end,
  }
  -- Define conditions in decreasing order of severity.
  report_response:define('amp>', "amplification", has_amp_gt)
  report_response:define('ra', "recursion", has_ra_flag_and_answers)
  report_response:define('upref', "upwards referral", has_upref)

  if report_arg then
    local label, limit
    for label, limit in report_arg:gmatch('(%w+[>]?)(%d*)') do
      assert_w_table(report_response:enable(label, tonumber(limit)),
                     "Unrecognised condition: " .. label)
    end
  end

  return report_response
end


--- Query dns-server on /host/, /port/ for /qname/, /qclass_raw/,
-- /qtype_raw/, limiting responses according to /report_raw/. Returns
-- an output_table.
local function query_server(host, port,
                            qname, qclass_raw, qtype_raw,
                            clear_do, clear_opt,
                            report_raw)
  local qclass = dns.CLASS[qclass_raw:upper()]
  assert_w_table(qclass, "Invalid class: " .. qclass_raw)
  local qtype = dns.types[qtype_raw:upper()]
  assert_w_table(qtype, "Invalid type: " .. qtype_raw)
  local report_response = parse_report_arg(report_raw)

  local query_table = dns.newPacket()
  query_table.opcode = dns.opcodes.query
  dns.addQuestion(query_table, qname, qtype, qclass)
  if not clear_opt then
    dns.addOPT(query_table, { DO = not clear_do, })
  end
  query_table.id = math.random(0, short_max)
  local query_pl = dns.encode(query_table)
  local status, response_or_error = dns.sendPackets(
    query_pl, host.ip, port.number,
    dns.get_default_timeout(),
    2,     -- maximum send count for udp
    false, -- don't expect multiple responses
    port.protocol)
  assert_w_table(status, response_or_error)
  nmap.set_port_state(host, port, 'open')
  local response_info = stdnse.output_table()

  assert_w_table(#response_or_error == 1, "unexpected response count")
  local response_table = dns.decode(response_or_error[1].data)
  response_table.query_pl_len = query_pl:len()
  response_table.response_pl_len = response_or_error[1].data:len()

  if not report_response:empty() then
    local condition
    for condition in report_response:enabled_conditions() do
      if condition.test(condition.limit, port, response_table) then
        response_info["reported for"] = condition.reason
        break
      end
    end
    assert_w_table(response_info["reported for"],
                   "Response matches no conditions in "
                     .. SCRIPT_NAME .. ".report: "
                     .. report_raw:gsub(':', ', '),
                   response_info)
  end

  if port.protocol == 'udp' then
    response_info['payload amplification'] = ("%u/%u=%.1f"):format(
      response_table.response_pl_len, response_table.query_pl_len,
      response_table.response_pl_len / response_table.query_pl_len)
  end

  response_info.status = ''
  response_info.id = response_table.id

  local rcode = response_table.rcode
  local idx, question, answer, section
  response_info.flags = list_flags(response_table.flags,
                                   { 'QR', 'AA', 'TC', 'RD', 'RA',
                                     'Z', 'AD', 'CD', })
  response_info['rr counts'] = (
    "query: %u, answer: %u, authority: %u, additional: %u"):format(
    #response_table.questions, #response_table.answers,
    #response_table.auth, #response_table.add)
  response_info['opt pseudosection'] = {}

  response_info["question section"] = {}
  for idx, question in pairs(response_table.questions) do
    table.insert(response_info["question section"],
                 ("%-28s %-7s %s"):format(
                   question.dname .. '.', class_by_id[question.class],
                   type_by_id[question.dtype]))
  end

  local opt = nil
  for idx, section in pairs({
      { key = 'answers', label = "answer section" },
      { key = 'auth', label = "authority section" },
      { key = 'add', label = "additional section" }, }) do
    for idx, rr in pairs(response_table[section.key]) do
      if idx == 1 then
        response_info[section.label] = {}
      end
      if section.key == 'add' and rr.dtype == dns.types.OPT then
        opt = decode_opt(rr)
      else
        table.insert(response_info[section.label], answer_by_dtype(rr))
      end
    end
  end

  if opt then
    rcode = (opt.ext_rcode << 4) + rcode
    table.insert(response_info['opt pseudosection'],
                 ("edns: version: %u, flags: %s, udp: %u"):format(
                   opt.version, list_flags(opt.flags, { 'DO', }),
                   opt.max_udp_pl))
    if opt.zflags ~= 0 then
      table.insert(response_info['opt pseudosection'],
                   ("undecoded z flags: %x"):format(opt.zflags))
    end
    if opt.rdlen > 0 then
      -- rudimentary presentation
      table.insert(response_info['opt pseudosection'],
                   ("rdlen: %u, rdata: %s"):format(opt.rdlen, opt.rdata))
    end
  else
    response_info['opt pseudosection'] = nil
  end
  response_info.status = status_for_rcode(rcode)

  -- Remove empty sections.
  if (response_info['additional section'] ~= nil
      and next(response_info['additional section'])) == nil then
    response_info['additional section'] = nil
  end

  return response_info
end


--- Return /results_table/ unless contraindicated by /status/ and
-- debugging being false.
local function collate_results(status, results_table)
  if not status and nmap.debugging() < 1 then
    return nil
  end
  return results_table
end


--- Nmap entry point.
function action(host, port)
  -- Define global computed tables.
  local class, dtype, id
  for class, id in pairs(dns.CLASS) do
    class_by_id[id] = class
  end
  for dtype, id in pairs(dns.types) do
    type_by_id[id] = dtype
  end
  for rcode, id in pairs(dns.rcodes) do
    rcode_by_id[id] = rcode
  end

  -- Get script args.

  -- nmap.org selected as default name for two reasons:
  -- * it should be registered for the service life of this script
  -- * whoever scans the nmap.org datacenter for open resolvers should
  --   be the last to have trouble with supplying script args
  local qname = stdnse.get_script_args(
    SCRIPT_NAME .. ".name") or 'nmap.org'
  local qtype = stdnse.get_script_args(
    SCRIPT_NAME .. ".type") or 'a'
  local qclass = stdnse.get_script_args(
    SCRIPT_NAME .. ".class") or 'in'
  local clear_do = stdnse.get_script_args(
    SCRIPT_NAME .. ".clear-do")
  local clear_opt = stdnse.get_script_args(
    SCRIPT_NAME .. ".clear-opt")
  local report = stdnse.get_script_args(
    SCRIPT_NAME .. ".report")

  -- Dispatch.
  return collate_results(pcall(query_server, host, port,
                               qname, qclass, qtype,
                               clear_do, clear_opt,
                               report))
end
