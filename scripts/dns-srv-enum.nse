local coroutine = require "coroutine"
local dns = require "dns"
local nmap = require "nmap"
local stdnse = require "stdnse"
local tab = require "tab"
local table = require "table"
local target = require "target"

description = [[
Enumerates various common service (SRV) records for a given domain name.
The service records contain the hostname, port and priority of servers for a given service.
The following services are enumerated by the script:
  - Active Directory Global Catalog
  - Exchange Autodiscovery
  - Kerberos KDC Service
  - Kerberos Passwd Change Service
  - LDAP Servers
  - SIP Servers
  - XMPP S2S
  - XMPP C2S
]]

---
-- @usage
-- nmap --script dns-srv-enum --script-args "dns-srv-enum.domain='example.com'"
--
-- @output
-- | dns-srv-enum:
-- |   Active Directory Global Catalog
-- |     service   prio  weight  host
-- |     3268/tcp  0     100     stodc01.example.com
-- |   Kerberos KDC Service
-- |     service  prio  weight  host
-- |     88/tcp   0     100     stodc01.example.com
-- |     88/udp   0     100     stodc01.example.com
-- |   Kerberos Password Change Service
-- |     service  prio  weight  host
-- |     464/tcp  0     100     stodc01.example.com
-- |     464/udp  0     100     stodc01.example.com
-- |   LDAP
-- |     service  prio  weight  host
-- |     389/tcp  0     100     stodc01.example.com
-- |   SIP
-- |     service   prio  weight  host
-- |     5060/udp  10    50      vclux2.example.com
-- |     5070/udp  10    50      vcbxl2.example.com
-- |     5060/tcp  10    50      vclux2.example.com
-- |     5060/tcp  10    50      vcbxl2.example.com
-- |   XMPP server-to-server
-- |     service   prio  weight  host
-- |     5269/tcp  5     0       xmpp-server.l.example.com
-- |     5269/tcp  20    0       alt2.xmpp-server.l.example.com
-- |     5269/tcp  20    0       alt4.xmpp-server.l.example.com
-- |     5269/tcp  20    0       alt3.xmpp-server.l.example.com
-- |_    5269/tcp  20    0       alt1.xmpp-server.l.example.com
--
-- @args dns-srv-enum.domain string containing the domain to query
-- @args dns-srv-enum.filter string containing the service to query
--       (default: all)

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


local arg_domain = stdnse.get_script_args(SCRIPT_NAME .. ".domain")
local arg_filter = stdnse.get_script_args(SCRIPT_NAME .. ".filter")

prerule = function() return not(not(arg_domain)) end

local function parseSvcList(services)
  local i = 1
  return function()
    local svc = services[i]
    if ( svc ) then
      i=i + 1
    else
      return
    end
    return svc.name, svc.query
  end
end

local function parseSrvResponse(resp)
  local i = 1
  if ( resp.answers ) then
    table.sort(resp.answers,
      function(a, b)
        if ( a.SRV and b.SRV and a.SRV.prio and b.SRV.prio ) then
          return a.SRV.prio < b.SRV.prio
        end
      end
    )
  end
  return function()
    if ( not(resp.answers) or 0 == #resp.answers ) then  return end
    if ( not(resp.answers[i]) ) then
      return
    elseif ( resp.answers[i].SRV ) then
      local srv = resp.answers[i].SRV
      i = i + 1
      return srv.target, srv.port, srv.prio, srv.weight
    end
  end
end

local function checkFilter(services)
  if ( not(arg_filter) or "" == arg_filter or "all" == arg_filter ) then
    return true
  end
  for name, queries in parseSvcList(services) do
    if ( name == arg_filter ) then
      return true
    end
  end
  return false
end

local function doQuery(name, queries, result)
  local condvar = nmap.condvar(result)
  local svc_result = tab.new(4)
  tab.addrow(svc_result, "service", "prio", "weight", "host")
  for _, query in ipairs(queries) do
    local fqdn = ("%s.%s"):format(query, arg_domain)
    local status, resp = dns.query(fqdn, { dtype="SRV", retAll=true, retPkt=true } )
    for host, port, prio, weight in parseSrvResponse(resp) do
      if target.ALLOW_NEW_TARGETS then
        target.add(host)
      end
      local proto = query:sub(-3)
      tab.addrow(svc_result, ("%d/%s"):format(port, proto), prio, weight, host)
    end
  end
  if ( #svc_result ~= 1 ) then
    table.insert(result, { name = name, tab.dump(svc_result) })
  end
  condvar "signal"
end

action = function(host)

  local services = {
    { name = "CalDAV (_caldav._tcp)", query = {"_caldav._tcp"} },
    { name = "CalDAV (_caldavs._tcp)", query = {"_caldavs._tcp"} },
    { name = "Ceph (_ceph._tcp)", query = {"_ceph._tcp"} },
    { name = "Ceph (_ceph-mon._tcp)", query = {"_ceph-mon._tcp"} },
    { name = "WWW (_www._tcp)", query = {"_www._tcp"} },
    { name = "HTTP (_http._tcp)", query = {"_http._tcp"} },
    { name = "HTTP (_www-http._tcp)", query = {"_www-http._tcp"} },
    { name = "HTTP (_http._sctp)", query = {"_http._sctp"} },
    { name = "SMTP (_smtp._tcp)", query = {"_smtp._tcp"} },
    { name = "SMTP (_smtp._udp)", query = {"_smtp._udp"} },
    { name = "Submission (_submission._tcp)", query = {"_submission._tcp"} },
    { name = "Submission (_submission._udp)", query = {"_submission._udp"} },
    { name = "Submission (_submissions._tcp)", query = {"_submissions._tcp"} },
    { name = "POP2 (_pop2._tcp)", query = {"_pop2._tcp"} },
    { name = "POP2 (_pop2._udp)", query = {"_pop2._udp"} },
    { name = "POP3 (_pop3._tcp)", query = {"_pop3._tcp"} },
    { name = "POP3 (_pop3._udp)", query = {"_pop3._udp"} },
    { name = "POP (_hybrid-pop._tcp)", query = {"_hybrid-pop._tcp"} },
    { name = "POP (_hybrid-pop._udp)", query = {"_hybrid-pop._udp"} },
    { name = "POP3 (_pop3s._tcp)", query = {"_pop3s._tcp"} },
    { name = "POP3 (_pop3s._udp)", query = {"_pop3s._udp"} },
    { name = "IMAP (_imap._tcp)", query = {"_imap._tcp"} },
    { name = "IMAP (_imap._udp)", query = {"_imap._udp"} },
    { name = "IMAP3 (_imap3._tcp)", query = {"_imap3._tcp"} },
    { name = "IMAP3 (_imap3._udp)", query = {"_imap3._udp"} },
    { name = "IMAPS (_imaps._tcp)", query = {"_imaps._tcp"} },
    { name = "IMAPS (_imaps._udp)", query = {"_imaps._udp"} },
    { name = "Host Identity Protocol (_hip-nat-t._udp)", query = {"_hip-nat-t._udp"} },
    { name = "Kerberos KDC Service (_kerberos._tcp)", query = {"_kerberos._tcp"} },
    { name = "Kerberos (_kerberos._udp)", query = {"_kerberos._udp"} },
    { name = "Kerberos (_kerberos-master._tcp)", query = {"_kerberos-master._tcp"} },
    { name = "Kerberos (_kerberos-master._udp)", query = {"_kerberos-master._udp"} },
    { name = "Kerberos Password Change Service( _kpasswd._tcp)", query = {"_kpasswd._tcp"} },
    { name = "Kerberos Password Change Service (_kpasswd._udp)", query = {"_kpasswd._udp"} },
    { name = "Kerberos (_kerberos-adm._tcp)", query = {"_kerberos-adm._tcp"} },
    { name = "Kerberos (_kerberos-adm._udp)", query = {"_kerberos-adm._udp"} },
    { name = "Kerberos (_kerneros-iv._udp)", query = {"_kerneros-iv._udp"} },
    { name = "Kerberos FTP (_kftp-data._tcp)", query = {"_kftp-data._tcp"} },
    { name = "Kerberos FTP (_kftp-data._udp)", query = {"_kftp-data._udp"} },
    { name = "Kerberos FTP (_kftp._tcp)", query = {"_kftp._tcp"} },
    { name = "Kerberos FTP (_kftp._udp)", query = {"_kftp._udp"} },
    { name = "Kerberos Telnet (_ktelnet._tcp)", query = {"_ktelnet._tcp"} },
    { name = "Kerberos Telnet (_ktelnet._udp)", query = {"_ktelnet._udp"} },
    { name = "AFS Kerberos (_afs3-kaserver._tcp)", query = {"_afs3-kaserver._tcp"} },
    { name = "AFS Kerberos (_afs3-kaserver._udp)", query = {"_afs3-kaserver._udp"} },
    { name = "LDAP (_ldap._tcp)", query = {"_ldap._tcp"} },
    { name = "LDAP (_ldap._udp)", query = {"_ldap._udp"} },
    { name = "LDAP (_ldaps._tcp)", query = {"_ldaps._tcp"} },
    { name = "LDAP (_ldaps._udp)", query = {"_ldaps._udp"} },
    { name = "LDAP (_www-ldap-gw._tcp)", query = {"_www-ldap-gw._tcp"} },
    { name = "LDAP (_www-ldap-gw._udp)", query = {"_www-ldap-gw._udp"} },
    { name = "LDAP (_msft-gc-ssl._tcp)", query = {"_msft-gc-ssl._tcp"} },
    { name = "LDAP (_msft-gc-ssl._udp)", query = {"_msft-gc-ssl._udp"} },
    { name = "LDAP (_ldap-admin._tcp)", query = {"_ldap-admin._tcp"} },
    { name = "LDAP (_ldap-admin._udp)", query = {"_ldap-admin._udp"} },
    { name = "LDAP / Active Directory Global Catalog", query = {"_gc._tcp"} },
    { name = "Avatar (_avatars._tcp)", query = {"_avatars._tcp"} },
    { name = "Avatar (_avatars-sec._tcp)", query = {"_avatars-sec._tcp"} },
    { name = "Matrix (_matrix-vnet._tcp)", query = {"_matrix-vnet._tcp"} },
    { name = "Puppet (_puppet._tcp)", query = {"_puppet._tcp"} },
    { name = "Puppet (_x-puppet._tcp)", query = {"_x-puppet._tcp"} },
    { name = "STUN (_stun._tcp)", query = {"_stun._tcp"} },
    { name = "STUN (_stun._udp)", query = {"_stun._udp"} },
    { name = "STUN (_stun-behavior._tcp)", query = {"_stun-behavior._tcp"} },
    { name = "STUN (_stun-behavior._udp)", query = {"_stun-behavior._udp"} },
    { name = "STUN (_stuns._tcp)", query = {"_stuns._tcp"} },
    { name = "STUN (_stuns._udp)", query = {"_stuns._udp"} },
    { name = "STUN (_stun-behaviors._tcp)", query = {"_stun-behaviors._tcp"} },
    { name = "STUN (_stun-behaviors._udp)", query = {"_stun-behaviors._udp"} },
    { name = "STUN (_stun-p1._tcp)", query = {"_stun-p1._tcp"} },
    { name = "STUN (_stun-p1._udp)", query = {"_stun-p1._udp"} },
    { name = "STUN (_stun-p2._tcp)", query = {"_stun-p2._tcp"} },
    { name = "STUN (_stun-p2._udp)", query = {"_stun-p2._udp"} },
    { name = "STUN (_stun-p3._tcp)", query = {"_stun-p3._tcp"} },
    { name = "STUN (_stun-p3._udp)", query = {"_stun-p3._udp"} },
    { name = "STUN (_stun-port._tcp)", query = {"_stun-port._tcp"} },
    { name = "STUN (_stun-port._udp)", query = {"_stun-port._udp"} },
    { name = "SIP (_sip._tcp)", query = {"_sip._tcp"} },
    { name = "SIP (_sip._udp)", query = {"_sip._udp"} },
    { name = "SIP (_sip._sctp)", query = {"_sip._sctp"} },
    { name = "SIP (_sips._tcp)", query = {"_sips._tcp"} },
    { name = "SIP (_sips._udp)", query = {"_sips._udp"} },
    { name = "SIP (_sips._sctp)", query = {"_sips._sctp"} },
    { name = "XMPP Client-Server (_xmpp-client._tcp)", query = {"_xmpp-client._tcp"} },
    { name = "XMPP Client-Server (_xmpp-client._udp)", query = {"_xmpp-client._udp"} },
    { name = "XMPP Server-Server (_xmpp-server._tcp)", query = {"_xmpp-server._tcp"} },
    { name = "XMPP Server-Server (_xmpp-server._udp)", query = {"_xmpp-server._udp"} },
    { name = "Jabber (_jabber._tcp)", query = {"_jabber._tcp"} },
    { name = "XMPP (_xmpp-bosh._tcp)", query = {"_xmpp-bosh._tcp"} },
    { name = "XMPP (_presence._tcp)", query = {"_presence._tcp"} },
    { name = "XMPP (_presence._udp)", query = {"_presence._udp"} },
    { name = "Whois (_rwhois._tcp)", query = {"_rwhois._tcp"} },
    { name = "Whois (_rwhois._udp)", query = {"_rwhois._udp"} },
    { name = "Whois (_whoispp._tcp)", query = {"_whoispp._tcp"} },
    { name = "Whois (_whoispp._udp)", query = {"_whoispp._udp"} },
    { name = "Teamspeak (_ts3._udp)", query = {"_ts3._udp"} },
    { name = "Teamspeak (_tsdns._tcp)", query = {"_tsdns._tcp"} },
    { name = "Matrix (_matrix._tcp)", query = {"_matrix._tcp"} },
    { name = "Minecraft (_minecraft._tcp)", query = {"_minecraft._tcp"} },
    { name = "Instant Messaging and Presence Service (_imps-server._tcp)", query = {"_imps-server._tcp"} },
    { name = "Exchange Autodiscover (_autodiscover._tcp)", query = {"_autodiscover._tcp"} },
    { name = "Whois (_nicname._tcp)", query = {"_nicname._tcp"} },
    { name = "Whois (_nicname._udp)", query = {"_nicname._udp"} },
    { name = "Cisco Collaboration Edge (_collab-edge._tls)", query = {"_collab-edge._tls"} },
  }

  if ( not(checkFilter(services)) ) then
    return stdnse.format_output(false, ("Invalid filter (%s) was supplied"):format(arg_filter))
  end

  local threads, result = {}, {}
  for name, queries in parseSvcList(services) do
    if ( not(arg_filter) or 0 == #arg_filter or
      "all" == arg_filter or arg_filter == name ) then
      local co = stdnse.new_thread(doQuery, name, queries, result)
      threads[co] = true
    end
  end

  local condvar = nmap.condvar(result)
  repeat
    for t in pairs(threads) do
      if ( coroutine.status(t) == "dead" ) then threads[t] = nil end
    end
    if ( next(threads) ) then
      condvar "wait"
    end
  until( next(threads) == nil )

  table.sort(result, function(a,b) return a.name < b.name end)

  return stdnse.format_output(true, result)
end
