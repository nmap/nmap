local http = require "http"
local stdnse = require "stdnse"
local vulns = require "vulns"
local nmap = require "nmap"
local shortport = require "shortport"
local table = require "table"
local tableaux = require "tableaux"
local string = require "string"
local slaxml = require "slaxml"

description = [[
Checks the cross-domain policy file (/crossdomain.xml) and the client-acces-policy file (/clientaccesspolicy.xml)
in web applications and lists the trusted domains. Overly permissive settings enable Cross Site Request Forgery
attacks and may allow attackers to access sensitive data. This script is useful to detect permissive
configurations and possible domain names available for purchase to exploit the application.

The script queries instantdomainsearch.com to lookup the domains. This functionality is
turned off by default, to enable it set the script argument http-cross-domain-policy.domain-lookup.

References:
* http://sethsec.blogspot.com/2014/03/exploiting-misconfigured-crossdomainxml.html
* http://gursevkalra.blogspot.com/2013/08/bypassing-same-origin-policy-with-flash.html
* https://www.adobe.com/devnet/articles/crossdomain_policy_file_spec.html
* https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/CrossDomain_PolicyFile_Specification.pdf
* https://www.owasp.org/index.php/Test_RIA_cross_domain_policy_%28OTG-CONFIG-008%29
* http://acunetix.com/vulnerabilities/web/insecure-clientaccesspolicy-xml-file
]]

---
-- @usage nmap --script http-cross-domain-policy <target>
-- @usage nmap -p 80 --script http-cross-domain-policy --script-args http-cross-domain-policy.domain-lookup=true <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 8080/tcp open  http-proxy syn-ack
-- | http-cross-domain-policy:
-- |   VULNERABLE:
-- |   Cross-domain policy file (crossdomain.xml)
-- |     State: VULNERABLE
-- |       A cross-domain policy file specifies the permissions that a web client such as Java, Adobe Flash, Adobe Reader,
-- |       etc. use to access data across different domains. A client acces policy file is similar to cross-domain policy
-- |       but is used for M$ Silverlight applications. Overly permissive configurations enables Cross-site Request
-- |       Forgery attacks, and may allow third parties to access sensitive data meant for the user.
-- |     Check results:
-- |       /crossdomain.xml:
-- |         <cross-domain-policy>
-- |         <allow-access-from domain="*.example.com"/>
-- |         <allow-access-from domain="*.exampleobjects.com"/>
-- |         <allow-access-from domain="*.example.co.in"/>'
-- |         </cross-domain-policy>
-- |       /clientaccesspolicy.xml:
-- |         <?xml version="1.0" encoding="utf8"?>
-- |         </accesspolicy>
-- |           <crossdomainaccess>
-- |             <policy>
-- |               <allowfrom httprequestheaders="SOAPAction">
-- |                 <domain uri="*"/>
-- |                 <domain uri="*.example.me"/>
-- |                 <domain uri="*.exampleobjects.me"/>
-- |               </allowfrom>
-- |               <granto>
-- |                 <resource path="/" includesubpaths="true"/>
-- |               </granto>
-- |             </policy>
-- |           </crossdomainaccess>
-- |         </accesspolicy>
-- |     Extra information:
-- |       Trusted domains:example.com, exampleobjects.com, example.co.in, *, example.me, exampleobjects.me
-- |   Use the script argument 'domain-lookup' to find trusted domains available for purchase
-- |     References:
-- |       http://gursevkalra.blogspot.com/2013/08/bypassing-same-origin-policy-with-flash.html
-- |       http://sethsec.blogspot.com/2014/03/exploiting-misconfigured-crossdomainxml.html
-- |       https://www.owasp.org/index.php/Test_RIA_cross_domain_policy_%28OTG-CONFIG-008%29
-- |       http://acunetix.com/vulnerabilities/web/insecure-clientaccesspolicy-xml-file
-- |       https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/CrossDomain_PolicyFile_Specification.pdf
-- |_      https://www.adobe.com/devnet/articles/crossdomain_policy_file_spec.html
--
--
-- @args http-cross-domain-policy.domain-lookup Boolean to check domain availability. Default:false
--
-- @xmloutput
-- <elem key="title">Cross-domain and Client Access policies.</elem>
-- <elem key="state">VULNERABLE</elem>
-- <table key="description">
--   <elem>A cross-domain policy file specifies the permissions that a
--   web client such as Java, Adobe Flash, Adobe Reader, etc. use to
--   access data across different domains. A client acces policy file
--   is similar to cross-domain policy but is used for M$ Silverlight
--   applications. Overly permissive configurations enables Cross-site
--   Request Forgery attacks, and may allow third parties to access
--   sensitive data meant for the user.</elem>
-- </table>
-- <table key="check_results">
--   <table>
--     <elem key="name">/crossdomain.xml</elem>
--     <elem key="body">&lt;cross-domain-policy&gt;
--     &lt;allow-access-from domain="*.example.com"/&gt;
--     &lt;allow-access-from domain="*.exampleobjects.com"/&gt;
--     &lt;allow-access-from domain="*.example.co.in"/&gt;'
--     &lt;/cross-domain-policy&gt;</elem>
--   </table>
--   <table>
--     <elem key="name">/clientaccesspolicy.xml</elem>
--     <elem key="body">&lt;?xml version="1.0" encoding="utf8"?&gt;
--     &lt;/accesspolicy&gt; &lt;crossdomainaccess&gt; &lt;policy&gt;
--     &lt;allowfrom httprequestheaders="SOAPAction"&gt; &lt;domain
--     uri="*"/&gt; &lt;domain uri="*.example.me"/&gt; &lt;domain
--     uri="*.exampleobjects.me"/&gt; &lt;/allowfrom&gt; &lt;granto&gt;
--     &lt;resource path="/" includesubpaths="true"/&gt;
--     &lt;/granto&gt; &lt;/policy&gt; &lt;/crossdomainaccess&gt;
--     &lt;/accesspolicy&gt;</elem>
--   </table>
-- </table>
-- <table key="extra_info">
--   <elem>Trusted domains:example.com, exampleobjects.com,
--   example.co.in, *, example.me, exampleobjects.me Use the script argument
--   'domain-lookup' to find trusted domains available for
--   purchase</elem>
-- </table>
-- <table key="refs">
--   <elem>
--   https://www.adobe.com/devnet/articles/crossdomain_policy_file_spec.html</elem>
--   <elem>
--   https://www.owasp.org/index.php/Test_RIA_cross_domain_policy_%28OTG-CONFIG-008%29</elem>
--   <elem>
--   http://sethsec.blogspot.com/2014/03/exploiting-misconfigured-crossdomainxml.html</elem>
--   <elem>
--   https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/CrossDomain_PolicyFile_Specification.pdf</elem>
--   <elem>
--   http://acunetix.com/vulnerabilities/web/insecure-clientaccesspolicy-xml-file</elem>
--   <elem>
--   http://gursevkalra.blogspot.com/2013/08/bypassing-same-origin-policy-with-flash.html</elem>
-- </table>
--
---

author = {"Seth Art <sethsec()gmail>", "Paulino Calderon <calderon()websec.mx>", "Gyanendra Mishra"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "external", "vuln"}

portrule = shortport.http
local tlds_instantdomainsearch = {".com", ".net", ".org", ".co", ".info", ".biz", ".mobi", ".us", ".ca", ".co.uk",
                          ".in", ".io", ".it", ".pt", ".me", ".tv"}

---
-- Queries instantdomainsearch.com to check if domains are available
-- Returns nil if the query failed and true/false to indicate domain availability
--
-- Sample response:
--
-- {"label":"nmap","tld":"com","isRegistered":true,"isBid":false,
-- "price":0,"aftermarketProvider":"","rank":14.028985023498535,"search":"name"}
-- {"words":["nmap"],"synonyms":["nmap","scans"],"tld":"com","isBid":false,"price":0,
-- "aftermarketProvider":"","rank":0.23496590554714203,"search":"word"}
-- {"label":"snmap","tld":"com","isBid":false,"price":2994,"aftermarketProvider":"afternic.com",
-- "rank":9.352656364440918,"search":"ngram"}
---
local function check_domain (domain)
  local name, tld = domain:match("(%w*)%.*(%w*%.%w+)$")
  if not(tableaux.contains(tlds_instantdomainsearch, tld)) then
    stdnse.debug(1, "TLD '%s' is not supported by instantdomainsearch.com. Check manually.", tld)
    return nil
  end

  stdnse.print_debug(1, "Checking availability of domain %s with tld:%s ", name, tld)
  local path = string.format("/all/%s?/tlds=%s&limit=1", name, tld)
  local response = http.get("instantdomainsearch.com", 443, path, {any_af=true})
  if ( not(response) or (response.status and response.status ~= 200) ) then
    return nil
  end
  local _, _, registered = response.body:find('"isRegistered":(.-),"isBid":')
  return registered
end

---
-- Requests and parses crossdomain.xml file
---
function check_crossdomain(host, port, lookup)
  local trusted_domains = {}
  local trusted_domains_available = {}
  local content = {}
  local req_opt = {redirect_ok=function(host,port)
    local c = 3
    return function(uri)
      if ( c==0 ) then return false end
      c = c - 1
      return true
    end
  end}
  local domain_table = {}
  local CROSSDOMAIN = {
    uri = '/crossdomain.xml',
    attribute = function(name, value)
      if name == 'domain' then
        table.insert(domain_table, value)
      end
    end,
    }

  local CLIENTACCESS = {
    uri = '/clientaccesspolicy.xml',
    attribute = function(name, value)
      if name == 'uri' then
        table.insert(domain_table, value)
      end
    end,
  }
  local lists = {}
  table.insert(lists, CROSSDOMAIN)
  table.insert(lists, CLIENTACCESS)
  for _, list in pairs(lists) do
    local req = http.get(host, port, list.uri, req_opt)
    if req.status and req.status == 200 then
      domain_table = {}
      local parser = slaxml.parser:new({attribute = list.attribute})
      parser:parseSAX (req.body)
      table.insert(content, {name = list.uri, body = req.body})
      for _, domain in pairs(domain_table) do
        --Matches wildcard, which means vulnerable as any host can comunicate with app
        if domain == '*' or domain == 'http://' or domain == 'https://' then
          stdnse.debug(1, "Wildcard detected!")
          table.insert(trusted_domains, domain)
        else
          --Parse domains
          local line = domain:gsub("%*%.", "")
          stdnse.debug(1, "Extracted line: %s", line)
          local domain  = line:match("(%w*%.*%w+%.%w+)$")
          if domain ~= nil then
            --Deals with tlds with double extension
            local tld = domain:match("%w*(%.%w*)%.%w+$")
            if tld ~= nil and not(tableaux.contains(tlds_instantdomainsearch, tld)) then
              domain = domain:match("%w*%.(.*)$")
            end
            --We add domains only once as they can appear multiple times
            if not(tableaux.contains(trusted_domains, domain)) then
              stdnse.debug(1, "Added trusted domain:%s", domain)
              table.insert(trusted_domains, domain)
              --Lookup domains if script argument is set
              if ( lookup ) then
                if check_domain(domain) == "false" then
                  stdnse.debug(1, "Domain '%s' is available for purchase!", domain)
                  table.insert(trusted_domains_available, domain)
                end
              end
            end
          end
          stdnse.debug(1, "Extracted domain: %s", domain)
        end
      end
    end
  end
  if (#trusted_domains> 0) then
    return true, trusted_domains, trusted_domains_available, content
  else
    return nil
  end
end


action = function(host, port)
  local lookup = stdnse.get_script_args(SCRIPT_NAME..".domain-lookup") or false

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local vuln = {
       title = 'Cross-domain and Client Access policies.',
       state = vulns.STATE.NOT_VULN,
       description = [[
A cross-domain policy file specifies the permissions that a web client such as Java, Adobe Flash, Adobe Reader,
etc. use to access data across different domains. A client acces policy file is similar to cross-domain policy
but is used for M$ Silverlight applications. Overly permissive configurations enables Cross-site Request
Forgery attacks, and may allow third parties to access sensitive data meant for the user.]],
       references = {
          'http://sethsec.blogspot.com/2014/03/exploiting-misconfigured-crossdomainxml.html',
          'http://gursevkalra.blogspot.com/2013/08/bypassing-same-origin-policy-with-flash.html',
          'https://www.adobe.com/devnet/articles/crossdomain_policy_file_spec.html',
          'https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/CrossDomain_PolicyFile_Specification.pdf',
          'https://www.owasp.org/index.php/Test_RIA_cross_domain_policy_%28OTG-CONFIG-008%29',
          'http://acunetix.com/vulnerabilities/web/insecure-clientaccesspolicy-xml-file'
       },
     }
  local check, domains, domains_available, content = check_crossdomain(host, port, lookup)
  local mt = {__tostring=function(p) return ("%s:\n      %s"):format(p.name, p.body:gsub("\n", "\n      ")) end}
  if check then
    if tableaux.contains(domains, "*") or tableaux.contains(domains, "https://") or tableaux.contains(domains, "http://") then
      vuln.state = vulns.STATE.VULN
    else
      vuln.state = vulns.STATE.LIKELY_VULN
    end
    for i, _ in pairs(content) do
      setmetatable(content[i], mt)
      tostring(content[i])
    end
    vuln.check_results = content
    vuln.extra_info = string.format("Trusted domains:%s\n", table.concat(domains, ', '))
    if not(lookup) and nmap.verbosity()>=2 then
      vuln.extra_info = vuln.extra_info .. "Use the script argument 'domain-lookup' to find trusted domains available for purchase"
    end
    if lookup ~= nil and #domains_available>0 then
      vuln.state = vulns.STATE.EXPLOIT
      vuln.extra_info = vuln.extra_info .. string.format("[!]Trusted domains available for purchase:%s", table.concat(domains_available, ', '))
    end

  end

  return vuln_report:make_output(vuln)
end
