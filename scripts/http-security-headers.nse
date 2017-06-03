local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Checks for the HTTP response headers related to security given in OWASP Secure Headers Project,
shows whether they are configured and gives a brief description of them. 
 
The script requests the server for the header with http.head and parses it to list headers founds with their
configurations. The script checks for HSTS(HTTP Strict Transport Security), HPKP(HTTP Public Key Pins),
X-Frame-Options, X-XSS-Protection, X-Content-Type-Options, Content-Security-Policy and 
X-Permitted-Cross-Domain-Policies

References: https://www.owasp.org/index.php/OWASP_Secure_Headers_Project
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers

]]

---
-- @usage
-- nmap -p <port> --script http-security-headers <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | http-security-headers:
-- |  HSTS is configured.
-- |  Header: Strict-Transport-Security: max-age=31536000
-- |  HPKP is configured
-- |  Header: Public-Key-Pins: pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="; report-uri="http://example.com/pkp-report"; max-age=10000; includeSubDomains
-- |  X-Frame-Options is configured.
-- |  Header: X-Frame-Options: DENY
-- |  Description: The browser must not display this content in any frame.
-- |  X-XSS-Protection is configured.
-- |  Header: X-XSS-Protection: 1; mode=block
-- |  Description: Rather than sanitize the page, when a XSS attack is detected, the browser will prevent rendering of the page. 
-- |  X-Content-Type-Options is configured.
-- |  Header: X-Content-Type-Options: nosniff
-- |  Description: Will prevent the browser from MIME-sniffing a response away from the declared content-type. 
-- |  Content-Security-Policy is configured.
-- |  Header: Content-Security-Policy: script-src 'self'
-- |  Description: Loading policy for all resources type in case of a resource type dedicated directive is not defined (fallback).
-- |  X-Permitted-Cross-Domain-Policies are configured.
-- |  Header: X-Permitted-Cross-Domain-Policies: none 
-- |_ Description : No policy files are allowed anywhere on the target server, including this master policy file. 
--
--
-- @xmloutput
-- <elem>HSTS is configured</elem>
-- <elem key="Header">Strict-Transport-Security: max-age=31536000</elem>
-- <elem>HPKP is configured</elem>
-- <elem key="Header">Public-Key-Pins: pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="; report-uri="http://example.com/pkp-report"; max-age=10000; includeSubDomains</elem>
-- <elem>X-Frame-Options is configured</elem>
-- <elem key="Header">X-Frame-Options: DENY</elem>
-- <elem key="Description">The browser must not display this content in any frame.</elem>
-- <elem>X-XSS-Protection is configured</elem>
-- <elem key="Header">X-XSS-Protection: 1; mode=block</elem>
-- <elem key=Description>Rather than sanitize the page, when a XSS attack is detected, the browser will prevent rendering of the page.</elem>
-- <elem>X-Content-Type-Options is configured.</elem>
-- <elem key="Header">X-Content-Type-Options: nosniff</elem>
-- <elem key="Description">Will prevent the browser from MIME-sniffing a response away from the declared content-type.</elem>
-- <elem>Content-Security-Policy is configured.</elem>
-- <elem key="Header">Content-Security-Policy: script-src 'self'</elem>
-- <elem key="Description">Loading policy for all resources type in case of a resource type dedicated directive is not defined (fallback).</elem>
-- <elem>X-Permitted-Cross-Domain-Policies are configured.</elem>
-- <elem key="Header">X-Permitted-Cross-Domain-Policies: none</elem>
-- <elem key="Description">No policy files are allowed anywhere on the target server, including this master policy file.</elem>
--
-- @args http-security-headers.path The URL path to request. The default path is "/".

author = {"Icaro Torres", "Vinamra Bhatia"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({80,443}, "http", "tcp")

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"
  local response
  local output_info = {}
  local hsts_header 
  local hpkp_header 
  local xframe_header 
  local x_xss_header 
  local x_content_type_header 
  local csp_header
  local x_cross_domain_header 
  local cookie 
  local req_opt = {redirect_ok=function(host,port)
    local c = 2
    return function(uri)
      if ( c==0 ) then return false end
      c = c - 1
      return true
    end
  end}

  response = http.head(host, port, path, req_opt)

  output_info = stdnse.output_table()

  if response == nil then
    return fail("Request failed")
  end

  if response.header == nil then
    return fail("Response didn't include a proper header")
  end

  for i,v in pairs(response.header) do
    print(i,v)
  end

  if response.header['strict-transport-security'] then
    table.insert(output_info, "HSTS is configured.")
    table.insert(output_info, "Header: " .. "Strict-Transport-Security: "..response.header['strict-transport-security'])
  elseif shortport.ssl(host,port) then
    table.insert(output_info, "HSTS not configured in HTTPS Server")
  end

  if response.header['public-key-pins-report-only'] then
    table.insert(output_info, "HPKP is configured.")
    table.insert(output_info, "Header: " .. "Public-Key-Pins-Report-Only: "..response.header['public-key-pins-report-only'])
  end

  if response.header['x-frame-options'] then
    table.insert(output_info, "X-Frame-Options is configured.")
    table.insert(output_info, "Header: " .. "X-Frame-Options: "..response.header['x-frame-options'])

    xframe_header = string.lower(response.header['x-frame-options'])
    if string.match(xframe_header,'deny') then
      table.insert(output_info, "Description: The browser must not display this content in any frame.")
    elseif string.match(xframe_header,'sameorigin') then  
      table.insert(output_info, "Description: The browser must not display this content in any frame from a page of different origin than the content itself.")
    elseif string.match(xframe_header,'allow.from') then
      table.insert(output_info, "Description: The browser must not display this content in a frame from any page with a top-level browsing context of different origin than the specified origin.")
    end

  end

  if response.header['x-xss-protection'] then
    table.insert(output_info, "X-XSS-Protection is configured.")
    table.insert(output_info, "Header: " .. "X-XSS-Protection: "..response.header['x-xss-protection'])

    x_xss_header = string.lower(response.header['x-xss-protection'])
    if string.match(x_xss_header,'block') then
      table.insert(output_info, "Description: The browser will prevent the rendering of the page when XSS is detected.")
    elseif string.match(x_xss_header,'report') then  
      table.insert(output_info, "Description: The browser will sanitize the page and report the violation if XSS is detected.")
    elseif string.match(x_xss_header,'0') then
      table.insert(output_info, "Description: The XSS filter is disabled.")
    end

  end

  if response.header['x-content-type-options'] then
    table.insert(output_info, "X-Content-Type-Options is configured.")
    table.insert(output_info, "Header: " .."X-Content-Type-Options: "..response.header['x-content-type-options'])

    x_content_type_header = string.lower(response.header['x-content-type-options'])
    if string.match(x_content_type_header,'nosniff') then
      table.insert(output_info, "Will prevent the browser from MIME-sniffing a response away from the declared content-type. ")
    end

  end

  if response.header['content-security-policy'] then
    table.insert(output_info, "Content-Security-Policy is configured.")
    table.insert(output_info, "Header: " .."Content-Security-Policy: "..response.header['content-security-policy'])

    csp_header = string.lower(response.header['content-security-policy'])
    if string.match(csp_header,'base.uri') then
       table.insert(output_info, "Description: Define the base uri for relative uri.")
    end
    if string.match(csp_header,'default.src') then
      table.insert(output_info, "Description: Define loading policy for all resources type in case of a resource type dedicated directive is not defined (fallback).")
    end
    if string.match(csp_header,'script.src') then
      table.insert(output_info, "Description: Define which scripts the protected resource can execute.")
    end
    if string.match(csp_header,'object.src') then
      table.insert(output_info, "Description: Define from where the protected resource can load plugins.")
    end
    if string.match(csp_header,'style.src') then
      table.insert(output_info, "Description: Define which styles (CSS) the user applies to the protected resource.")
    end
    if string.match(csp_header,'img.src') then
      table.insert(output_info, "Description: Define from where the protected resource can load images.")
    end
    if string.match(csp_header,'media.src') then
      table.insert(output_info, "Description: Define from where the protected resource can load video and audio.")
    end
    if string.match(csp_header,'frame.src') then
      table.insert(output_info, "Description: Deprecated and replaced by child-src. Define from where the protected resource can embed frames.")
    end
    if string.match(csp_header,'child.src') then
      table.insert(output_info, "Description: Define from where the protected resource can embed frames.")
    end
    if string.match(csp_header,'frame.ancestors') then
      table.insert(output_info, "Description: Define from where the protected resource can be embedded in frames.")
    end
    if string.match(csp_header,'font.src') then
      table.insert(output_info, "Description: Define from where the protected resource can load fonts.")
    end
    if string.match(csp_header,'connect.src') then
      table.insert(output_info, "Description: Define which URIs the protected resource can load using script interfaces.")
    end
    if string.match(csp_header,'mailfest.src') then
      table.insert(output_info, "Description: Define from where the protected resource can load manifest.")
    end
    if string.match(csp_header,'form.action') then
      table.insert(output_info, "Description: Define which URIs can be used as the action of HTML form elements.")
    end
    if string.match(csp_header,'sandbox') then
      table.insert(output_info, "Description: Specifies an HTML sandbox policy that the user agent applies to the protected resource.")
    end
    if string.match(csp_header,'script.nonce') then
      table.insert(output_info, "Description: Define script execution by requiring the presence of the specified nonce on script elements.")
    end
    if string.match(csp_header,'plugin.types') then
      table.insert(output_info, "Description: Define the set of plugins that can be invoked by the protected resource by limiting the types of resources that can be embedded.")
    end
    if string.match(csp_header,'reflected.xss') then
      table.insert(output_info, "Description: Instructs a user agent to activate or deactivate any heuristics used to filter or block reflected cross-site scripting attacks, equivalent to the effects of the non-standard X-XSS-Protection header.")
    end
    if string.match(csp_header,'block.all.mixed.content') then
      table.insert(output_info, "Description: Prevent user agent from loading mixed content.")
    end
    if string.match(csp_header,'upgrade.insecure.requests') then
      table.insert(output_info, "Description: Instructs user agent to download insecure resources using HTTPS.")
    end
    if string.match(csp_header,'referrer') then
      table.insert(output_info, "Description: Define information user agent must send in Referer header.")
    end
    if string.match(csp_header,'report.uri') then
      table.insert(output_info, "Description: Specifies a URI to which the user agent sends reports about policy violation.")
    end
    if string.match(csp_header,'report.to') then
      table.insert(output_info, "Description: Specifies a group (defined in Report-To header) to which the user agent sends reports about policy violation. ")
    end
 
  end

  if response.header['x-permitted-cross-domain-policies'] then
    table.insert(output_info, "X-Permitted-Cross-Domain-Policies are configured.")
    table.insert(output_info, "Header: " .."X-Permitted-Cross-Domain-Policies: "..response.header['x-permitted-cross-domain-policies'])

    x_cross_domain_header = string.lower(response.header['x-permitted-cross-domain-policies'])
    if string.match(x_cross_domain_header,'none') then
      table.insert(output_info, "Description: No policy files are allowed anywhere on the target server, including this master policy file. ")
    elseif string.match(x_cross_domain_header,'master.only') then
      table.insert(output_info, "Description: Only this master policy file is allowed. ")
    elseif string.match(x_cross_domain_header,'by.content.type') then
      table.insert(output_info, "Description: Define which scripts the protected resource can execute.")
    elseif string.match(x_cross_domain_header,'all') then
      table.insert(output_info, "Description: All policy files on this target domain are allowed.")
    end

  end

  if response.header['set-cookie'] then
    cookie = string.lower(response.header['set-cookie'])
    if string.match(cookie,'secure') and shortport.ssl(host,port) then
      table.insert(output_info, "Cookies are secured with Secure Flag in HTTPS Connection")
    end
  end

  if response.header['except-ct'] then
    table.insert(output_info, "Except-CT is configured.")
    table.insert(output_info, "Header: " .."Except-CT: "..response.header['except-ct'])
  end

  if response.header['cache-control'] then
    table.insert(output_info, "Cache-Control is configured.")
    table.insert(output_info, "Header: " .."Cache-Control: "..response.header['cache-control'])
  end

  if response.header['pragma'] then
    table.insert(output_info, "Pragma is configured.")
    table.insert(output_info, "Header: " .."Pragma: "..response.header['pragma'])
  end

  if response.header['expires'] then
    table.insert(output_info, "Expires is configured.")
    table.insert(output_info, "Header: " .."Expires: "..response.header['expires'])
  end

  return stdnse.format_output(true, output_info)

end