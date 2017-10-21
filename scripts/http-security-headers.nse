local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Checks for the HTTP response headers related to security given in OWASP Secure Headers Project
and gives a brief description of the header and its configuration value.

The script requests the server for the header with http.head and parses it to list headers founds with their
configurations. The script checks for HSTS(HTTP Strict Transport Security), HPKP(HTTP Public Key Pins),
X-Frame-Options, X-XSS-Protection, X-Content-Type-Options, Content-Security-Policy,
X-Permitted-Cross-Domain-Policies, Set-Cookie, Expect-CT, Cache-Control, Pragma and Expires.

References: https://www.owasp.org/index.php/OWASP_Secure_Headers_Project
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers

]]

---
-- @usage
-- nmap -p <port> --script http-security-headers <target>
--
-- @output
-- 80/tcp open  http    syn-ack
-- | http-security-headers:
-- |   Strict_Transport_Security:
-- |     Header: Strict-Transport-Security: max-age=15552000; preload
-- |   Public_Key_Pins_Report_Only:
-- |     Header: Public-Key-Pins-Report-Only: max-age=500; pin-sha256="WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18="; pin-sha256="r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E="; pin-sha256="q4PO2G2cbkZhZ82+JgmRUyGMoAeozA+BSXVXQWB8XWQ="; report-uri="http://reports.fb.com/hpkp/"
-- |   X_Frame_Options:
-- |     Header: X-Frame-Options: DENY
-- |     Description: The browser must not display this content in any frame.
-- |   X_XSS_Protection:
-- |     Header: X-XSS-Protection: 0
-- |     Description: The XSS filter is disabled.
-- |   X_Content_Type_Options:
-- |     Header: X-Content-Type-Options: nosniff
-- |     Will prevent the browser from MIME-sniffing a response away from the declared content-type.
-- |   Content-Security-Policy:
-- |     Header: Content-Security-Policy: script-src 'self'
-- |     Description: Loading policy for all resources type in case of a resource type dedicated directive is not defined (fallback).
-- |   X-Permitted-Cross-Domain-Policies:
-- |     Header: X-Permitted-Cross-Domain-Policies: none
-- |     Description : No policy files are allowed anywhere on the target server, including this master policy file.
-- |   Cache_Control:
-- |     Header: Cache-Control: private, no-cache, no-store, must-revalidate
-- |   Pragma:
-- |     Header: Pragma: no-cache
-- |   Expires:
-- |_    Header: Expires: Sat, 01 Jan 2000 00:00:00 GMT
--
--
-- @xmloutput
-- <table key="Strict_Transport_Policy">
-- <elem>Header: Strict-Transport-Security: max-age=31536000</elem>
-- </table>
-- <table key="Public_Key_Pins_Report_Only">
-- <elem>Header: Public-Key-Pins-Report-Only: pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="; report-uri="http://example.com/pkp-report"; max-age=10000; includeSubDomains</elem>
-- </table>
-- <table key="X_Frame_Options">
-- <elem>Header: X-Frame-Options: DENY</elem>
-- <elem>Description: The browser must not display this content in any frame.</elem>
-- </table>
-- <table key="X-XSS-Protection">
-- <elem>Header: X-XSS-Protection: 1; mode=block</elem>
-- <elem>Description: Rather than sanitize the page, when a XSS attack is detected, the browser will prevent rendering of the page.</elem>
-- </table>
-- <table key="X_Content_Type_Options">
-- <elem>Header: X-Content-Type-Options: nosniff</elem>
-- <elem>Description: Will prevent the browser from MIME-sniffing a response away from the declared content-type.</elem>
-- </table>
-- <table key="Content_Security_Policy">
-- <elem>Header: Content-Security-Policy: script-src 'self'</elem>
-- <elem>Description: Loading policy for all resources type in case of a resource type dedicated directive is not defined (fallback).</elem>
-- </table>
-- <table key="X_Permitted_Cross_Domain_Policies">
-- <elem>Header: X-Permitted-Cross-Domain-Policies: none</elem>
-- <elem>Description: No policy files are allowed anywhere on the target server, including this master policy file.</elem>
-- </table>
-- <table key="Cache_Control">
-- <elem>Header: Cache-Control: private, no-cache, no-store, must-revalidate</elem>
-- </table>
-- <table key="Pragma">
-- <elem>Header: Pragma: no-cache</elem
-- </table>
-- <table key="Expires">
-- <elem>Header: Expires: Sat, 01 Jan 2000 00:00:00 GMT</elem
-- </table>
--
-- @args http-security-headers.path The URL path to request. The default path is "/".
---

author = {"Icaro Torres", "Vinamra Bhatia"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({80,443}, "http", "tcp")

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
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

  if response.header['strict-transport-security'] then
    output_info.Strict_Transport_Security = {}
    table.insert(output_info.Strict_Transport_Security, "Header: Strict-Transport-Security: " .. response.header['strict-transport-security'])
  elseif shortport.ssl(host,port) then
    output_info.Strict_Transport_Security = {}
    table.insert(output_info.Strict_Transport_Security, "HSTS not configured in HTTPS Server")
  end

  if response.header['public-key-pins-report-only'] then
    output_info.Public_Key_Pins_Report_Only = {}
    table.insert(output_info.Public_Key_Pins_Report_Only, "Header: Public-Key-Pins-Report-Only: " .. response.header['public-key-pins-report-only'])
  end

  if response.header['x-frame-options'] then
    output_info.X_Frame_Options = {}
    table.insert(output_info.X_Frame_Options, "Header: X-Frame-Options: " .. response.header['x-frame-options'])

    xframe_header = string.lower(response.header['x-frame-options'])
    if string.match(xframe_header,'deny') then
      table.insert(output_info.X_Frame_Options, "Description: The browser must not display this content in any frame.")
    elseif string.match(xframe_header,'sameorigin') then
      table.insert(output_info.X_Frame_Options, "Description: The browser must not display this content in any frame from a page of different origin than the content itself.")
    elseif string.match(xframe_header,'allow.from') then
      table.insert(output_info.X_Frame_Options, "Description: The browser must not display this content in a frame from any page with a top-level browsing context of different origin than the specified origin.")
    end

  end

  if response.header['x-xss-protection'] then
    output_info.X_XSS_Protection = {}
    table.insert(output_info.X_XSS_Protection, "Header: X-XSS-Protection: " .. response.header['x-xss-protection'])

    x_xss_header = string.lower(response.header['x-xss-protection'])
    if string.match(x_xss_header,'block') then
      table.insert(output_info.X_XSS_Protection, "Description: The browser will prevent the rendering of the page when XSS is detected.")
    elseif string.match(x_xss_header,'report') then
      table.insert(output_info.X_XSS_Protection, "Description: The browser will sanitize the page and report the violation if XSS is detected.")
    elseif string.match(x_xss_header,'0') then
      table.insert(output_info.X_XSS_Protection, "Description: The XSS filter is disabled.")
    end

  end

  if response.header['x-content-type-options'] then
    output_info.X_Content_Type_Options = {}
    table.insert(output_info.X_Content_Type_Options, "Header: X-Content-Type-Options: " .. response.header['x-content-type-options'])

    x_content_type_header = string.lower(response.header['x-content-type-options'])
    if string.match(x_content_type_header,'nosniff') then
      table.insert(output_info.X_Content_Type_Options, "Description: Will prevent the browser from MIME-sniffing a response away from the declared content-type. ")
    end

  end

  if response.header['content-security-policy'] then
    output_info.Content_Security_Policy = {}
    table.insert(output_info.Content_Security_Policy, "Header: Content-Security-Policy: " .. response.header['content-security-policy'])

    csp_header = string.lower(response.header['content-security-policy'])
    if string.match(csp_header,'base.uri') then
       table.insert(output_info.Content_Security_Policy, "Description: Define the base uri for relative uri.")
    end
    if string.match(csp_header,'default.src') then
      table.insert(output_info.Content_Security_Policy, "Description: Define loading policy for all resources type in case of a resource type dedicated directive is not defined (fallback).")
    end
    if string.match(csp_header,'script.src') then
      table.insert(output_info.Content_Security_Policy, "Description: Define which scripts the protected resource can execute.")
    end
    if string.match(csp_header,'object.src') then
      table.insert(output_info.Content_Security_Policy, "Description: Define from where the protected resource can load plugins.")
    end
    if string.match(csp_header,'style.src') then
      table.insert(output_info.Content_Security_Policy, "Description: Define which styles (CSS) the user applies to the protected resource.")
    end
    if string.match(csp_header,'img.src') then
      table.insert(output_info.Content_Security_Policy, "Description: Define from where the protected resource can load images.")
    end
    if string.match(csp_header,'media.src') then
      table.insert(output_info.Content_Security_Policy, "Description: Define from where the protected resource can load video and audio.")
    end
    if string.match(csp_header,'frame.src') then
      table.insert(output_info.Content_Security_Policy, "Description: Deprecated and replaced by child-src. Define from where the protected resource can embed frames.")
    end
    if string.match(csp_header,'child.src') then
      table.insert(output_info.Content_Security_Policy, "Description: Define from where the protected resource can embed frames.")
    end
    if string.match(csp_header,'frame.ancestors') then
      table.insert(output_info.Content_Security_Policy, "Description: Define from where the protected resource can be embedded in frames.")
    end
    if string.match(csp_header,'font.src') then
      table.insert(output_info.Content_Security_Policy, "Description: Define from where the protected resource can load fonts.")
    end
    if string.match(csp_header,'connect.src') then
      table.insert(output_info.Content_Security_Policy, "Description: Define which URIs the protected resource can load using script interfaces.")
    end
    if string.match(csp_header,'mailfest.src') then
      table.insert(output_info.Content_Security_Policy, "Description: Define from where the protected resource can load manifest.")
    end
    if string.match(csp_header,'form.action') then
      table.insert(output_info.Content_Security_Policy, "Description: Define which URIs can be used as the action of HTML form elements.")
    end
    if string.match(csp_header,'sandbox') then
      table.insert(output_info.Content_Security_Policy, "Description: Specifies an HTML sandbox policy that the user agent applies to the protected resource.")
    end
    if string.match(csp_header,'script.nonce') then
      table.insert(output_info.Content_Security_Policy, "Description: Define script execution by requiring the presence of the specified nonce on script elements.")
    end
    if string.match(csp_header,'plugin.types') then
      table.insert(output_info.Content_Security_Policy, "Description: Define the set of plugins that can be invoked by the protected resource by limiting the types of resources that can be embedded.")
    end
    if string.match(csp_header,'reflected.xss') then
      table.insert(output_info.Content_Security_Policy, "Description: Instructs a user agent to activate or deactivate any heuristics used to filter or block reflected cross-site scripting attacks, equivalent to the effects of the non-standard X-XSS-Protection header.")
    end
    if string.match(csp_header,'block.all.mixed.content') then
      table.insert(output_info.Content_Security_Policy, "Description: Prevent user agent from loading mixed content.")
    end
    if string.match(csp_header,'upgrade.insecure.requests') then
      table.insert(output_info.Content_Security_Policy, "Description: Instructs user agent to download insecure resources using HTTPS.")
    end
    if string.match(csp_header,'referrer') then
      table.insert(output_info.Content_Security_Policy, "Description: Define information user agent must send in Referer header.")
    end
    if string.match(csp_header,'report.uri') then
      table.insert(output_info.Content_Security_Policy, "Description: Specifies a URI to which the user agent sends reports about policy violation.")
    end
    if string.match(csp_header,'report.to') then
      table.insert(output_info.Content_Security_Policy, "Description: Specifies a group (defined in Report-To header) to which the user agent sends reports about policy violation. ")
    end

  end

  if response.header['x-permitted-cross-domain-policies'] then
    output_info.X_Permitted_Cross_Domain_Policies = {}
    table.insert(output_info.X_Permitted_Cross_Domain_Policies, "Header: X-Permitted-Cross-Domain-Policies: " .. response.header['x-permitted-cross-domain-policies'])

    x_cross_domain_header = string.lower(response.header['x-permitted-cross-domain-policies'])
    if string.match(x_cross_domain_header,'none') then
      table.insert(output_info.X_Permitted_Cross_Domain_Policies, "Description: No policy files are allowed anywhere on the target server, including this master policy file. ")
    elseif string.match(x_cross_domain_header,'master.only') then
      table.insert(output_info.X_Permitted_Cross_Domain_Policies, "Description: Only this master policy file is allowed. ")
    elseif string.match(x_cross_domain_header,'by.content.type') then
      table.insert(output_info.X_Permitted_Cross_Domain_Policies, "Description: Define which scripts the protected resource can execute.")
    elseif string.match(x_cross_domain_header,'all') then
      table.insert(output_info.X_Permitted_Cross_Domain_Policies, "Description: All policy files on this target domain are allowed.")
    end

  end

  if response.header['set-cookie'] then
    cookie = string.lower(response.header['set-cookie'])
    if string.match(cookie,'secure') and shortport.ssl(host,port) then
      output_info.Cookie = {}
      table.insert(output_info.Cookie, "Cookies are secured with Secure Flag in HTTPS Connection")
    end
  end

  if response.header['expect-ct'] then
    output_info.Expect_CT = {}
    table.insert(output_info.Expect_CT, "Header: Expect-CT: " .. response.header['expect-ct'])
  end

  if response.header['cache-control'] then
    output_info.Cache_Control = {}
    table.insert(output_info.Cache_Control, "Header: Cache-Control: " .. response.header['cache-control'])
  end

  if response.header['pragma'] then
    output_info.Pragma = {}
    table.insert(output_info.Pragma, "Header: Pragma: " .. response.header['pragma'])
  end

  if response.header['expires'] then
    output_info.Expires = {}
    table.insert(output_info.Expires, "Header: Expires: " .. response.header['expires'])
  end

  return output_info, stdnse.format_output(true, output_info)

end

