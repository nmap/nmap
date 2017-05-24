local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Checks for the HTTP response headers related to security given in OWASP Secure Headers Project 
and shows whether they are configured.

HTTP Strict-Transport-Security (HSTS) (RFC 6797) forces a web browser to communicate with a 
web server over HTTPS.

HTTP Public Key Pinning (HPKP) (RFC 7469) allows HTTPS websites to resist impersonation by attackers 
using mis-issued or otherwise fraudulent certificates.the HTTPS web server serves a list of “pinned” 
public key hashes; on subsequent connections clients expect that server to use one or more of those 
public keys in its certificate chain.

X-Frame-Options (RFC 7034) is a HTTP header field that allows the server to communicate to the browser 
to display or not the content of the frames included in the current page that are part of other web 
pages. It improves the protection of web applications against Clickjacking.

X-XSS-Protection enables the Cross-Site Scripting filter in the browser.

X-Content-Type-Options response HTTP header is a marker used by the server to indicate that the MIME
types advertised in the Content-Type headers should not be changed and be followed.

Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain 
types of attacks.  If enabled, CSP has significant impact on the way browser renders pages. CSP prevents
a wide range of attacks, including Cross-site scripting and other cross-site injections. 

X-Permitted-Cross-Domain-Policies are cross-domain policy files is an XML document that grants a web
client permission to handle data across domains. When clients request content hosted on a particular source domain 
and that content make requests directed towards a domain other than its own, the remote domain 
needs to host a cross-domain policy file that grants access to the source domain, allowing the 
client to continue the transaction.  

References: https://www.owasp.org/index.php/OWASP_Secure_Headers_Project
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers

]]

---
-- @usage
-- nmap -p <port> --script http-vuln-headers <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | http-vuln-headers:
-- |  HSTS is configured.
-- |  Header: Strict-Transport-Security: max-age=31536000
-- |  HPKP is configured
-- |  Header: Public-Key-Pins: pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="; report-uri="http://example.com/pkp-report"; max-age=10000; includeSubDomains
-- |  X-Frame-Options is configured.
-- |  Header: X-Frame-Options: DENY
-- |  Description: The browser must not display this content in any frame.
-- |  X-XSS-Protection is configured.
-- |  Header: X-XSS-Protection: 1; mode=block
-- |  Description:  Rather than sanitize the page, when a XSS attack is detected, the browser will prevent rendering of the page. 
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
-- @args http-vuln-headers.path The URL path to request. The default path is "/".

author = {"Icaro Torres", "Vinamra Bhatia"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({80,443,3000}, "http", "tcp")

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"
  local response
  local output_info = {}
  local hsts_header = {}
  local hpkp_header = {}
  local xframe_header = {}
  local x_xss_header = {}
  local x_content_type_header = {}
  local csp_header = {}
  local x_cross_domain_header = {}

  response = http.head(host, port, path)

  if response == nil then
    return fail("Request failed")
  end

  if response.rawheader == nil then
    return fail("Response didn't include a proper header")
  end

  for _, line in pairs(response.rawheader) do
    if line:match("[Ss]trict.[Tt]ransport.[Ss]ecurity") then
      table.insert(hsts_header, line)
    end
    if line:match("[Pp]ublic.[Kk]ey.[Pp]ins") then
      table.insert(hpkp_header, line)
    end
    if line:match("[Xx].[Ff]rame.[Oo]ptions") then
      table.insert(xframe_header, line)
    end
    if line:match("[Xx].[Xx][Ss][Ss].[Pp]rotection") then
      table.insert(x_xss_header, line)
    end
    if line:match("[Xx].[Cc]ontent.[Tt]ype.[Oo]ptions") then
      table.insert(x_content_type_header, line)
    end
    if line:match("[Cc]ontent.[Ss]ecurity.[Pp]olicy") then
      table.insert(csp_header, line)
    end
    if line:match("[Xx].[Pp]ermitted.[Cc]ross.[Dd]omain.[Pp]olicies") then
      table.insert(x_cross_domain_header, line)
    end
  end

  if #hsts_header > 0 then
    table.insert(output_info, "HSTS is configured.")
    table.insert(output_info, "Header: " .. table.concat(hsts_header, " "))
  end

  if #hpkp_header > 0 then
    table.insert(output_info, "HPKP is configured.")
    table.insert(output_info, "Header: " .. table.concat(hpkp_header, " "))
  end

  if #xframe_header > 0 then
    table.insert(output_info, "X-Frame-Options is configured.")
    table.insert(output_info, "Header: " .. table.concat(xframe_header, " "))

    for _,line in pairs(xframe_header) do
      if line:match("DENY") or line:match("deny") then
        table.insert(output_info, "Description: The browser must not display this content in any frame.")
      elseif line:match("SAMEORIGIN") or line:match("sameorigin") then
        table.insert(output_info, "Description: The browser must not display this content in any frame from a page of different origin than the content itself.")
      elseif line:match("ALLOW.FROM") or line:match("allow.from") then
        table.insert(output_info, "Description: The browser must not display this content in a frame from any page with a top-level browsing context of different origin than the specified origin.")
      end
    end

  end

  if #x_xss_header > 0 then
    table.insert(output_info, "X-XSS-Protection is configured.")
    table.insert(output_info, "Header: " .. table.concat(x_xss_header, " "))

    for _,line in pairs(x_xss_header) do
      if line:match("BLOCK") or line:match("block") then
        table.insert(output_info, "Description: The browser will prevent the rendering of the page when XSS is detected.")
      elseif line:match("REPORT") or line:match("report") then
        table.insert(output_info, "Description: The browser will sanitize the page and report the violation if XSS is detected.")
      elseif line:match("0") then
        table.insert(output_info, "Description: The XSS filter is disabled.")
      else
        table.insert(output_info, "Description: The browser will sanitize the page if XSS attack is detected.")
      end
    end

  end

  if #x_content_type_header > 0 then
    table.insert(output_info, "X-Content-Type-Options is configured.")
    table.insert(output_info, "Header: " .. table.concat(x_content_type_header, " "))

    for _,line in pairs(x_content_type_header) do
      if line:match("NOSNIFF") or line:match("nosniff") then
        table.insert(output_info, "Will prevent the browser from MIME-sniffing a response away from the declared content-type. ")
      end
    end

  end

  if #csp_header > 0 then
    table.insert(output_info, "Content-Security-Policy is configured.")
    table.insert(output_info, "Header: " .. table.concat(csp_header, " "))

    for _,line in pairs(csp_header) do
      if line:match("BASE.URI") or line:match("base.uri") then
        table.insert(output_info, "Description: Define the base uri for relative uri.")
      end
      if line:match("DEFAULT.SRC") or line:match("default.src") then
        table.insert(output_info, "Description: Define loading policy for all resources type in case of a resource type dedicated directive is not defined (fallback).")
      end
      if line:match("SCRIPT.SRC") or line:match("script.src") then
        table.insert(output_info, "Description: Define which scripts the protected resource can execute.")
      end
      if line:match("OBJECT.SRC") or line:match("object.src") then
        table.insert(output_info, "Description: Define from where the protected resource can load plugins.")
      end
      if line:match("STYLE.SRC") or line:match("style.src") then
        table.insert(output_info, "Description: Define which styles (CSS) the user applies to the protected resource.")
      end
      if line:match("IMG.SRC") or line:match("img.src") then
        table.insert(output_info, "Description: Define from where the protected resource can load images.")
      end
      if line:match("MEDIA.SRC") or line:match("media.src") then
        table.insert(output_info, "Description: Define from where the protected resource can load video and audio.")
      end
      if line:match("FRAME.SRC") or line:match("frame.src") then
        table.insert(output_info, "Description: Deprecated and replaced by child-src. Define from where the protected resource can embed frames.")
      end
      if line:match("CHILD.SRC") or line:match("child.src") then
        table.insert(output_info, "Description: Define from where the protected resource can embed frames.")
      end
      if line:match("FRAME.ANCESTORS") or line:match("frame.ancestors") then
        table.insert(output_info, "Description: Define from where the protected resource can be embedded in frames.")
      end
      if line:match("FONT.SRC") or line:match("font.src") then
        table.insert(output_info, "Description: Define from where the protected resource can load fonts.")
      end
      if line:match("CONNECT.SRC") or line:match("connect.src") then
        table.insert(output_info, "Description: Define which URIs the protected resource can load using script interfaces.")
      end
      if line:match("MANIFEST.SRC") or line:match("mailfest.src") then
        table.insert(output_info, "Description: Define from where the protected resource can load manifest.")
      end
      if line:match("FORM.ACTION") or line:match("form.action") then
        table.insert(output_info, "Description: Define which URIs can be used as the action of HTML form elements.")
      end
      if line:match("SANDBOX") or line:match("sandbox") then
        table.insert(output_info, "Description: Specifies an HTML sandbox policy that the user agent applies to the protected resource.")
      end
      if line:match("SCRIPT.NONCE") or line:match("script.nonce") then
        table.insert(output_info, "Description: Define script execution by requiring the presence of the specified nonce on script elements.")
      end
      if line:match("PLUGIN.TYPES") or line:match("plugin.types") then
        table.insert(output_info, "Description: Define the set of plugins that can be invoked by the protected resource by limiting the types of resources that can be embedded.")
      end
      if line:match("REFLECTED.XSS") or line:match("reflected.xss") then
        table.insert(output_info, "Description: Instructs a user agent to activate or deactivate any heuristics used to filter or block reflected cross-site scripting attacks, equivalent to the effects of the non-standard X-XSS-Protection header.")
      end
      if line:match("BLOCK.ALL.MIXED.CONTENT") or line:match("block.all.mixed.content") then
        table.insert(output_info, "Description: Prevent user agent from loading mixed content.")
      end
      if line:match("UPGRADE.INSECURE.REQUESTS") or line:match("upgrade.insecure.requests") then
        table.insert(output_info, "Description: Instructs user agent to download insecure resources using HTTPS.")
      end
      if line:match("REFERRER") or line:match("referrer") then
        table.insert(output_info, "Description: Define information user agent must send in Referer header.")
      end
      if line:match("REPORT.URI") or line:match("report.uri") then
        table.insert(output_info, "Description: Specifies a URI to which the user agent sends reports about policy violation.")
      end
      if line:match("REPORT.TO") or line:match("report.to") then
        table.insert(output_info, "Description: Specifies a group (defined in Report-To header) to which the user agent sends reports about policy violation. ")
      end
    end

  end

  if #x_cross_domain_header > 0 then
    table.insert(output_info, "X-Permitted-Cross-Domain-Policies are configured.")
    table.insert(output_info, "Header: " .. table.concat(x_cross_domain_header, " "))

    for _,line in pairs(x_cross_domain_header) do
      if line:match("NONE") or line:match("none") then
        table.insert(output_info, "Description: No policy files are allowed anywhere on the target server, including this master policy file. ")
      elseif line:match("MASTER.ONLY") or line:match("master.only") then
        table.insert(output_info, "Description: Only this master policy file is allowed. ")
      elseif line:match("BY.CONTENT.TYPE") or line:match("by.content.type") then
        table.insert(output_info, "Description: Define which scripts the protected resource can execute.")
      elseif line:match("ALL") or line:match("all") then
        table.insert(output_info, "Description: All policy files on this target domain are allowed.")
      end  
    end

  end

  return stdnse.format_output(true, output_info)

end