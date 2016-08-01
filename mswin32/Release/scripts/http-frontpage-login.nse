local stdnse = require "stdnse"
local shortport = require "shortport"
local http = require "http"
local string = require "string"
local vulns = require "vulns"


description = [[
Checks whether target machines are vulnerable to anonymous Frontpage login.

Older, default configurations of Frontpage extensions allow
remote user to login anonymously which may lead to server compromise.

 ]]

---
-- @usage
-- nmap <target> -p 80 --script=http-frontpage-login
--
-- @args http-frontpage-login.path Path prefix to Frontpage directories. Defaults
-- to root ("/").
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-frontpage-login:
-- |   VULNERABLE:
-- |   Frontpage extension anonymous login
-- |     State: VULNERABLE
-- |     Description:
-- |       Default installations of older versions of frontpage extensions allow anonymous logins which can lead to server compromise.
-- |
-- |     References:
-- |_      http://insecure.org/sploits/Microsoft.frontpage.insecurities.html

author = "Aleksandar Nikolic"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local path = stdnse.get_script_args('http-frontpage-login.path') or "/"
  local data
  local frontpage_vuln = {
    title = "Frontpage extension anonymous login",

    description = [[
Default installations of older versions of frontpage extensions allow anonymous logins which can lead to server compromise.
]],
    references = {
      'http://insecure.org/sploits/Microsoft.frontpage.insecurities.html',
    },
    exploit_results = {},
  };

  local report = vulns.Report:new(SCRIPT_NAME, host, port);
  frontpage_vuln.state = vulns.STATE.NOT_VULN;

  data = http.get( host, port, path .. "/_vti_inf.html" )

  if data and data.status and data.status == 200 then
    --server does support frontpage extensions
    local fp_version = string.match(data.body,"FPVersion=\"[%d%.]*\"")
    if fp_version then
      -- do post request http://msdn.microsoft.com/en-us/library/ms446353
      local postdata = "method=open+service:".. fp_version .."&service_name=/"
      data = http.post(host,port,path .. "/_vti_bin/_vti_aut/author.dll",nil,nil,postdata)
      if data and data.status then
        if data.status == 200  then
          stdnse.debug1("Frontpage returned 200 OK, server vulnerable.")
          frontpage_vuln.state = vulns.STATE.VULN;
          return report:make_output(frontpage_vuln);
        elseif data.status == 401  then
          stdnse.debug1("Frontpage returned 401, password protected.")
          return false
        else
          stdnse.debug1("Frontpage returned unknown response.")
          return false
        end
      end
    end
  end
  stdnse.debug1("Frontpage probably not installed.")
  return false
end
