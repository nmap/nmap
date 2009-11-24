description = [[
Retrieves the authentication scheme and realm of a web service that requires
authentication.
]]

---
-- @output
-- 80/tcp open  http
-- |  http-auth: HTTP Service requires authentication
-- |    Auth type: Basic, realm = Password Required
-- |_   HTTP server may accept admin:admin combination for Basic authentication

-- HTTP authentication information gathering script
-- rev 1.1 (2007-05-25)
-- 2008-11-06 Vlatko Kosturjak <kost@linux.hr>
-- * bug fixes against base64 encoded strings, more flexible auth/pass check,
--   corrected sample output

author = "Thomas Buchanan"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "auth", "intrusive"}

require "shortport"
require "http"
require "base64"

portrule = shortport.port_or_service({80, 443, 8080}, {"http","https"})

action = function(host, port)
  local realm,scheme,result,authheader
  local basic = false
  local authcombinations= {"admin:", "admin:admin"}

  local answer = http.get( host, port, "/" )

  --- check for 401 response code
  if answer.status == 401 then
    result = "HTTP Service requires authentication\n"

    -- split www-authenticate header
    local auth_headers = {}
    local pcre = pcre.new('\\w+( (\\w+=("[^"]+"|\\w+), *)*(\\w+=("[^"]+"|\\w+)))?',0,"C")
    local match = function( match ) table.insert(auth_headers, match) end
    pcre:gmatch( answer.header['www-authenticate'], match )

    for _, value in pairs( auth_headers ) do
      result = result .. "  Auth type: "
      scheme, realm = string.match(value, "(%a+).-[Rr]ealm=\"(.-)\"")
      if scheme == "Basic" then
        basic = true
      end
      if realm ~= nil then
        result = result .. scheme .. ", realm = " .. realm .. "\n"
      else
        result = result .. string.match(value, "(%a+)") .. "\n"
      end
    end
  end

  if basic then
    for _, combination in pairs (authcombinations) do 
	    authheader = "Basic " .. base64.enc(combination)
	    answer = http.get(host, port, '/', {header={Authorization=authheader}})
	    if answer.status ~= 401 and answer.status ~= 403 then
	      result = result .. "  HTTP server may accept " .. combination .. " combination for Basic authentication\n"
	    end
    end
  end

  return result
end

