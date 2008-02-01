-- HTTP authentication information gathering script
-- rev 1.1 (2007-05-25)

id = "HTTP Auth"

description = "If a web server requires authentication, prints the authentication scheme and realm"

author = "Thomas Buchanan <tbuchanan@thecompassgrp.net>"

license = "See nmaps COPYING for licence"

-- uncomment the following line to enable safe category
-- categories = {"safe"}
categories = {"intrusive"}

require "shortport"
require "http"

portrule = shortport.port_or_service({80, 443, 8080}, {"http","https"})

action = function(host, port)
  local realm,scheme,result
  local basic = false

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
    answer = http.get(host, port, '/', {header={Authorization="Basic YWRtaW46C"}})
    if answer.status ~= 401 and answer.status ~= 403 then
      result = result .. "  HTTP server may accept user=\"admin\" with blank password for Basic authentication\n"
    end

    answer = http.get(host, port, '/', {header={Authorization="Basic YWRtaW46YWRtaW4"}})
    if answer.status ~= 401 and answer.status ~= 403 then
      result = result .. "  HTTP server may accept user=\"admin\" with password=\"admin\" for Basic authentication\n"
    end
  end

  return result
end

